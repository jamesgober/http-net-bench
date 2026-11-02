//! The connection state machine.
//!
//! One `Conn` per connection runs the protocol engine and the hand-off order
//! (dev/PLAN.md sections 8.3 and 8.4). It is driver independent: it reads
//! time, sets deadlines, and hands bytes to the transport through [`Io`], so
//! the simulated-connection tests drive it without sockets and the net-io
//! session is a thin translation.
//!
//! Order rules this file makes impossible to break:
//!
//! 1. No body byte is processed before `Admit` admitted the request.
//! 2. The service is never called for a request that failed ingress
//!    normalization, was refused by `head`, was not admitted, or was denied.
//! 3. A refusal skips every later step and closes.
//! 4. `done` runs exactly once for every request that reached `head`.
//! 5. A reply is handed to the transport whole before the next request is
//!    processed.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::client::{ClientInfo, Scheme};
use crate::config::{Compiled, KeepAlive, ProfileId, ProfileTable, ProxySource};
use crate::engine::{
    Engine, EngineEvent, Family, HeadContext, OutBuf, Refusal, RefusalKind, Service,
};
use crate::envelope::{Envelope, RequestSeq};
use crate::error::EndReason;
use crate::hooks::{
    Admit, Admitted, Checkpoint, CheckpointAt, Dispatch, Hooks, Observer, Shed, Verdict,
};
use crate::net::{CloseReason, ConnectionId, ControlLine, ControlState, WorkerId};
use crate::reply::{DeferSlot, Link, Reply, SlotState, WAKE_REPLY, Waker};
use crate::service::{BodyPolicy, Finished, HeadAction, Outcome, RequestEnd};
use crate::stats::{Count, Counters};

pub(crate) mod session;
#[cfg(all(test, feature = "http1"))]
mod tests;

/// What the machine asks the transport to do next (net-io `Step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Wait for more input.
    Read,
    /// Flush pending output, then call `on_writable`.
    Write,
    /// No reads until a wake or the deadline.
    Park { until: Instant },
    /// Flush, then close gracefully.
    Close,
    /// Reset now.
    Abort,
}

/// Which transport deadlines run (net-io `Phase`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Idle,
    Receiving,
    Sending,
}

/// Which deadline passed (the subset of net-io's `TimeoutKind` sessions see).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Timeout {
    /// The exchange deadline serve-net set.
    Exchange,
    /// The park deadline of a deferred reply.
    Park,
    /// A transport deadline (idle, read, write), with net-io's close reason.
    Transport(CloseReason),
}

/// The transport, as the machine sees it.
pub(crate) trait Io {
    /// The worker's clock.
    fn now(&self) -> Instant;
    /// The exchange deadline; `None` clears it.
    fn set_exchange_deadline(&mut self, at: Option<Instant>);
    /// Which transport deadlines run.
    fn set_phase(&mut self, phase: Phase);
    /// This connection's idle timeout from its next idle wait; `None`
    /// restores the listener's (net-io `SessionContext::set_idle_timeout`).
    fn set_idle_timeout(&mut self, timeout: Option<Duration>);
    /// A reply starts: a gate may still deny it cleanly until its first byte
    /// leaves (net-io `Output::begin_response`).
    fn begin_reply(&mut self);
    /// Hands as much of `bytes` as the output budget allows; returns the count.
    fn push(&mut self, bytes: &[u8]) -> usize;
    /// Whether the server is draining.
    fn draining(&self) -> bool;
    /// The fraction of capacity in use (blocking: busy workers), 0.0 to 1.0.
    fn pressure(&self) -> f32;
    /// The worker that owns this connection.
    fn worker(&self) -> WorkerId;
    /// The waker of this worker, for deferred replies.
    fn waker(&self) -> Arc<dyn Waker>;
}

/// One listener's runtime facts.
#[derive(Debug, Clone)]
pub(crate) struct ListenerRuntime {
    #[allow(dead_code)] // reported to the observer with listener events (0.4)
    pub(crate) name: String,
    pub(crate) profile: ProfileId,
    pub(crate) proxy: Option<ProxySource>,
    pub(crate) declared_scheme: Scheme,
}

/// What every connection of one server shares.
pub(crate) struct Shared<F: Family, S: Service<F>, H: Hooks> {
    pub(crate) family: F,
    pub(crate) service: S,
    pub(crate) admit: H::Admit,
    pub(crate) dispatch: H::Dispatch,
    pub(crate) checkpoint: H::Checkpoint,
    pub(crate) observer: H::Observer,
    /// The owner's line merged with serve-net's drain request (D-032). Read
    /// live at each checkpoint: net-io's `draining()` is fixed for the length
    /// of one callback, and a drain may start while the service runs (D-047).
    pub(crate) control: Arc<crate::running::Merged<H::Control>>,
    pub(crate) profiles: ProfileTable,
    pub(crate) listeners: Vec<ListenerRuntime>,
    pub(crate) counters: Arc<Counters>,
}

/// Where the machine is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Between requests (or before the first).
    AwaitHead,
    /// Admitted; reading the body under its policy.
    ReadBody,
    /// Waiting for a deferred reply.
    Parked { generation: u64, until: Instant },
    /// The reply is being handed to the transport; then the next request.
    Writing,
    /// A closing reply or refusal is being handed over; then close.
    Closing,
    /// Finished.
    Closed,
}

/// The current request's bookkeeping.
struct Request {
    admitted: Option<Admitted>,
    head_at: Instant,
    admitted_at: Option<Instant>,
    bytes_in: u64,
    policy: BodyPolicy,
    discard_over: bool,
    status: Option<u16>,
    bytes_out: u64,
}

/// The pressure above which keep-alive adapts (blocking driver).
const PRESSURE_SHORTEN: f32 = 0.75;
/// The pressure above which every reply carries the close signal.
const PRESSURE_CLOSE: f32 = 0.9;
/// Output capacity a connection starts with: every refusal and a typical
/// small reply fit without growing it.
const OUT_INITIAL: usize = 1024;
/// Output capacity kept after a reply.
const OUT_RETAIN: usize = 16 * 1024;
/// Body capacity kept between requests.
const BODY_RETAIN: usize = 64 * 1024;

/// One connection.
pub(crate) struct Conn<F: Family, S: Service<F>, H: Hooks> {
    shared: Arc<Shared<F, S, H>>,
    listener: usize,
    connection: ConnectionId,
    engine: F::Engine,
    client: ClientInfo,
    env: Envelope,
    state: State,
    request: Option<Request>,
    body: Vec<u8>,
    reply: Reply<F>,
    out: OutBuf,
    out_sent: usize,
    seq: u32,
    accepted_at: Instant,
    clock_base: (Instant, u64),
    epoch: u64,
    control: ControlState,
    defer: Option<Arc<DeferSlot<F::Parts>>>,
    generation: u64,
    end: Option<EndReason>,
    closing_after_write: bool,
    first_byte: Option<Instant>,
    wipe: bool,
    /// A drain was seen on this connection (for the drain report's counts).
    draining_seen: bool,
}

impl<F: Family, S: Service<F>, H: Hooks> Conn<F, S, H> {
    /// A connection on `listener`, whose client (before forwarded facts) is `client`.
    pub(crate) fn new(
        shared: Arc<Shared<F, S, H>>,
        listener: usize,
        connection: ConnectionId,
        client: ClientInfo,
        now: Instant,
        worker: WorkerId,
    ) -> Self {
        let profile_id = shared
            .listeners
            .get(listener)
            .map_or(ProfileId(0), |l| l.profile);
        let compiled = shared.profiles.compiled(profile_id);
        let (engine, wipe, lane, tag) = match compiled {
            Some(c) => (
                shared.family.engine(&c.profile, &c.limits),
                c.profile.wipe_buffers,
                c.profile.lane,
                c.profile.tag,
            ),
            None => {
                let p = crate::config::Profile::new(profile_id);
                (
                    shared.family.engine(&p, &crate::config::Limits::new()),
                    true,
                    crate::config::DEFAULT_LANE,
                    0,
                )
            }
        };
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let parts = shared.family.new_parts();
        let env = Envelope {
            connection,
            seq: RequestSeq(0),
            profile: profile_id,
            tag,
            lane,
            lane_open: false,
            lane_late: false,
            client,
            arrived: now,
            deadline: now,
            worker,
            user_word: 0,
        };
        let epoch = shared.control.epoch();
        let control = if epoch == 0 {
            ControlState::Normal
        } else {
            shared.control.state()
        };
        Conn {
            shared,
            listener,
            connection,
            engine,
            client,
            env,
            state: State::AwaitHead,
            request: None,
            body: Vec::new(),
            reply: Reply::new(parts),
            out: OutBuf {
                bytes: Vec::with_capacity(OUT_INITIAL),
            },
            out_sent: 0,
            seq: 0,
            accepted_at: now,
            clock_base: (now, unix),
            epoch,
            control,
            defer: None,
            generation: 0,
            end: None,
            closing_after_write: false,
            first_byte: None,
            wipe,
            draining_seen: false,
        }
    }

    fn compiled(&self) -> Option<&Compiled> {
        self.shared.profiles.compiled(self.env.profile)
    }

    fn limits(&self) -> crate::config::Limits {
        self.compiled()
            .map_or_else(crate::config::Limits::new, |c| c.limits)
    }

    fn keep_alive(&self) -> KeepAlive {
        self.compiled()
            .map_or_else(KeepAlive::new, |c| c.keep_alive)
    }

    fn unix_secs(&self, now: Instant) -> u64 {
        self.clock_base
            .1
            .saturating_add(now.saturating_duration_since(self.clock_base.0).as_secs())
    }

    #[inline]
    fn count<I: Io>(&mut self, io: &I, what: Count) {
        self.shared.counters.count(io.worker().get(), what);
    }

    /// Whether a drain runs: net-io's flag, or the live control line (net-io's
    /// flag is fixed for one callback, D-047).
    fn draining_now<I: Io>(&mut self, io: &I) -> bool {
        let live = matches!(
            self.checkpoint(),
            ControlState::Draining | ControlState::Stopping
        );
        self.draining_seen |= live || io.draining();
        self.draining_seen
    }

    /// Reads the control line: one load when nothing changed.
    fn checkpoint(&mut self) -> ControlState {
        let e = self.shared.control.epoch();
        if e != self.epoch {
            self.epoch = e;
            self.control = self.shared.control.state();
        }
        self.control
    }

    /// Called once when the connection opens.
    pub(crate) fn on_open<I: Io>(&mut self, io: &mut I, refuse_capacity: bool) -> Step {
        if refuse_capacity {
            self.end = Some(EndReason::CapacityRefused);
            return self.refuse_without_request(
                io,
                RefusalKind::Busy,
                503,
                Some(Duration::from_secs(1)),
            );
        }
        if matches!(self.checkpoint(), ControlState::Stopping) {
            self.end = Some(EndReason::Drained);
            return Step::Abort;
        }
        // The first request's head deadline runs from accept (idea I-1).
        let head = self.limits().head_timeout;
        io.set_phase(Phase::Receiving);
        io.set_exchange_deadline(Some(self.accepted_at + head));
        Step::Read
    }

    /// Bytes arrived; returns how many were consumed and what to do next.
    pub(crate) fn on_data<I: Io>(&mut self, io: &mut I, input: &[u8]) -> (usize, Step) {
        match self.state {
            State::Parked { until, .. } => return (0, Step::Park { until }),
            State::Closed => return (input.len(), Step::Close),
            State::Closing => return (input.len(), self.flush(io)),
            State::Writing => {
                let step = self.flush(io);
                if step != Step::Read {
                    return (0, step);
                }
            }
            State::AwaitHead | State::ReadBody => {}
        }
        let (n, step) = self.process(io, input);
        self.count(io, Count::BytesIn(n as u64));
        (n, step)
    }

    /// The peer closed its sending side; replies still go out.
    pub(crate) fn on_peer_closed<I: Io>(&mut self, io: &mut I) -> Step {
        if matches!(self.state, State::Parked { .. }) {
            // Nobody will read the reply: cancel it and close.
            self.cancel_deferred();
            self.finish_request(RequestEnd::PeerGone);
            self.end
                .get_or_insert(EndReason::Transport(CloseReason::PeerClosed));
            return Step::Close;
        }
        self.engine.feed_eof();
        if matches!(self.state, State::Closing | State::Writing) {
            self.closing_after_write = true;
            return self.flush(io);
        }
        self.process(io, &[]).1
    }

    /// All pending output was flushed.
    pub(crate) fn on_writable<I: Io>(&mut self, io: &mut I) -> Step {
        let step = self.flush(io);
        if step == Step::Read && matches!(self.state, State::AwaitHead | State::ReadBody) {
            // Pipelined input may already sit inside the engine; input still
            // in the transport's buffer comes through `on_data`.
            return self.process(io, &[]).1;
        }
        step
    }

    /// A completion for this connection arrived.
    pub(crate) fn on_wake<I: Io>(&mut self, io: &mut I, token: u32, value: u64) -> Step {
        let State::Parked { generation, until } = self.state else {
            return self.current_step();
        };
        if token != WAKE_REPLY || value != generation {
            return Step::Park { until };
        }
        let Some(slot) = self.defer.clone() else {
            return Step::Park { until };
        };
        let taken = {
            let mut state = slot.lock();
            match core::mem::replace(&mut *state, SlotState::Idle) {
                SlotState::Completed(g, parts) if g == generation => Some(Some(parts)),
                SlotState::Dropped(g) if g == generation => Some(None),
                other => {
                    *state = other;
                    None
                }
            }
        };
        match taken {
            None => Step::Park { until },
            Some(Some(parts)) => {
                let old = core::mem::replace(&mut self.reply.parts, parts);
                drop(old);
                self.state = State::Writing;
                let step = self.respond(io, Outcome::Done);
                if step == Step::Read && self.state == State::AwaitHead {
                    return self.process(io, &[]).1;
                }
                step
            }
            Some(None) => {
                self.end = Some(EndReason::ReplyDropped);
                self.refuse(io, RefusalKind::Internal, 500, None, RequestEnd::Dropped)
            }
        }
    }

    /// A deadline passed.
    pub(crate) fn on_timeout<I: Io>(&mut self, io: &mut I, which: Timeout) -> Step {
        match (which, self.state) {
            (Timeout::Park, State::Parked { .. }) => {
                self.cancel_deferred();
                self.end = Some(EndReason::ReplyTimeout);
                self.refuse(
                    io,
                    RefusalKind::ReplyTimeout,
                    503,
                    None,
                    RequestEnd::TimedOut,
                )
            }
            (Timeout::Exchange, State::AwaitHead) => {
                if self.first_byte.is_some() {
                    self.end = Some(EndReason::HeadTimeout);
                    self.refuse_without_request(io, RefusalKind::HeadTimeout, 408, None)
                } else {
                    // Nothing of a head arrived: a quiet close.
                    self.end = Some(EndReason::HeadTimeout);
                    self.count(io, Count::TimedOut);
                    self.state = State::Closed;
                    Step::Close
                }
            }
            (Timeout::Exchange, State::ReadBody) => {
                self.end = Some(EndReason::RequestTimeout);
                self.refuse(
                    io,
                    RefusalKind::BodyTimeout,
                    408,
                    None,
                    RequestEnd::TimedOut,
                )
            }
            (Timeout::Exchange, State::Closing) => {
                self.state = State::Closed;
                Step::Abort
            }
            (Timeout::Transport(reason), _) => {
                self.end.get_or_insert(EndReason::Transport(reason));
                Step::Close
            }
            _ => {
                self.end
                    .get_or_insert(EndReason::Transport(CloseReason::ExchangeDeadline));
                Step::Close
            }
        }
    }

    /// The gate denied the reply before its first byte left: the engine's
    /// refusal for `status` replaces it, and the connection closes (net-io
    /// closes it with `EgressDenied`).
    pub(crate) fn on_denied(&mut self, status: u16, worker: WorkerId) -> &[u8] {
        if matches!(self.state, State::Parked { .. }) {
            self.cancel_deferred();
        }
        self.end = Some(EndReason::Denied);
        self.out.clear(self.wipe);
        self.out_sent = 0;
        let refusal = Refusal {
            kind: RefusalKind::Denied,
            status: if (400..=599).contains(&status) {
                status
            } else {
                403
            },
            retry_after: None,
        };
        self.engine.refuse(&refusal, &mut self.out);
        self.shared.counters.count(
            worker.get(),
            Count::Refused {
                kind: RefusalKind::Denied,
                draining: self.draining_seen,
            },
        );
        if let Some(r) = self.request.as_mut() {
            r.status = Some(refusal.status);
        }
        self.finish_request(RequestEnd::Denied);
        self.state = State::Closed;
        self.out.as_slice()
    }

    /// The connection closed with net-io's `reason`; runs exactly once.
    pub(crate) fn on_close(&mut self, reason: CloseReason) {
        // A kill, the drain deadline, or shutdown ended it; anything else is
        // the transport or the machine's own close.
        let transport = !matches!(
            reason,
            CloseReason::Killed(_) | CloseReason::DrainDeadline | CloseReason::Shutdown
        );
        if matches!(self.state, State::Parked { .. }) {
            self.cancel_deferred();
        }
        if self.request.is_some() {
            let end = if transport {
                RequestEnd::PeerGone
            } else {
                RequestEnd::Killed
            };
            self.finish_request(end);
        }
        let end = match (transport, self.end) {
            (_, Some(e)) => e,
            (true, None) => EndReason::Transport(reason),
            (false, None) => EndReason::Drained,
        };
        self.state = State::Closed;
        self.shared
            .observer
            .connection_ended(self.connection, end, self.seq);
        self.out.clear(self.wipe);
        self.shared
            .family
            .clear_parts(&mut self.reply.parts, self.wipe);
        if self.wipe {
            crate::engine::wipe_bytes(&mut self.body);
        }
        self.body.clear();
    }

    fn current_step(&self) -> Step {
        match self.state {
            State::Parked { until, .. } => Step::Park { until },
            State::Closed => Step::Close,
            State::Closing | State::Writing if self.out_sent < self.out.len() => Step::Write,
            State::Closing => Step::Close,
            _ => Step::Read,
        }
    }

    /// Hands pending output to the transport.
    fn flush<I: Io>(&mut self, io: &mut I) -> Step {
        while self.out_sent < self.out.len() {
            let n = io.push(&self.out.as_slice()[self.out_sent..]);
            if n == 0 {
                io.set_phase(Phase::Sending);
                return Step::Write;
            }
            self.out_sent += n;
            self.count(io, Count::BytesOut(n as u64));
        }
        self.out.clear(self.wipe);
        self.out.shrink(OUT_RETAIN);
        self.out_sent = 0;
        match self.state {
            State::Closing => {
                self.state = State::Closed;
                Step::Close
            }
            State::Writing => {
                // The whole reply is with the transport: the request is done.
                self.finish_request(RequestEnd::Replied);
                if self.closing_after_write || !self.engine.keep_alive() {
                    self.state = State::Closed;
                    self.end.get_or_insert(EndReason::ClientClose);
                    return Step::Close;
                }
                self.state = State::AwaitHead;
                self.idle(io)
            }
            _ => Step::Read,
        }
    }

    /// Back between requests.
    fn idle<I: Io>(&mut self, io: &mut I) -> Step {
        self.first_byte = None;
        if self.body.capacity() > BODY_RETAIN {
            self.body.shrink_to(BODY_RETAIN);
        }
        match self.checkpoint() {
            ControlState::Stopping => {
                self.end = Some(EndReason::Drained);
                self.state = State::Closed;
                return Step::Abort;
            }
            ControlState::Draining => {
                self.end = Some(EndReason::Drained);
                self.state = State::Closed;
                return Step::Close;
            }
            _ => {}
        }
        if io.draining() {
            self.end = Some(EndReason::Drained);
            self.state = State::Closed;
            return Step::Close;
        }
        let k = self.keep_alive();
        if io.now().saturating_duration_since(self.accepted_at) >= k.max_age {
            self.end = Some(EndReason::MaxAge);
            self.state = State::Closed;
            return Step::Close;
        }
        // The engine keeps its buffer between requests: releasing it here would
        // cost an allocation per keep-alive request. Idle memory is returned
        // through per-worker engine pools with the reactor driver (0.5).
        io.set_exchange_deadline(None);
        io.set_phase(Phase::Idle);
        Step::Read
    }

    /// Feeds input and runs the engine until it needs more or a step is due.
    fn process<I: Io>(&mut self, io: &mut I, input: &[u8]) -> (usize, Step) {
        let mut consumed = 0;
        let max = usize::from(self.limits().max_pipelined_per_wake.max(1));
        let mut served = 0usize;
        loop {
            if consumed < input.len() {
                let fed = self.engine.feed(&input[consumed..]);
                consumed += fed;
                if fed > 0 && self.state == State::AwaitHead && self.first_byte.is_none() {
                    // The first byte of a head: its deadline starts now
                    // (the first request's started at accept).
                    let now = io.now();
                    self.first_byte = Some(now);
                    if self.seq > 0 {
                        io.set_phase(Phase::Receiving);
                        io.set_exchange_deadline(Some(now + self.limits().head_timeout));
                    }
                }
            }
            let event = match self.engine.poll() {
                Ok(e) => e,
                Err(e) => {
                    self.end = Some(EndReason::ProtocolError);
                    let step = if self.request.is_some() {
                        self.refuse(io, e.kind, e.status, None, RequestEnd::Refused(e.kind))
                    } else {
                        self.refuse_without_request(io, e.kind, e.status, None)
                    };
                    return (input.len(), step);
                }
            };
            let step = match event {
                EngineEvent::NeedInput => {
                    if consumed < input.len() {
                        // The engine refused bytes while waiting for more:
                        // its buffer is full of a head it cannot finish.
                        self.end = Some(EndReason::ProtocolError);
                        return (
                            input.len(),
                            self.refuse_without_request(io, RefusalKind::TooLarge, 431, None),
                        );
                    }
                    return (consumed, Step::Read);
                }
                EngineEvent::Head => self.on_head(io),
                EngineEvent::Body(bytes) => {
                    let n = bytes.len() as u64;
                    match self.request.as_mut() {
                        Some(r) => {
                            r.bytes_in = r.bytes_in.saturating_add(n);
                            match r.policy {
                                BodyPolicy::Buffer { max } => {
                                    if (self.body.len() as u64).saturating_add(n) > max {
                                        self.end = Some(EndReason::ProtocolError);
                                        let step = self.refuse(
                                            io,
                                            RefusalKind::TooLarge,
                                            413,
                                            None,
                                            RequestEnd::Refused(RefusalKind::TooLarge),
                                        );
                                        return (input.len(), step);
                                    }
                                    self.body.extend_from_slice(bytes);
                                    None
                                }
                                BodyPolicy::Discard { max } => {
                                    if r.bytes_in > max {
                                        r.discard_over = true;
                                        Some(self.dispatch(io))
                                    } else {
                                        None
                                    }
                                }
                            }
                        }
                        None => None,
                    }
                }
                EngineEvent::BodyEnd => {
                    if self.request.is_some() && self.state == State::ReadBody {
                        Some(self.dispatch(io))
                    } else {
                        None
                    }
                }
                EngineEvent::AwaitingReply => return (consumed, self.current_step()),
                EngineEvent::Upgraded | EngineEvent::Closed => {
                    if self.state == State::AwaitHead {
                        self.end.get_or_insert(EndReason::ClientClose);
                        self.state = State::Closed;
                        return (input.len(), Step::Close);
                    }
                    return (consumed, self.current_step());
                }
            };
            if let Some(step) = step {
                match step {
                    Step::Read if self.state == State::AwaitHead => {
                        served += 1;
                        if served >= max {
                            // Fairness: yield to other connections. The
                            // transport flushes and calls `on_writable`, which
                            // continues with input already inside the engine.
                            return (consumed, Step::Write);
                        }
                    }
                    Step::Read => {}
                    other => {
                        let c = if matches!(other, Step::Close | Step::Abort) {
                            input.len()
                        } else {
                            consumed
                        };
                        return (c, other);
                    }
                }
            }
        }
    }

    /// The head is complete: normalization, `head`, admission, checkpoint.
    fn on_head<I: Io>(&mut self, io: &mut I) -> Option<Step> {
        let now = io.now();
        let control = self.checkpoint();
        if control == ControlState::Stopping {
            self.end = Some(EndReason::Drained);
            self.state = State::Closed;
            return Some(Step::Abort);
        }
        let limits = self.limits();
        let shared = Arc::clone(&self.shared);
        let compiled = shared.profiles.compiled(self.env.profile);
        // Everything that borrows the engine's head happens in this block, so
        // the borrow ends before any refusal is written.
        let viewed = {
            let listener = shared.listeners.get(self.listener);
            let cx = HeadContext {
                client: &self.client,
                proxy: listener.and_then(|l| l.proxy.as_ref()),
                declared_scheme: listener.map_or(Scheme::Http, |l| l.declared_scheme),
                resolved: None,
            };
            match self.engine.head() {
                None => None,
                Some(raw) => Some(match shared.family.head(raw, &cx) {
                    Err(e) => Err(e),
                    Ok((head, client)) => {
                        let arrived = self.first_byte.unwrap_or(now);
                        self.seq = self.seq.saturating_add(1);
                        self.env.seq = RequestSeq(self.seq);
                        self.env.client = client;
                        self.env.lane =
                            compiled.map_or(crate::config::DEFAULT_LANE, |c| c.profile.lane);
                        self.env.lane_open = true;
                        self.env.lane_late = false;
                        self.env.arrived = arrived;
                        self.env.deadline = arrived + limits.request_timeout;
                        self.env.user_word = 0;
                        shared.observer.request_head(&self.env);
                        let action = shared.service.head(&head, &mut self.env);
                        self.env.lane_open = false;
                        Ok(action)
                    }
                }),
            }
        };
        let action = match viewed {
            None => return None,
            Some(Err(e)) => {
                self.end = Some(EndReason::IngressRefused);
                return Some(self.refuse_without_request(io, e.kind, e.status, None));
            }
            Some(Ok(action)) => action,
        };
        let head_len = self.engine.head_len() as u64;
        let arrived = self.env.arrived;
        let declared = self.engine.declared_length();
        let expects = self.engine.expects_continue();
        let default_policy = compiled.map_or(
            BodyPolicy::Buffer {
                max: limits.max_body,
            },
            |c| c.body,
        );
        self.request = Some(Request {
            admitted: None,
            head_at: arrived,
            admitted_at: None,
            bytes_in: head_len,
            policy: default_policy,
            discard_over: false,
            status: None,
            bytes_out: 0,
        });
        let policy = match action {
            HeadAction::Proceed => default_policy,
            HeadAction::ProceedWith(p) => p,
            HeadAction::Refuse {
                status,
                retry_after,
            } => {
                self.end = Some(EndReason::Refused);
                return Some(self.refuse(
                    io,
                    RefusalKind::Service,
                    status,
                    retry_after,
                    RequestEnd::Refused(RefusalKind::Service),
                ));
            }
        };
        // Control line: shed, lockdown, drain.
        let critical = compiled.is_some_and(|c| c.profile.critical);
        let refused_by_control = match control {
            ControlState::Shed { from_lane } => self.env.lane >= from_lane,
            ControlState::Lockdown => !critical,
            _ => false,
        };
        if refused_by_control {
            self.end = Some(EndReason::Shed);
            let shed = Shed {
                retry_after: None,
                close: true,
            };
            shared.observer.request_shed(&self.env, &shed);
            return Some(self.refuse(
                io,
                RefusalKind::Busy,
                503,
                Some(Duration::from_secs(1)),
                RequestEnd::Shed,
            ));
        }
        match shared.admit.admit(io.worker(), &self.env) {
            Ok(a) => {
                if let Some(r) = self.request.as_mut() {
                    r.admitted = Some(a);
                    r.admitted_at = Some(now);
                }
                shared.observer.request_admitted(&self.env);
            }
            Err(shed) => {
                self.end = Some(EndReason::Shed);
                shared.observer.request_shed(&self.env, &shed);
                let retry = shed.retry_after.or(Some(Duration::from_secs(1)));
                return Some(self.refuse(io, RefusalKind::Busy, 503, retry, RequestEnd::Shed));
            }
        }
        match shared.checkpoint.check(&self.env, CheckpointAt::Admitted) {
            Verdict::Pass => {}
            Verdict::Deny { status } => {
                self.end = Some(EndReason::Denied);
                return Some(self.refuse(
                    io,
                    RefusalKind::Denied,
                    status,
                    None,
                    RequestEnd::Denied,
                ));
            }
            Verdict::Kill => return Some(self.kill()),
        }
        if let (BodyPolicy::Buffer { max }, Some(len)) = (policy, declared) {
            if len > max {
                self.end = Some(EndReason::ProtocolError);
                return Some(self.refuse(
                    io,
                    RefusalKind::TooLarge,
                    413,
                    None,
                    RequestEnd::Refused(RefusalKind::TooLarge),
                ));
            }
        }
        if let Some(r) = self.request.as_mut() {
            r.policy = policy;
        }
        if expects && self.engine.send_continue(&mut self.out).is_ok() {
            let _ = self.flush_partial(io);
        }
        self.body.clear();
        self.state = State::ReadBody;
        io.set_phase(Phase::Receiving);
        io.set_exchange_deadline(Some(self.env.deadline));
        if control == ControlState::Draining || io.draining() {
            self.engine.close_after_reply();
        }
        None
    }

    /// Hands what fits of pending output to the transport without changing state.
    fn flush_partial<I: Io>(&mut self, io: &mut I) -> bool {
        while self.out_sent < self.out.len() {
            let n = io.push(&self.out.as_slice()[self.out_sent..]);
            if n == 0 {
                return false;
            }
            self.out_sent += n;
        }
        self.out.clear(self.wipe);
        self.out_sent = 0;
        true
    }

    /// The request is complete: checkpoint, dispatch, service call.
    fn dispatch<I: Io>(&mut self, io: &mut I) -> Step {
        let shared = Arc::clone(&self.shared);
        let _ = self.checkpoint();
        match shared
            .checkpoint
            .check(&self.env, CheckpointAt::BeforeDispatch)
        {
            Verdict::Pass => {}
            Verdict::Deny { status } => {
                self.end = Some(EndReason::Denied);
                return self.refuse(io, RefusalKind::Denied, status, None, RequestEnd::Denied);
            }
            Verdict::Kill => return self.kill(),
        }
        // A deferral gets the next generation; the slot is made once per connection.
        self.generation = self.generation.wrapping_add(1);
        let slot = match &self.defer {
            Some(s) => Arc::clone(s),
            None => {
                let s = Arc::new(DeferSlot::new(io.waker(), self.connection));
                self.defer = Some(Arc::clone(&s));
                s
            }
        };
        self.reply.link = Some(Link {
            slot,
            generation: self.generation,
        });
        self.reply.deferred = false;
        shared.family.clear_parts(&mut self.reply.parts, self.wipe);
        let outcome = {
            let listener = shared.listeners.get(self.listener);
            let cx = HeadContext {
                client: &self.client,
                proxy: listener.and_then(|l| l.proxy.as_ref()),
                declared_scheme: listener.map_or(Scheme::Http, |l| l.declared_scheme),
                resolved: Some(self.env.client),
            };
            let discard = self
                .request
                .as_ref()
                .is_some_and(|r| matches!(r.policy, BodyPolicy::Discard { .. }));
            match self.engine.head() {
                None => None,
                // The client resolved at the head is reused: no second walk.
                Some(raw) => match shared.family.head(raw, &cx) {
                    Err(_) => None,
                    Ok((head, _)) => {
                        let body: &[u8] = if discard { &[] } else { &self.body };
                        let request = shared.family.request(head, body);
                        let started = Instant::now();
                        let worker = self.env.worker.get();
                        shared.counters.in_call(worker, true);
                        let outcome = shared.dispatch.run(
                            &shared.service,
                            &request,
                            &self.env,
                            &mut self.reply,
                        );
                        shared.counters.in_call(worker, false);
                        if cfg!(debug_assertions)
                            && <S as Service<F>>::WORK == crate::service::WorkClass::Quick
                        {
                            let took = started.elapsed();
                            if took > Duration::from_millis(1) {
                                shared.observer.service_misdeclared(&self.env, took);
                            }
                        }
                        Some(outcome)
                    }
                },
            }
        };
        let Some(outcome) = outcome else {
            self.reply.link = None;
            return self.refuse(
                io,
                RefusalKind::Internal,
                500,
                None,
                RequestEnd::Refused(RefusalKind::Internal),
            );
        };
        self.reply.link = None;
        if self.env.lane_late {
            shared
                .observer
                .service_error(&self.env, "lane set after head");
        }
        if self.reply.deferred {
            if outcome != Outcome::Deferred {
                shared
                    .observer
                    .service_error(&self.env, "reply deferred but call did not return Deferred");
            }
            self.count(io, Count::Deferred);
            let until = io.now() + self.limits().reply_timeout;
            self.state = State::Parked {
                generation: self.generation,
                until,
            };
            io.set_exchange_deadline(None);
            // A completion that arrived while `call` ran is picked up at once.
            if self.slot_has_result() {
                return self.on_wake(io, WAKE_REPLY, self.generation);
            }
            return Step::Park { until };
        }
        if outcome == Outcome::Deferred {
            shared
                .observer
                .service_error(&self.env, "Deferred returned without reply.defer()");
            self.end = Some(EndReason::ServiceClosed);
            return self.refuse(
                io,
                RefusalKind::Internal,
                500,
                None,
                RequestEnd::Refused(RefusalKind::Internal),
            );
        }
        self.state = State::Writing;
        self.respond(io, outcome)
    }

    fn slot_has_result(&self) -> bool {
        self.defer
            .as_ref()
            .is_some_and(|s| matches!(*s.lock(), SlotState::Completed(..) | SlotState::Dropped(_)))
    }

    /// Encodes and hands over the reply.
    fn respond<I: Io>(&mut self, io: &mut I, outcome: Outcome) -> Step {
        let shared = Arc::clone(&self.shared);
        let control = self.checkpoint();
        match shared
            .checkpoint
            .check(&self.env, CheckpointAt::BeforeReply)
        {
            Verdict::Pass => {}
            Verdict::Deny { status } => {
                self.end = Some(EndReason::Denied);
                return self.refuse(io, RefusalKind::Denied, status, None, RequestEnd::Denied);
            }
            Verdict::Kill => return self.kill(),
        }
        let k = self.keep_alive();
        let now = io.now();
        // Keep-alive under pressure (FR-58): above PRESSURE_SHORTEN the next
        // idle wait is `under_pressure`; above PRESSURE_CLOSE the reply closes.
        let pressure = if k.under_pressure.is_zero() {
            0.0
        } else {
            io.pressure()
        };
        let pressured = pressure >= PRESSURE_CLOSE;
        io.set_idle_timeout(if pressure >= PRESSURE_SHORTEN {
            Some(k.under_pressure)
        } else {
            None
        });
        let mut close = !k.on
            || outcome == Outcome::Close
            || u64::from(self.seq) >= u64::from(k.max_requests)
            || now.saturating_duration_since(self.accepted_at) >= k.max_age
            || io.draining()
            || pressured
            || matches!(control, ControlState::Draining | ControlState::Shed { .. })
            || self.request.as_ref().is_some_and(|r| r.discard_over);
        if close {
            self.engine.close_after_reply();
            self.end.get_or_insert(if outcome == Outcome::Close {
                EndReason::ServiceClosed
            } else if u64::from(self.seq) >= u64::from(k.max_requests) {
                EndReason::RequestLimit
            } else if io.draining() || control == ControlState::Draining {
                EndReason::Drained
            } else if now.saturating_duration_since(self.accepted_at) >= k.max_age {
                EndReason::MaxAge
            } else {
                EndReason::ClientClose
            });
        }
        let unix = self.unix_secs(now);
        match shared
            .family
            .respond(&mut self.engine, &mut self.reply.parts, unix, &mut self.out)
        {
            Ok(status) => {
                let n = self.out.len() as u64;
                if let Some(r) = self.request.as_mut() {
                    r.status = Some(status);
                    r.bytes_out = n;
                }
            }
            Err(e) => {
                shared
                    .observer
                    .service_error(&self.env, "reply could not be encoded");
                self.end = Some(EndReason::ServiceClosed);
                return self.refuse(io, e.kind, e.status, None, RequestEnd::Refused(e.kind));
            }
        }
        close |= !self.engine.keep_alive();
        self.closing_after_write = close;
        self.state = State::Writing;
        io.set_exchange_deadline(None);
        io.begin_reply();
        self.flush(io)
    }

    /// Writes a refusal for the current request (which reached `head`) and closes.
    fn refuse<I: Io>(
        &mut self,
        io: &mut I,
        kind: RefusalKind,
        status: u16,
        retry_after: Option<Duration>,
        end: RequestEnd,
    ) -> Step {
        if let Some(r) = self.request.as_mut() {
            r.status = Some(if (400..=599).contains(&status) {
                status
            } else {
                500
            });
        }
        self.out.clear(self.wipe);
        self.out_sent = 0;
        let refusal = Refusal {
            kind,
            status,
            retry_after,
        };
        self.engine.refuse(&refusal, &mut self.out);
        let draining = self.draining_now(io);
        self.count(io, Count::Refused { kind, draining });
        let n = self.out.len() as u64;
        if let Some(r) = self.request.as_mut() {
            r.bytes_out = n;
        }
        self.finish_request(end);
        self.state = State::Closing;
        io.set_exchange_deadline(Some(io.now() + self.limits().write_stall));
        io.begin_reply();
        self.flush(io)
    }

    /// Writes a refusal when no request reached `head` and closes.
    fn refuse_without_request<I: Io>(
        &mut self,
        io: &mut I,
        kind: RefusalKind,
        status: u16,
        retry_after: Option<Duration>,
    ) -> Step {
        self.out.clear(self.wipe);
        self.out_sent = 0;
        let refusal = Refusal {
            kind,
            status,
            retry_after,
        };
        self.engine.refuse(&refusal, &mut self.out);
        let draining = self.draining_now(io);
        self.count(io, Count::Refused { kind, draining });
        match kind {
            RefusalKind::Busy => self.count(io, Count::Shed),
            RefusalKind::HeadTimeout => self.count(io, Count::TimedOut),
            _ => {}
        }
        self.state = State::Closing;
        io.set_exchange_deadline(Some(io.now() + self.limits().write_stall));
        io.begin_reply();
        self.flush(io)
    }

    fn kill(&mut self) -> Step {
        self.end = Some(EndReason::CheckpointKill);
        self.finish_request(RequestEnd::Denied);
        self.out.clear(self.wipe);
        self.out_sent = 0;
        self.state = State::Closed;
        Step::Abort
    }

    fn cancel_deferred(&mut self) {
        if let Some(slot) = &self.defer {
            *slot.lock() = SlotState::Idle;
        }
    }

    /// Ends the current request: `done`, the observer, and admission release, once.
    fn finish_request(&mut self, end: RequestEnd) {
        let Some(r) = self.request.take() else { return };
        let worker = self.env.worker.get();
        let counters = &self.shared.counters;
        counters.count(worker, Count::Requests);
        match end {
            RequestEnd::Replied => counters.count(worker, Count::Replied),
            RequestEnd::Shed => counters.count(worker, Count::Shed),
            RequestEnd::Denied => counters.count(worker, Count::Denied),
            RequestEnd::TimedOut => counters.count(worker, Count::TimedOut),
            _ => {}
        }
        let live = matches!(
            self.checkpoint(),
            ControlState::Draining | ControlState::Stopping
        );
        self.draining_seen |= live;
        let counters = &self.shared.counters;
        if self.draining_seen {
            counters.count(worker, Count::FinishedDraining);
        }
        let finished = Finished {
            status: r.status,
            end,
            bytes_in: r.bytes_in,
            bytes_out: r.bytes_out,
            head_at: r.head_at,
            admitted_at: r.admitted_at,
            replied_at: if end == RequestEnd::Replied {
                Some(Instant::now())
            } else {
                None
            },
        };
        let shared = Arc::clone(&self.shared);
        shared.service.done(&self.env, &finished);
        shared.observer.request_finished(&self.env, &finished);
        if let Some(a) = r.admitted {
            shared.admit.release(self.env.worker, &self.env, a);
        }
        if self.wipe {
            crate::engine::wipe_bytes(&mut self.body);
        }
        self.body.clear();
    }

    /// The current envelope (tests).
    #[cfg(test)]
    pub(crate) fn envelope(&self) -> &Envelope {
        &self.env
    }
}
