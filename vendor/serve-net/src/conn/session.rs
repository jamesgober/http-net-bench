//! The connection machine as a net-io session.
//!
//! A thin translation: net-io's worker calls the session, the session calls
//! [`Conn`] with an [`Io`] over net-io's `SessionContext`, and maps the
//! returned step back. Soft connection caps are taken in the factory, so the
//! busy refusal is written by the session before anything is read (D-013).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use net_io::{
    CloseReason, Completer, ConnectionInfo, Input, PostError, RefusalCause, SessionContext,
    TimeoutKind,
};

use super::{Conn, Io, Phase, Shared, Step, Timeout};
use crate::client::ClientInfo;
use crate::config::ProfileId;
use crate::engine::{Family, Service};
use crate::hooks::Hooks;
use crate::net::{ConnectionId, WorkerId};
use crate::reply::{PostFail, Waker};

/// A worker's completion queue as the machine's waker.
struct CompleterWaker(Completer);

impl Waker for CompleterWaker {
    fn post(&self, connection: ConnectionId, token: u32, value: u64) -> Result<(), PostFail> {
        self.0.post(connection, token, value).map_err(|e| match e {
            PostError::Full => PostFail::Full,
            _ => PostFail::Stopped,
        })
    }
}

/// One soft cap: a limit and the connections holding a seat under it.
struct Cap {
    limit: u32,
    open: AtomicU32,
}

impl Cap {
    fn new(limit: Option<u32>) -> Cap {
        Cap {
            limit: limit.unwrap_or(u32::MAX),
            open: AtomicU32::new(0),
        }
    }

    /// Takes a seat; `true` when the cap is now exceeded.
    fn take(&self) -> bool {
        self.open.fetch_add(1, Ordering::AcqRel) >= self.limit
    }

    fn give_back(&self) {
        self.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The runtime state every session of one server shares, independent of the
/// service and hook types.
pub(crate) struct Runtime {
    global: Cap,
    listeners: Box<[Cap]>,
    profiles: Box<[Cap]>,
    /// One waker per worker, made on first use (no allocation per connection).
    wakers: Box<[OnceLock<Arc<dyn Waker>>]>,
}

impl Runtime {
    pub(crate) fn new(
        global: Option<u32>,
        listeners: &[Option<u32>],
        profiles: &[Option<u32>],
        workers: u16,
    ) -> Runtime {
        Runtime {
            global: Cap::new(global),
            listeners: listeners.iter().map(|l| Cap::new(*l)).collect(),
            profiles: profiles.iter().map(|p| Cap::new(*p)).collect(),
            wakers: (0..workers.max(1)).map(|_| OnceLock::new()).collect(),
        }
    }
}

/// A connection's seat under the global, listener, and profile caps; given
/// back on drop, so a panicking session cannot leak it.
struct Seat {
    rt: Arc<Runtime>,
    listener: usize,
    profile: usize,
}

impl Seat {
    fn take(rt: &Arc<Runtime>, listener: usize, profile: ProfileId) -> (Seat, bool) {
        let profile = usize::from(profile.0);
        let mut over = rt.global.take();
        if let Some(c) = rt.listeners.get(listener) {
            over |= c.take();
        }
        if let Some(c) = rt.profiles.get(profile) {
            over |= c.take();
        }
        let seat = Seat {
            rt: Arc::clone(rt),
            listener,
            profile,
        };
        (seat, over)
    }
}

impl Drop for Seat {
    fn drop(&mut self) {
        self.rt.global.give_back();
        if let Some(c) = self.rt.listeners.get(self.listener) {
            c.give_back();
        }
        if let Some(c) = self.rt.profiles.get(self.profile) {
            c.give_back();
        }
    }
}

/// [`Io`] over net-io's session context.
struct NetIo<'a, 'b> {
    cx: &'a mut SessionContext<'b>,
    rt: &'a Runtime,
}

impl Io for NetIo<'_, '_> {
    fn now(&self) -> Instant {
        self.cx.now()
    }
    fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        self.cx.set_exchange_deadline(at);
    }
    fn set_phase(&mut self, phase: Phase) {
        self.cx.set_phase(match phase {
            Phase::Idle => net_io::Phase::Idle,
            Phase::Receiving => net_io::Phase::Receiving,
            Phase::Sending => net_io::Phase::Sending,
        });
    }
    fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.cx.set_idle_timeout(timeout);
    }
    fn begin_reply(&mut self) {
        self.cx.output().begin_response();
    }
    fn push(&mut self, bytes: &[u8]) -> usize {
        self.cx.output().push_partial(bytes)
    }
    fn draining(&self) -> bool {
        self.cx.draining()
    }
    fn pressure(&self) -> f32 {
        self.cx.pressure()
    }
    fn worker(&self) -> WorkerId {
        self.cx.worker()
    }
    fn waker(&self) -> Arc<dyn Waker> {
        let made = || Arc::new(CompleterWaker(self.cx.completer())) as Arc<dyn Waker>;
        match self.rt.wakers.get(usize::from(self.cx.worker().get())) {
            Some(cell) => Arc::clone(cell.get_or_init(made)),
            None => made(),
        }
    }
}

fn step(s: Step) -> net_io::Step {
    match s {
        Step::Read => net_io::Step::Read,
        Step::Write => net_io::Step::Write,
        Step::Park { until } => net_io::Step::Park { until: Some(until) },
        Step::Close => net_io::Step::Close,
        Step::Abort => net_io::Step::Abort,
    }
}

/// The machine counts a reply as handed over once `push` took it, but net-io
/// sends queued output only on `Write` (and `Close`). So a `Read` or `Park`
/// with output queued becomes `Write`, and the step resumes after the flush
/// (D-045).
fn handed(s: Step, cx: &mut SessionContext<'_>, resume: &mut Option<Step>) -> net_io::Step {
    match s {
        Step::Read | Step::Park { .. } if !cx.output().is_empty() => {
            *resume = Some(s);
            net_io::Step::Write
        }
        other => step(other),
    }
}

/// One connection under net-io.
pub(crate) struct ServeSession<F: Family, S: Service<F>, H: Hooks> {
    conn: Conn<F, S, H>,
    rt: Arc<Runtime>,
    worker: WorkerId,
    over_cap: bool,
    /// The step a flush forced by [`handed`] interrupted.
    resume: Option<Step>,
    _seat: Seat,
}

impl<F: Family, S: Service<F> + 'static, H: Hooks> net_io::Session for ServeSession<F, S, H> {
    fn on_open(&mut self, cx: &mut SessionContext<'_>) -> net_io::Step {
        let mut io = NetIo {
            cx: &mut *cx,
            rt: &self.rt,
        };
        let s = self.conn.on_open(&mut io, self.over_cap);
        handed(s, cx, &mut self.resume)
    }

    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> net_io::Step {
        let mut io = NetIo {
            cx: &mut *cx,
            rt: &self.rt,
        };
        let (n, s) = self.conn.on_data(&mut io, input.bytes());
        input.consume(n);
        handed(s, cx, &mut self.resume)
    }

    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> net_io::Step {
        // A parked reply keeps waiting; any other interrupted step continues
        // with what the machine does after a write (pipelined input already
        // in the engine).
        if let Some(s @ Step::Park { .. }) = self.resume.take() {
            return step(s);
        }
        let mut io = NetIo {
            cx: &mut *cx,
            rt: &self.rt,
        };
        let s = self.conn.on_writable(&mut io);
        handed(s, cx, &mut self.resume)
    }

    fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, value: u64) -> net_io::Step {
        let mut io = NetIo {
            cx: &mut *cx,
            rt: &self.rt,
        };
        let s = self.conn.on_wake(&mut io, token, value);
        handed(s, cx, &mut self.resume)
    }

    fn on_timeout(&mut self, cx: &mut SessionContext<'_>, which: TimeoutKind) -> net_io::Step {
        let which = match which {
            TimeoutKind::Exchange => Timeout::Exchange,
            TimeoutKind::Park => Timeout::Park,
            TimeoutKind::Handshake => Timeout::Transport(CloseReason::HandshakeTimeout),
            TimeoutKind::Idle => Timeout::Transport(CloseReason::Idle),
            TimeoutKind::Write => Timeout::Transport(CloseReason::WriteTimeout),
            TimeoutKind::Drain => Timeout::Transport(CloseReason::DrainDeadline),
            _ => Timeout::Transport(CloseReason::ReadTimeout),
        };
        let mut io = NetIo {
            cx: &mut *cx,
            rt: &self.rt,
        };
        let s = self.conn.on_timeout(&mut io, which);
        handed(s, cx, &mut self.resume)
    }

    fn on_peer_closed(&mut self, cx: &mut SessionContext<'_>) -> net_io::Step {
        let mut io = NetIo {
            cx: &mut *cx,
            rt: &self.rt,
        };
        let s = self.conn.on_peer_closed(&mut io);
        handed(s, cx, &mut self.resume)
    }

    fn on_denied(&mut self, code: u16, output: &mut net_io::Output) {
        let refusal = self.conn.on_denied(code, self.worker);
        // net-io sends this once, bounded by its refusal limit; what does not
        // fit is dropped, and the connection closes either way.
        let _ = output.push_partial(refusal);
    }

    fn on_close(&mut self, _info: &ConnectionInfo, reason: CloseReason) {
        self.conn.on_close(reason);
    }
}

/// Makes one [`ServeSession`] per connection net-io admits.
pub(crate) struct Factory<F: Family, S: Service<F>, H: Hooks> {
    pub(crate) shared: Arc<Shared<F, S, H>>,
    pub(crate) rt: Arc<Runtime>,
}

impl<F: Family, S: Service<F> + 'static, H: Hooks> net_io::SessionFactory for Factory<F, S, H> {
    type Session = ServeSession<F, S, H>;

    fn open(&self, info: &ConnectionInfo) -> Result<Self::Session, RefusalCause> {
        let listener = info.listener.map_or(0, |l| usize::from(l.get()));
        let Some(runtime) = self.shared.listeners.get(listener) else {
            return Err(RefusalCause::Session);
        };
        let Some(peer) = info.client_addr() else {
            return Err(RefusalCause::Session);
        };
        let client = ClientInfo::direct(peer, info.tls.is_some());
        let (seat, over_cap) = Seat::take(&self.rt, listener, runtime.profile);
        let conn = Conn::new(
            Arc::clone(&self.shared),
            listener,
            info.id,
            client,
            info.accepted_at,
            info.worker,
        );
        Ok(ServeSession {
            conn,
            rt: Arc::clone(&self.rt),
            worker: info.worker,
            over_cap,
            resume: None,
            _seat: seat,
        })
    }
}
