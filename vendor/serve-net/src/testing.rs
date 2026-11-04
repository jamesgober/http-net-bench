//! Calling a service with raw request bytes, without sockets or threads.
//!
//! The request goes through the real HTTP engine, the real head decision,
//! body policy, admission, and reply encoding, with the default hooks. A
//! malformed request returns the refusal serve-net would send.
//!
//! ```
//! use serve_net::testing::{respond, TestRequest};
//!
//! let site = serve_net::handler(|req, reply| {
//!     if req.client().addr().is_some_and(|a| a.is_loopback()) {
//!         reply.text(200, "local");
//!     } else {
//!         reply.text(403, "no");
//!     }
//! });
//! assert_eq!(respond(&site, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").text(), "local");
//! let remote = TestRequest::new(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").client("198.51.100.4:5000".parse().unwrap());
//! assert_eq!(remote.send(&site).status, 403);
//! // Malformed input never reaches the service.
//! assert_eq!(respond(&site, b"GET / HTTP/1.1\r\n\r\n").status, 400);
//! ```

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::Finished;
use crate::client::{ClientInfo, Scheme};
use crate::config::{KeepAlive, Limits, Profile, ProfileId, ProfileTable, ProxySource};
use crate::conn::{Conn, Io, ListenerRuntime, Phase, Shared, Step, Timeout};
use crate::envelope::Envelope;
use crate::hooks::{
    Admit, DefaultHooks, HookSet, Hooks, InFlightCap, Inline, NoCheckpoint, NoObserver,
};
use crate::http::{HttpFamily, HttpHead, HttpReply, HttpRequest, HttpService};
use crate::net::{ConnectionId, NoControl, WorkerId};
use crate::reply::{PostFail, Waker};
use crate::service::{HeadAction, Outcome, WorkClass};

/// Calls `service` with `request` (raw HTTP/1.1 bytes) from 127.0.0.1.
pub fn respond<S: HttpService>(service: &S, request: &[u8]) -> TestReply {
    TestRequest::new(request).send(service)
}

/// A request to send to a service in a test.
#[must_use]
#[derive(Debug)]
pub struct TestRequest<'a> {
    raw: &'a [u8],
    client: SocketAddr,
    scheme: Scheme,
    profile: Option<Profile>,
    proxy: Option<ProxySource>,
}

impl<'a> TestRequest<'a> {
    /// A request from 127.0.0.1:40000 over plain HTTP.
    pub fn new(request: &'a [u8]) -> Self {
        TestRequest {
            raw: request,
            client: SocketAddr::from(([127, 0, 0, 1], 40000)),
            scheme: Scheme::Http,
            profile: None,
            proxy: None,
        }
    }

    /// The socket peer.
    pub fn client(mut self, addr: SocketAddr) -> Self {
        self.client = addr;
        self
    }

    /// The scheme of the connection (TLS on for `Https`).
    pub fn scheme(mut self, scheme: Scheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// The profile the request runs under (limits, keep-alive, body policy).
    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Sends it as if behind a proxy configured with `source`.
    pub fn behind(mut self, source: ProxySource) -> Self {
        self.proxy = Some(source);
        self
    }

    /// Runs the request through serve-net and the service.
    pub fn send<S: HttpService>(self, service: &S) -> TestReply {
        let head = self.raw.starts_with(b"HEAD ");
        let mut profile = self.profile.unwrap_or_else(|| Profile::new(ProfileId(0)));
        profile.id = ProfileId(0);
        let (shared, _) = shared(ByRef(service), profile, self.proxy, self.scheme);
        let mut io = SimIo::new(Instant::now());
        let client = ClientInfo::direct(self.client, self.scheme == Scheme::Https);
        let mut conn = Conn::new(
            Arc::clone(&shared),
            0,
            io.connection,
            client,
            io.now,
            io.worker,
        );
        let mut step = conn.on_open(&mut io, false);
        let mut input: &[u8] = self.raw;
        let mut eof = false;
        // Drive the machine until it closes or stalls with nothing left to give it.
        for _ in 0..10_000 {
            match step {
                Step::Close | Step::Abort => break,
                Step::Write => step = conn.on_writable(&mut io),
                Step::Park { .. } => {
                    if let Some((token, value)) = io.take_wake() {
                        step = conn.on_wake(&mut io, token, value);
                    } else {
                        step = conn.on_timeout(&mut io, Timeout::Park);
                    }
                }
                Step::Read => {
                    if !input.is_empty() {
                        let (n, next) = conn.on_data(&mut io, input);
                        input = &input[n.min(input.len())..];
                        step = next;
                        if n == 0 && next == Step::Read {
                            // Nothing consumed and nothing to do: give it EOF.
                            input = &[];
                        }
                    } else if !eof {
                        eof = true;
                        step = conn.on_peer_closed(&mut io);
                    } else {
                        step = conn.on_timeout(&mut io, Timeout::Exchange);
                    }
                }
            }
        }
        conn.on_close(crate::net::CloseReason::PeerClosed);
        TestReply::parse(&io.written, head)
    }
}

/// What a service answered in a test.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestReply {
    /// The status, or 0 when nothing was written.
    pub status: u16,
    /// The fields, in order.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
    /// Whether the reply closed the connection.
    pub closes: bool,
}

impl TestReply {
    /// The first field with this name (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// The body as UTF-8; `""` when it is not.
    #[must_use]
    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.body).unwrap_or("")
    }

    fn parse(bytes: &[u8], asked_head: bool) -> TestReply {
        let mut fields = [http_net::FieldSpan::default(); 128];
        let asked = http_net::Asked {
            head: asked_head,
            connect: false,
        };
        let mut at = 0;
        // Skip interim responses (100 Continue).
        loop {
            let Ok(http_net::Parsed::Complete { head, len }) = http_net::parse_response_head(
                &bytes[at..],
                &http_net::Limits::new(),
                asked,
                &mut fields,
            ) else {
                return TestReply {
                    status: 0,
                    headers: Vec::new(),
                    body: Vec::new(),
                    closes: true,
                };
            };
            let view = head.view();
            if view.is_informational() {
                at += len;
                continue;
            }
            let body_start = at + len;
            let n = match view.framing() {
                http_net::BodyFraming::Length(n) => usize::try_from(n).unwrap_or(usize::MAX),
                _ => 0,
            };
            let body = bytes
                .get(body_start..body_start.saturating_add(n).min(bytes.len()))
                .unwrap_or(&[])
                .to_vec();
            return TestReply {
                status: view.status(),
                headers: view
                    .headers()
                    .map(|(n, v)| (n.to_owned(), v.to_vec()))
                    .collect(),
                body,
                closes: !view.keep_alive(),
            };
        }
    }
}

/// One keep-alive connection to a service, kept across requests, for tests of
/// keep-alive, pipelining, and per-connection behaviour.
///
/// ```
/// use serve_net::testing::TestConnection;
///
/// let mut conn = TestConnection::new(serve_net::handler(|req, reply| { reply.text(200, req.path()); }));
/// let replies = conn.send(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
/// assert_eq!(replies.len(), 2);
/// assert_eq!(replies[1].text(), "/b");
/// assert!(conn.is_open());
/// ```
pub struct TestConnection<S: HttpService> {
    conn: Conn<HttpFamily, S, DefaultHooks>,
    io: SimIo,
    open: bool,
}

impl<S: HttpService> TestConnection<S> {
    /// A connection from 127.0.0.1:40000 to `service` with the default profile.
    pub fn new(service: S) -> Self {
        Self::with_profile(service, Profile::new(ProfileId(0)))
    }

    /// A connection whose requests run under `profile`.
    pub fn with_profile(service: S, profile: Profile) -> Self {
        Self::build(service, profile, None)
    }

    /// A connection from a proxy at 127.0.0.1 configured with `source`, so
    /// forwarded headers decide the client of each request; requests run
    /// under `profile`.
    pub fn behind(service: S, source: ProxySource, profile: Profile) -> Self {
        Self::build(service, profile, Some(source))
    }

    fn build(service: S, mut profile: Profile, proxy: Option<ProxySource>) -> Self {
        profile.id = ProfileId(0);
        let (shared, _) = shared(service, profile, proxy, Scheme::Http);
        let mut io = SimIo::new(Instant::now());
        let client = ClientInfo::direct(SocketAddr::from(([127, 0, 0, 1], 40000)), false);
        let mut conn = Conn::new(shared, 0, io.connection, client, io.now, io.worker);
        let open = conn.on_open(&mut io, false) == Step::Read;
        TestConnection { conn, io, open }
    }

    /// Sends `bytes` and returns every reply they produced.
    pub fn send(&mut self, bytes: &[u8]) -> Vec<TestReply> {
        let mut out = Vec::new();
        self.send_into(bytes, &mut out);
        let mut replies = Vec::new();
        let mut rest = out.as_slice();
        while !rest.is_empty() {
            let reply = TestReply::parse(rest, false);
            let used = reply_len(rest).max(1);
            replies.push(reply);
            rest = &rest[used.min(rest.len())..];
        }
        replies
    }

    /// Sends `bytes` and appends the raw bytes written to `out`. Allocates
    /// nothing once the connection and `out` have warmed up.
    pub fn send_into(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        let mut input = bytes;
        let mut step = Step::Read;
        while self.open {
            match step {
                Step::Close | Step::Abort => {
                    self.open = false;
                    self.conn.on_close(crate::net::CloseReason::Shutdown);
                }
                Step::Write => step = self.conn.on_writable(&mut self.io),
                Step::Park { .. } => match self.io.take_wake() {
                    Some((token, value)) => step = self.conn.on_wake(&mut self.io, token, value),
                    None => break,
                },
                Step::Read if input.is_empty() => break,
                Step::Read => {
                    let (n, next) = self.conn.on_data(&mut self.io, input);
                    input = &input[n.min(input.len())..];
                    step = next;
                    if n == 0 && next == Step::Read {
                        break;
                    }
                }
            }
        }
        out.extend_from_slice(&self.io.written);
        self.io.written.clear();
    }

    /// Whether the connection is still open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open
    }
}

impl<S: HttpService> Drop for TestConnection<S> {
    fn drop(&mut self) {
        if self.open {
            self.open = false;
            self.conn.on_close(crate::net::CloseReason::PeerClosed);
        }
    }
}

impl<S: HttpService> core::fmt::Debug for TestConnection<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestConnection")
            .field("open", &self.open)
            .finish()
    }
}

/// The length of the first response in `bytes` (head plus content-length body).
fn reply_len(bytes: &[u8]) -> usize {
    let mut fields = [http_net::FieldSpan::default(); 128];
    let asked = http_net::Asked {
        head: false,
        connect: false,
    };
    let mut at = 0;
    loop {
        let Ok(http_net::Parsed::Complete { head, len }) = http_net::parse_response_head(
            &bytes[at..],
            &http_net::Limits::new(),
            asked,
            &mut fields,
        ) else {
            return bytes.len();
        };
        let view = head.view();
        if view.is_informational() {
            at += len;
            continue;
        }
        let n = match view.framing() {
            http_net::BodyFraming::Length(n) => usize::try_from(n).unwrap_or(usize::MAX),
            _ => 0,
        };
        return at.saturating_add(len).saturating_add(n);
    }
}

/// Lets the machine borrow a service for the length of a test.
struct ByRef<'s, S>(&'s S);

impl<S: HttpService> HttpService for ByRef<'_, S> {
    const WORK: WorkClass = S::WORK;
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        self.0.head(head, env)
    }
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        self.0.call(request, env, reply)
    }
    fn done(&self, env: &Envelope, finished: &Finished) {
        self.0.done(env, finished);
    }
}

/// Builds the shared state of a one-listener server with the default hooks.
/// The shared state of a test server and a copy of its profile table.
pub(crate) type TestShared<S, H> = (Arc<Shared<HttpFamily, S, H>>, ProfileTable);

pub(crate) fn shared<S: HttpService>(
    service: S,
    profile: Profile,
    proxy: Option<ProxySource>,
    scheme: Scheme,
) -> TestShared<S, DefaultHooks> {
    shared_with(
        service,
        profile,
        proxy,
        scheme,
        HookSet {
            admit: InFlightCap::new(),
            dispatch: Inline,
            checkpoint: NoCheckpoint,
            observer: NoObserver,
            control: Arc::new(NoControl),
            gate: crate::net::AllowAll,
            events: crate::net::NoopSink,
            tls: net_io::NoTls,
        },
    )
}

/// As [`shared`], with given hooks.
#[allow(clippy::type_complexity)] // the hook set's eight slots, as in `ServerBuilder`
pub(crate) fn shared_with<S: HttpService, A, D, K, O, G, E, C, T>(
    service: S,
    profile: Profile,
    proxy: Option<ProxySource>,
    scheme: Scheme,
    hooks: HookSet<A, D, K, O, G, E, C, T>,
) -> TestShared<S, HookSet<A, D, K, O, G, E, C, T>>
where
    HookSet<A, D, K, O, G, E, C, T>:
        Hooks<Admit = A, Dispatch = D, Checkpoint = K, Observer = O, Control = C>,
    A: Admit,
    C: crate::net::ControlLine,
{
    let profiles = ProfileTable::compile(
        core::slice::from_ref(&profile),
        Limits::new(),
        KeepAlive::new(),
    );
    let copy = ProfileTable::compile(
        core::slice::from_ref(&profile),
        Limits::new(),
        KeepAlive::new(),
    );
    let mut admit = hooks.admit;
    admit.prepare(1, &profiles);
    let listener = ListenerRuntime {
        name: "test".into(),
        profile: ProfileId(0),
        proxy,
        declared_scheme: scheme,
    };
    let shared = Shared {
        family: HttpFamily,
        service,
        admit,
        dispatch: hooks.dispatch,
        checkpoint: hooks.checkpoint,
        observer: hooks.observer,
        control: Arc::new(crate::running::Merged::new(hooks.control)),
        profiles,
        listeners: vec![listener],
        counters: Arc::new(crate::stats::Counters::new(1)),
    };
    (Arc::new(shared), copy)
}

/// A transport simulated in memory, with a clock that moves only when told.
pub(crate) struct SimIo {
    pub(crate) now: Instant,
    pub(crate) connection: ConnectionId,
    pub(crate) worker: WorkerId,
    pub(crate) written: Vec<u8>,
    /// Bytes `push` accepts before reporting the output full; `None` = unlimited.
    pub(crate) budget: Option<usize>,
    pub(crate) deadline: Option<Instant>,
    pub(crate) phase: Phase,
    pub(crate) draining: bool,
    pub(crate) pressure: f32,
    /// The per-connection idle override the machine last set.
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) wakes: Arc<SimWaker>,
}

/// Records posted wakes.
#[derive(Default)]
pub(crate) struct SimWaker {
    pub(crate) posted: Mutex<VecDeque<(ConnectionId, u32, u64)>>,
    pub(crate) full: std::sync::atomic::AtomicBool,
}

impl Waker for SimWaker {
    fn post(&self, connection: ConnectionId, token: u32, value: u64) -> Result<(), PostFail> {
        if self.full.load(std::sync::atomic::Ordering::Acquire) {
            return Err(PostFail::Full);
        }
        self.posted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back((connection, token, value));
        Ok(())
    }
}

impl SimIo {
    pub(crate) fn new(now: Instant) -> Self {
        SimIo {
            now,
            connection: SIM_CONNECTION,
            worker: WorkerId::first(),
            written: Vec::with_capacity(16 * 1024),
            budget: None,
            deadline: None,
            phase: Phase::Idle,
            draining: false,
            pressure: 0.0,
            idle_timeout: None,
            wakes: Arc::new(SimWaker::default()),
        }
    }

    pub(crate) fn take_wake(&mut self) -> Option<(u32, u64)> {
        let mut q = self
            .wakes
            .posted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        q.pop_front().map(|(_, t, v)| (t, v))
    }

    #[cfg(test)]
    pub(crate) fn advance(&mut self, by: Duration) {
        self.now += by;
    }
}

/// The id of simulated connections (checked at compile time).
const SIM_CONNECTION: ConnectionId = match ConnectionId::new(1) {
    Some(id) => id,
    None => panic!("1 is a valid connection id"),
};

impl Io for SimIo {
    fn now(&self) -> Instant {
        self.now
    }
    fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        self.deadline = at;
    }
    fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }
    fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.idle_timeout = timeout;
    }
    fn begin_reply(&mut self) {}
    fn push(&mut self, bytes: &[u8]) -> usize {
        let n = match &mut self.budget {
            None => bytes.len(),
            Some(left) => {
                let n = bytes.len().min(*left);
                *left -= n;
                n
            }
        };
        self.written.extend_from_slice(&bytes[..n]);
        n
    }
    fn draining(&self) -> bool {
        self.draining
    }
    fn pressure(&self) -> f32 {
        self.pressure
    }
    fn worker(&self) -> WorkerId {
        self.worker
    }
    fn waker(&self) -> Arc<dyn Waker> {
        Arc::clone(&self.wakes) as Arc<dyn Waker>
    }
}
