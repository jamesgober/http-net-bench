//! Simulated-connection tests: the state machine driven with scripted input
//! and a manual clock, without sockets. Test names name the requirement,
//! threat, or invariant (dev/PLAN.md) they check.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::config::{Budget, Profile};
use crate::hooks::{HookSet, InFlightCap, Inline, NoCheckpoint, NoObserver};
use crate::http::{HttpFamily, HttpHead, HttpReply, HttpRequest, HttpService};
use crate::net::{Lane, NoControl, SimpleControl};
use crate::reply::ReplyToken;
use crate::testing::{SimIo, TestReply, TestRequest, shared, shared_with};

/// Counts calls so the `done`-exactly-once invariant can be checked.
#[derive(Default)]
struct Counting {
    heads: AtomicU32,
    calls: AtomicU32,
    dones: AtomicU32,
    ends: Mutex<Vec<RequestEnd>>,
}

impl HttpService for Counting {
    fn head(&self, _head: &HttpHead<'_>, _env: &mut Envelope) -> HeadAction {
        self.heads.fetch_add(1, Ordering::Relaxed);
        HeadAction::Proceed
    }
    fn call(&self, req: &HttpRequest<'_>, _env: &Envelope, reply: &mut HttpReply) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        reply.text(200, req.path());
        Outcome::Done
    }
    fn done(&self, _env: &Envelope, finished: &Finished) {
        self.dones.fetch_add(1, Ordering::Relaxed);
        self.ends.lock().unwrap().push(finished.end);
    }
}

type C<S> = Conn<HttpFamily, S, crate::hooks::DefaultHooks>;

fn conn<S: HttpService>(service: S, profile: Profile) -> (C<S>, SimIo) {
    let (shared, _) = shared(service, profile, None, Scheme::Http);
    let io = SimIo::new(Instant::now());
    let client = ClientInfo::direct("127.0.0.1:5000".parse().unwrap(), false);
    let c = Conn::new(shared, 0, io.connection, client, io.now, io.worker);
    (c, io)
}

fn replies(bytes: &[u8]) -> Vec<TestReply> {
    // Split the written bytes into responses (content-length framed).
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let end = rest
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(rest.len(), |p| p + 4);
        let head = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
        let len = head
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-length: ")
                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
            })
            .unwrap_or(0);
        let total = (end + len).min(rest.len());
        out.push(parse_one(&rest[..total]));
        rest = &rest[total..];
    }
    out
}

fn parse_one(bytes: &[u8]) -> TestReply {
    let text = String::from_utf8_lossy(bytes);
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body_at = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(bytes.len(), |p| p + 4);
    TestReply {
        status,
        headers: Vec::new(),
        body: bytes[body_at..].to_vec(),
        closes: text.contains("connection: close"),
    }
}

const GET: &[u8] = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n";

#[test]
fn test_get_replied_and_kept_alive() {
    let svc = Counting::default();
    let (mut c, mut io) = conn(svc, Profile::new(ProfileId(0)));
    assert_eq!(c.on_open(&mut io, false), Step::Read);
    let (n, step) = c.on_data(&mut io, GET);
    assert_eq!((n, step), (GET.len(), Step::Read));
    let r = replies(&io.written);
    assert_eq!(r.len(), 1);
    assert_eq!(
        (r[0].status, r[0].body.as_slice(), r[0].closes),
        (200, &b"/a"[..], false)
    );
    assert_eq!(io.phase, Phase::Idle);
    assert_eq!(io.deadline, None);
}

#[test]
fn test_done_exactly_once_on_every_path() {
    // Invariant 1, across a reply, a refusal, a timeout, and a close mid-request.
    let svc = Arc::new(Counting::default());
    struct Shared(Arc<Counting>);
    impl HttpService for Shared {
        fn head(&self, h: &HttpHead<'_>, e: &mut Envelope) -> HeadAction {
            HttpService::head(&*self.0, h, e)
        }
        fn call(&self, r: &HttpRequest<'_>, e: &Envelope, o: &mut HttpReply) -> Outcome {
            HttpService::call(&*self.0, r, e, o)
        }
        fn done(&self, e: &Envelope, f: &Finished) {
            HttpService::done(&*self.0, e, f);
        }
    }
    // 1. replied
    let (mut c, mut io) = conn(Shared(svc.clone()), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    c.on_close(crate::net::CloseReason::PeerClosed);
    // 2. body timeout
    let (mut c, mut io) = conn(Shared(svc.clone()), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(
        &mut io,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nab",
    );
    assert_eq!(c.on_timeout(&mut io, Timeout::Exchange), Step::Close);
    c.on_close(crate::net::CloseReason::Shutdown);
    // 3. peer gone mid-body
    let (mut c, mut io) = conn(Shared(svc.clone()), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(
        &mut io,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nab",
    );
    c.on_close(crate::net::CloseReason::PeerClosed);
    assert_eq!(svc.heads.load(Ordering::Relaxed), 3);
    assert_eq!(svc.dones.load(Ordering::Relaxed), 3);
    let ends = svc.ends.lock().unwrap().clone();
    assert_eq!(
        ends,
        [
            RequestEnd::Replied,
            RequestEnd::TimedOut,
            RequestEnd::PeerGone
        ]
    );
    assert_eq!(svc.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn test_pipelined_requests_answered_in_order() {
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let input = b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\nGET /3 HTTP/1.1\r\nHost: x\r\n\r\n";
    let (n, step) = c.on_data(&mut io, input);
    assert_eq!((n, step), (input.len(), Step::Read));
    let bodies: Vec<Vec<u8>> = replies(&io.written).into_iter().map(|r| r.body).collect();
    assert_eq!(bodies, [b"/1".to_vec(), b"/2".to_vec(), b"/3".to_vec()]);
}

#[test]
fn test_pipelining_fair_per_wake() {
    let profile =
        Profile::new(ProfileId(0)).limits(crate::config::Limits::new().max_pipelined_per_wake(2));
    let (mut c, mut io) = conn(Counting::default(), profile);
    c.on_open(&mut io, false);
    let one = b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n";
    let input: Vec<u8> = one.iter().copied().cycle().take(one.len() * 5).collect();
    let (n, mut step) = c.on_data(&mut io, &input);
    assert_eq!(n, input.len());
    let mut yields = 0;
    while step == Step::Write {
        yields += 1;
        assert!(yields < 20);
        step = c.on_writable(&mut io);
    }
    assert_eq!(step, Step::Read);
    assert_eq!(yields, 2, "five requests, two per wake: two yields");
    assert_eq!(replies(&io.written).len(), 5);
}

#[test]
fn test_head_trickle_one_byte_per_second_closed_at_deadline() {
    // T-1: input never extends the head deadline.
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let deadline = io.deadline.expect("head deadline armed at open");
    assert_eq!(deadline, io.now + Duration::from_secs(10));
    for b in b"GET / HTTP/1.1\r\nHo" {
        io.advance(Duration::from_millis(500));
        let _ = c.on_data(&mut io, &[*b]);
        assert_eq!(io.deadline, Some(deadline), "a byte moved the deadline");
    }
    let step = c.on_timeout(&mut io, Timeout::Exchange);
    assert_eq!(step, Step::Close);
    let r = replies(&io.written);
    assert_eq!(r[0].status, 408);
    assert!(r[0].closes);
}

#[test]
fn test_head_deadline_no_bytes_quiet_close() {
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    assert_eq!(c.on_timeout(&mut io, Timeout::Exchange), Step::Close);
    assert!(io.written.is_empty());
}

#[test]
fn test_later_request_head_deadline_from_first_byte() {
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    assert_eq!(io.deadline, None);
    io.advance(Duration::from_secs(5));
    let _ = c.on_data(&mut io, b"GET /2 HT");
    assert_eq!(io.deadline, Some(io.now + Duration::from_secs(10)));
    assert_eq!(io.phase, Phase::Receiving);
}

#[test]
fn test_body_deadline_refused_408() {
    // T-2: a slow body hits the request deadline.
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(
        &mut io,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc",
    );
    assert_eq!(io.deadline, Some(c.envelope().deadline()));
    assert_eq!(c.on_timeout(&mut io, Timeout::Exchange), Step::Close);
    assert_eq!(replies(&io.written)[0].status, 408);
}

#[test]
fn test_declared_length_over_max_refused_413_before_body() {
    let svc = Counting::default();
    let profile = Profile::new(ProfileId(0)).limits(crate::config::Limits::new().max_body(10));
    let (mut c, mut io) = conn(svc, profile);
    c.on_open(&mut io, false);
    let (_, step) = c.on_data(
        &mut io,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n",
    );
    assert_eq!(step, Step::Close);
    assert_eq!(replies(&io.written)[0].status, 413);
}

#[test]
fn test_service_head_refusal_closes_and_skips_call() {
    struct No;
    impl HttpService for No {
        fn head(&self, _h: &HttpHead<'_>, _e: &mut Envelope) -> HeadAction {
            HeadAction::refuse(403)
        }
        fn call(&self, _r: &HttpRequest<'_>, _e: &Envelope, _o: &mut HttpReply) -> Outcome {
            panic!("call after a refusal");
        }
    }
    let (mut c, mut io) = conn(No, Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let (_, step) = c.on_data(&mut io, GET);
    assert_eq!(step, Step::Close);
    let r = &replies(&io.written)[0];
    assert_eq!((r.status, r.closes), (403, true));
    assert_eq!(r.body, b"403 Forbidden\n");
}

#[test]
fn test_malformed_request_never_reaches_service_and_later_requests_dropped() {
    // T-7, invariant 7.
    let svc = Counting::default();
    let (mut c, mut io) = conn(svc, Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let input = b"GET / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n";
    let (_, step) = c.on_data(&mut io, input);
    assert_eq!(step, Step::Close);
    let r = replies(&io.written);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].status, 400);
}

#[test]
fn test_admission_shed_503_with_retry_after_no_call() {
    // T-24: over the in-flight cap, the busy refusal and nothing else.
    struct Never;
    impl Admit for Never {
        fn admit(&self, _w: WorkerId, _e: &Envelope) -> Result<Admitted, Shed> {
            Err(Shed {
                retry_after: Some(Duration::from_secs(3)),
                close: false,
            })
        }
        fn release(&self, _w: WorkerId, _e: &Envelope, _a: Admitted) {}
    }
    let svc = Counting::default();
    let hooks = HookSet {
        admit: Never,
        dispatch: Inline,
        checkpoint: NoCheckpoint,
        observer: NoObserver,
        control: Arc::new(NoControl),
        gate: crate::net::AllowAll,
        events: crate::net::NoopSink,
        tls: net_io::NoTls,
    };
    let (shared, _) = shared_with(svc, Profile::new(ProfileId(0)), None, Scheme::Http, hooks);
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared.clone(),
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let (_, step) = c.on_data(
        &mut io,
        b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
    );
    assert_eq!(step, Step::Close);
    let text = String::from_utf8_lossy(&io.written).into_owned();
    // T-22: no 100 Continue before a refusal.
    assert!(text.starts_with("HTTP/1.1 503 "), "{text}");
    assert!(text.contains("retry-after: 3"));
    assert_eq!(shared.service.calls.load(Ordering::Relaxed), 0);
    assert_eq!(shared.service.dones.load(Ordering::Relaxed), 1);
}

#[test]
fn test_expect_continue_sent_after_admission() {
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(
        &mut io,
        b"PUT /f HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
    );
    assert_eq!(io.written, b"HTTP/1.1 100 Continue\r\n\r\n");
    let _ = c.on_data(&mut io, b"ok");
    assert!(String::from_utf8_lossy(&io.written).contains("HTTP/1.1 200 OK"));
}

#[test]
fn test_partial_head_holds_no_admission_slot() {
    // T-23: one slot per worker; a half-sent head does not take it.
    let profile = Profile::new(ProfileId(0)).budget(Budget::new().max_in_flight(1));
    let (shared, _) = shared(Counting::default(), profile, None, Scheme::Http);
    let mut io = SimIo::new(Instant::now());
    let client = ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false);
    let mut slow = Conn::new(shared.clone(), 0, io.connection, client, io.now, io.worker);
    slow.on_open(&mut io, false);
    let _ = slow.on_data(&mut io, b"GET / HTTP/1.1\r\nHo");
    let mut io2 = SimIo::new(Instant::now());
    let mut fast = Conn::new(shared, 0, io2.connection, client, io2.now, io2.worker);
    fast.on_open(&mut io2, false);
    let _ = fast.on_data(&mut io2, GET);
    assert_eq!(replies(&io2.written)[0].status, 200);
}

#[test]
fn test_checkpoint_deny_before_reply_no_bytes_of_reply() {
    // T-28: a denial at BeforeReply replaces the reply whole.
    struct DenyReply;
    impl Checkpoint for DenyReply {
        fn check(&self, _e: &Envelope, at: CheckpointAt) -> Verdict {
            if at == CheckpointAt::BeforeReply {
                Verdict::Deny { status: 403 }
            } else {
                Verdict::Pass
            }
        }
    }
    let hooks = HookSet {
        admit: InFlightCap::new(),
        dispatch: Inline,
        checkpoint: DenyReply,
        observer: NoObserver,
        control: Arc::new(NoControl),
        gate: crate::net::AllowAll,
        events: crate::net::NoopSink,
        tls: net_io::NoTls,
    };
    let (shared, _) = shared_with(
        crate::handler(|_r, o| {
            o.text(200, "secret");
        }),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
        hooks,
    );
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared,
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    let text = String::from_utf8_lossy(&io.written).into_owned();
    assert!(text.starts_with("HTTP/1.1 403 "));
    assert!(!text.contains("secret"));
}

#[test]
fn test_checkpoint_kill_aborts_with_nothing_written() {
    struct Kill;
    impl Checkpoint for Kill {
        fn check(&self, _e: &Envelope, _at: CheckpointAt) -> Verdict {
            Verdict::Kill
        }
    }
    let hooks = HookSet {
        admit: InFlightCap::new(),
        dispatch: Inline,
        checkpoint: Kill,
        observer: NoObserver,
        control: Arc::new(NoControl),
        gate: crate::net::AllowAll,
        events: crate::net::NoopSink,
        tls: net_io::NoTls,
    };
    let (shared, _) = shared_with(
        Counting::default(),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
        hooks,
    );
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared.clone(),
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let (_, step) = c.on_data(&mut io, GET);
    assert_eq!(step, Step::Abort);
    assert!(io.written.is_empty());
    assert_eq!(shared.service.dones.load(Ordering::Relaxed), 1);
}

/// Defers every request; the test completes the token.
struct Later(Mutex<Option<ReplyToken>>);

impl HttpService for Later {
    fn call(&self, _r: &HttpRequest<'_>, _e: &Envelope, reply: &mut HttpReply) -> Outcome {
        *self.0.lock().unwrap() = Some(reply.defer());
        Outcome::Deferred
    }
}

#[test]
fn test_deferred_reply_completed_from_another_thread() {
    let (shared, _) = shared(
        Later(Mutex::new(None)),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
    );
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared.clone(),
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let (_, step) = c.on_data(&mut io, GET);
    assert!(matches!(step, Step::Park { .. }));
    // While parked, input is not read.
    assert_eq!(c.on_data(&mut io, GET).0, 0);
    let mut token = shared.service.0.lock().unwrap().take().unwrap();
    assert!(!token.is_cancelled());
    let t = std::thread::spawn(move || {
        token.reply().text(200, "later");
        token.complete().map_err(|_| ()).unwrap();
    });
    t.join().unwrap();
    let (tok, val) = io.take_wake().unwrap();
    assert_eq!(c.on_wake(&mut io, tok, val), Step::Read);
    let r = replies(&io.written);
    assert_eq!((r[0].status, r[0].body.as_slice()), (200, &b"later"[..]));
}

#[test]
fn test_deferred_deadline_refusal_and_late_complete_expired() {
    // T-26.
    let (shared, _) = shared(
        Later(Mutex::new(None)),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
    );
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared.clone(),
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    assert_eq!(c.on_timeout(&mut io, Timeout::Park), Step::Close);
    assert_eq!(replies(&io.written)[0].status, 503);
    let token = shared.service.0.lock().unwrap().take().unwrap();
    assert!(token.is_cancelled());
    assert!(matches!(
        token.complete(),
        Err(crate::CompleteError::Expired(_))
    ));
}

#[test]
fn test_token_dropped_connection_closed_500() {
    let (shared, _) = shared(
        Later(Mutex::new(None)),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
    );
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared.clone(),
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    drop(shared.service.0.lock().unwrap().take());
    let (tok, val) = io.take_wake().unwrap();
    assert_eq!(c.on_wake(&mut io, tok, val), Step::Close);
    assert_eq!(replies(&io.written)[0].status, 500);
}

#[test]
fn test_complete_busy_returns_token() {
    let (shared, _) = shared(
        Later(Mutex::new(None)),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
    );
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(
        shared.clone(),
        0,
        io.connection,
        ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
        io.now,
        io.worker,
    );
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    io.wakes.full.store(true, Ordering::Release);
    let token = shared.service.0.lock().unwrap().take().unwrap();
    let Err(crate::CompleteError::Busy(mut again)) = token.complete() else {
        panic!("expected Busy")
    };
    io.wakes.full.store(false, Ordering::Release);
    again.reply().text(200, "retried");
    again.complete().map_err(|_| ()).unwrap();
    let (tok, val) = io.take_wake().unwrap();
    let _ = c.on_wake(&mut io, tok, val);
    assert_eq!(replies(&io.written)[0].body, b"retried");
}

#[test]
fn test_deferred_without_defer_is_500() {
    let (mut c, mut io) = conn(
        {
            struct Liar;
            impl HttpService for Liar {
                fn call(&self, _r: &HttpRequest<'_>, _e: &Envelope, _o: &mut HttpReply) -> Outcome {
                    Outcome::Deferred
                }
            }
            Liar
        },
        Profile::new(ProfileId(0)),
    );
    c.on_open(&mut io, false);
    let (_, step) = c.on_data(&mut io, GET);
    assert_eq!(step, Step::Close);
    assert_eq!(replies(&io.written)[0].status, 500);
}

#[test]
fn test_request_limit_last_reply_closes() {
    let profile = Profile::new(ProfileId(0)).keep_alive(KeepAlive::new().max_requests(2));
    let (mut c, mut io) = conn(Counting::default(), profile);
    c.on_open(&mut io, false);
    let (_, s1) = c.on_data(&mut io, GET);
    assert_eq!(s1, Step::Read);
    let (_, s2) = c.on_data(&mut io, GET);
    assert_eq!(s2, Step::Close);
    let r = replies(&io.written);
    assert!(!r[0].closes && r[1].closes);
}

#[test]
fn test_drain_sets_close_signal() {
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    io.draining = true;
    let (_, step) = c.on_data(&mut io, GET);
    assert_eq!(step, Step::Close);
    assert!(replies(&io.written)[0].closes);
}

#[test]
fn test_idle_flood_blocking_pool_shortens_keep_alive() {
    // FR-58, T-4: above 75% busy the next idle wait is 2 s; above 90% replies close.
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    io.pressure = 0.74;
    assert_eq!(c.on_data(&mut io, GET).1, Step::Read);
    assert_eq!(io.idle_timeout, None);
    io.pressure = 0.8;
    assert_eq!(c.on_data(&mut io, GET).1, Step::Read);
    assert_eq!(io.idle_timeout, Some(Duration::from_secs(2)));
    io.pressure = 0.5;
    assert_eq!(c.on_data(&mut io, GET).1, Step::Read);
    assert_eq!(
        io.idle_timeout, None,
        "the listener's idle timeout is restored"
    );
    io.pressure = 0.95;
    let (_, step) = c.on_data(&mut io, GET);
    assert_eq!(step, Step::Close);
    assert!(replies(&io.written).last().unwrap().closes);
}

#[test]
fn test_control_shed_refuses_lane_and_lockdown_refuses_non_critical() {
    let control = Arc::new(SimpleControl::new());
    let hooks = HookSet {
        admit: InFlightCap::new(),
        dispatch: Inline,
        checkpoint: NoCheckpoint,
        observer: NoObserver,
        control: control.clone(),
        gate: crate::net::AllowAll,
        events: crate::net::NoopSink,
        tls: net_io::NoTls,
    };
    let (shared, _) = shared_with(
        Counting::default(),
        Profile::new(ProfileId(0)),
        None,
        Scheme::Http,
        hooks,
    );
    let client = ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false);
    control.set(ControlState::Shed { from_lane: Lane(4) }, None);
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(shared.clone(), 0, io.connection, client, io.now, io.worker);
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    assert_eq!(replies(&io.written)[0].status, 503);
    control.set(ControlState::Shed { from_lane: Lane(5) }, None);
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(shared.clone(), 0, io.connection, client, io.now, io.worker);
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    let r = &replies(&io.written)[0];
    assert_eq!(r.status, 200);
    assert!(r.closes, "keep-alive ends under shed");
    control.set(ControlState::Lockdown, None);
    let mut io = SimIo::new(Instant::now());
    let mut c = Conn::new(shared, 0, io.connection, client, io.now, io.worker);
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, GET);
    assert_eq!(replies(&io.written)[0].status, 503);
}

#[test]
fn test_output_budget_backpressure_then_completes() {
    let big = "x".repeat(10_000);
    let (mut c, mut io) = conn(
        crate::handler(move |_r, o| {
            o.text(200, &big);
        }),
        Profile::new(ProfileId(0)),
    );
    c.on_open(&mut io, false);
    io.budget = Some(1000);
    let (_, step) = c.on_data(&mut io, GET);
    assert_eq!(step, Step::Write);
    assert_eq!(io.phase, Phase::Sending);
    let mut rounds = 0;
    loop {
        io.budget = Some(1000);
        match c.on_writable(&mut io) {
            Step::Write => rounds += 1,
            Step::Read => break,
            other => panic!("{other:?}"),
        }
        assert!(rounds < 50);
    }
    assert_eq!(replies(&io.written)[0].body.len(), 10_000);
}

#[test]
fn test_split_at_every_byte_same_reply() {
    let input = b"POST /p?q=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody";
    let whole = {
        let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
        c.on_open(&mut io, false);
        let _ = c.on_data(&mut io, input);
        replies(&io.written)[0].body.clone()
    };
    for cut in 1..input.len() {
        let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
        c.on_open(&mut io, false);
        let (n, _) = c.on_data(&mut io, &input[..cut]);
        assert_eq!(n, cut);
        let _ = c.on_data(&mut io, &input[cut..]);
        assert_eq!(replies(&io.written)[0].body, whole, "cut at {cut}");
    }
}

#[test]
fn test_capacity_refusal_without_read() {
    // T-5: the busy refusal is written at open, before anything is read.
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    assert_eq!(c.on_open(&mut io, true), Step::Close);
    let text = String::from_utf8_lossy(&io.written).into_owned();
    assert!(text.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(text.contains("retry-after: 1"));
}

#[test]
fn test_head_request_has_no_body() {
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(&mut io, b"HEAD /abc HTTP/1.1\r\nHost: x\r\n\r\n");
    let text = String::from_utf8_lossy(&io.written).into_owned();
    assert!(text.contains("content-length: 4"));
    assert!(text.ends_with("\r\n\r\n"));
}

#[test]
fn test_wipe_buffers_pool_holds_only_zeroes() {
    // T-36: after a request, the reply and body buffers hold no request bytes.
    let (mut c, mut io) = conn(Counting::default(), Profile::new(ProfileId(0)));
    c.on_open(&mut io, false);
    let _ = c.on_data(
        &mut io,
        b"POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\nsecret",
    );
    assert!(c.body.is_empty());
    assert!(c.out.is_empty());
}

#[test]
fn test_forwarded_client_reaches_service() {
    let svc = crate::handler(|r, o| {
        o.text(200, &format!("{:?}", r.client().addr()));
    });
    let proxy = crate::ProxySource::forwarded_for(crate::TrustedProxies::loopback());
    let reply =
        TestRequest::new(b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n")
            .behind(proxy.clone())
            .send(&svc);
    assert_eq!(reply.text(), "Some(203.0.113.9)");
    // A trusted proxy that sends no header: refused (fail closed).
    let missing = TestRequest::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .behind(proxy.clone())
        .send(&svc);
    assert_eq!(missing.status, 400);
    // From an untrusted peer the header is ignored.
    let spoof = TestRequest::new(b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n")
        .client("198.51.100.2:9".parse().unwrap())
        .behind(proxy)
        .send(&svc);
    assert_eq!(spoof.text(), "Some(198.51.100.2)");
}

#[test]
fn test_reply_with_crlf_in_value_becomes_500() {
    let svc = crate::handler(|_r, o| {
        o.header("x-a", "1\r\nset-cookie: x").text(200, "nope");
    });
    let reply = crate::testing::respond(&svc, GET);
    assert_eq!(reply.status, 500);
    assert!(reply.header("set-cookie").is_none());
}

mod props {
    use super::*;
    use proptest::prelude::*;

    fn request() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec()),
            Just(b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc".to_vec()),
            Just(b"POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec()),
            Just(b"PUT /e HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\nz".to_vec()),
            Just(b"GET /x HTTP/1.0\r\n\r\n".to_vec()),
            Just(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec()),
            Just(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n".to_vec()),
            proptest::collection::vec(any::<u8>(), 0..64),
        ]
    }

    struct S(Arc<Counting>);
    impl HttpService for S {
        fn head(&self, h: &HttpHead<'_>, e: &mut Envelope) -> HeadAction {
            HttpService::head(&*self.0, h, e)
        }
        fn call(&self, r: &HttpRequest<'_>, e: &Envelope, o: &mut HttpReply) -> Outcome {
            HttpService::call(&*self.0, r, e, o)
        }
        fn done(&self, e: &Envelope, f: &Finished) {
            HttpService::done(&*self.0, e, f);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Invariants 1 and 6 under arbitrary input split at arbitrary points
        /// and a small output budget: no panic, `done` once per `head`, no
        /// more replies than requests that reached `head` plus one refusal.
        #[test]
        fn test_machine_invariants_hold_for_any_input(
            reqs in proptest::collection::vec(request(), 1..6),
            cuts in proptest::collection::vec(1usize..40, 1..20),
            budget in proptest::option::of(1usize..300),
        ) {
            let svc = Arc::new(Counting::default());
            let (mut c, mut io) = conn(S(svc.clone()), Profile::new(ProfileId(0)));
            let input: Vec<u8> = reqs.concat();
            let mut step = c.on_open(&mut io, false);
            let mut at = 0;
            let mut cut = cuts.iter().copied().cycle();
            let mut eof = false;
            let mut guard = 0;
            while !matches!(step, Step::Close | Step::Abort) && guard < 10_000 {
                guard += 1;
                io.budget = budget;
                step = match step {
                    Step::Write => c.on_writable(&mut io),
                    Step::Park { .. } => c.on_timeout(&mut io, Timeout::Park),
                    Step::Read if at < input.len() => {
                        let end = (at + cut.next().unwrap_or(1)).min(input.len());
                        let (n, next) = c.on_data(&mut io, &input[at..end]);
                        prop_assert!(n <= end - at);
                        at += n;
                        next
                    }
                    Step::Read if !eof => {
                        eof = true;
                        c.on_peer_closed(&mut io)
                    }
                    Step::Read => c.on_timeout(&mut io, Timeout::Exchange),
                    other => other,
                };
            }
            prop_assert!(guard < 10_000, "the machine did not finish");
            c.on_close(crate::net::CloseReason::PeerClosed);
            let heads = svc.heads.load(Ordering::Relaxed);
            let calls = svc.calls.load(Ordering::Relaxed);
            let dones = svc.dones.load(Ordering::Relaxed);
            prop_assert_eq!(heads, dones, "done exactly once per head");
            prop_assert!(calls <= heads);
            let replies = String::from_utf8_lossy(&io.written).matches("HTTP/1.1 ").count() as u32;
            prop_assert!(replies <= heads * 2 + 1, "{} replies for {} heads", replies, heads);
        }
    }
}
