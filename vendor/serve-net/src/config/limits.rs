//! serve-net's budgets: request deadlines, sizes, caps, and keep-alive.

use std::time::Duration;

/// serve-net's budgets.
///
/// The request-level values serve-net enforces itself, and the transport
/// values it sets on net-io for each listener. Ranges are checked by
/// `ServerBuilder::build`.
///
/// ```
/// use serve_net::Limits;
/// use std::time::Duration;
///
/// let strict = Limits::new()
///     .head_timeout(Duration::from_secs(5))
///     .request_timeout(Duration::from_secs(15))
///     .max_body(64 * 1024)
///     .max_connections(2_000);
/// assert_ne!(strict, Limits::new());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub(crate) head_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) reply_timeout: Duration,
    pub(crate) write_stall: Duration,
    pub(crate) min_rate_bytes: u32,
    pub(crate) min_rate_window: Duration,
    pub(crate) max_body: u64,
    pub(crate) max_pipelined_per_wake: u16,
    pub(crate) max_pending_output: u32,
    pub(crate) max_deferred_per_worker: u32,
    pub(crate) max_connections: Option<u32>,
    pub(crate) hard_cap_headroom: Option<u32>,
    pub(crate) linger_total: Duration,
    pub(crate) linger_bytes: u32,
    #[cfg(feature = "http1")]
    pub(crate) engine: http_net::Limits,
}

/// Ranges the builder enforces (rule `DeadlineRange`).
pub(crate) mod range {
    use std::time::Duration;
    pub(crate) const HEAD_MIN: Duration = Duration::from_millis(100);
    pub(crate) const HEAD_MAX: Duration = Duration::from_secs(300);
    pub(crate) const REQUEST_MAX: Duration = Duration::from_secs(3600);
    pub(crate) const REPLY_MIN: Duration = Duration::from_millis(1);
    pub(crate) const REPLY_MAX: Duration = Duration::from_secs(3600);
    pub(crate) const STALL_MIN: Duration = Duration::from_millis(100);
    pub(crate) const STALL_MAX: Duration = Duration::from_secs(3600);
    pub(crate) const PENDING_MIN: u32 = 4 * 1024;
    pub(crate) const PENDING_MAX: u32 = 64 * 1024 * 1024;
    pub(crate) const PIPELINED_MAX: u16 = 1024;
    pub(crate) const LINGER_MAX: Duration = Duration::from_secs(60);
}

impl Limits {
    /// The defaults.
    #[must_use]
    pub const fn new() -> Self {
        Limits {
            head_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            reply_timeout: Duration::from_secs(30),
            write_stall: Duration::from_secs(30),
            min_rate_bytes: 256,
            min_rate_window: Duration::from_secs(10),
            max_body: 1024 * 1024,
            max_pipelined_per_wake: 16,
            max_pending_output: 256 * 1024,
            max_deferred_per_worker: 4096,
            max_connections: None,
            hard_cap_headroom: None,
            linger_total: Duration::from_secs(2),
            linger_bytes: 64 * 1024,
            #[cfg(feature = "http1")]
            engine: http_net::Limits::new(),
        }
    }

    /// From accept (first request) or the first byte (later requests) to a
    /// complete head. Default 10 s; 100 ms to 300 s.
    #[must_use]
    pub const fn head_timeout(mut self, d: Duration) -> Self {
        self.head_timeout = d;
        self
    }

    /// From the first head byte to the end of the body. Default 30 s; at least
    /// `head_timeout`, at most 1 h.
    #[must_use]
    pub const fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// How long a deferred reply may take. Default 30 s.
    #[must_use]
    pub const fn reply_timeout(mut self, d: Duration) -> Self {
        self.reply_timeout = d;
        self
    }

    /// Output that makes no progress for this long closes the connection.
    /// Default 30 s.
    #[must_use]
    pub const fn write_stall(mut self, d: Duration) -> Self {
        self.write_stall = d;
        self
    }

    /// The minimum transfer rate while receiving or sending. Default 256 B/s
    /// over 10 s; 0 turns it off (a warning).
    #[must_use]
    pub const fn min_rate(mut self, bytes_per_sec: u32, window: Duration) -> Self {
        self.min_rate_bytes = bytes_per_sec;
        self.min_rate_window = window;
        self
    }

    /// The largest request body. Default 1 MiB.
    #[must_use]
    pub const fn max_body(mut self, bytes: u64) -> Self {
        self.max_body = bytes;
        self
    }

    /// Requests processed per input event on one connection. Default 16.
    #[must_use]
    pub const fn max_pipelined_per_wake(mut self, n: u16) -> Self {
        self.max_pipelined_per_wake = n;
        self
    }

    /// Output queued per connection before input processing stops. Default 256 KiB.
    #[must_use]
    pub const fn max_pending_output(mut self, bytes: u32) -> Self {
        self.max_pending_output = bytes;
        self
    }

    /// Requests parked for a deferred reply per worker. Default 4,096.
    #[must_use]
    pub const fn max_deferred_per_worker(mut self, n: u32) -> Self {
        self.max_deferred_per_worker = n;
        self
    }

    /// The server-wide soft connection cap. Default: the blocking worker count,
    /// or 10,000 on the reactor.
    #[must_use]
    pub const fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = Some(n);
        self
    }

    /// How far net-io's hard cap sits above the soft cap. Default one eighth
    /// of the soft cap, at least 16.
    #[must_use]
    pub const fn hard_cap_headroom(mut self, n: u32) -> Self {
        self.hard_cap_headroom = Some(n);
        self
    }

    /// The bound on reading and dropping unread input after a closing reply.
    /// Default 2 s and 64 KiB.
    #[must_use]
    pub const fn linger(mut self, total: Duration, bytes: u32) -> Self {
        self.linger_total = total;
        self.linger_bytes = bytes;
        self
    }

    /// The HTTP/1.1 engine's own budgets (start line, header bytes and count,
    /// field line, trailers).
    #[cfg(feature = "http1")]
    #[must_use]
    pub const fn engine_limits(mut self, limits: http_net::Limits) -> Self {
        self.engine = limits;
        self
    }

    /// The headroom of net-io's hard cap above `soft`.
    #[must_use]
    pub(crate) fn headroom_for(&self, soft: u32) -> u32 {
        match self.hard_cap_headroom {
            Some(n) => n,
            None => (soft / 8).max(16),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::new()
    }
}

/// How long a connection stays open between requests.
///
/// ```
/// use serve_net::KeepAlive;
/// use std::time::Duration;
///
/// // Behind Apache with ProxyPass ttl=50: keep the backend longer than the front end.
/// let behind_apache = KeepAlive::new().idle(Duration::from_secs(75));
/// let api = KeepAlive::new().max_requests(10_000).max_age(Duration::from_secs(600));
/// assert_ne!(behind_apache, api);
/// assert_ne!(KeepAlive::off(), KeepAlive::new());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepAlive {
    pub(crate) on: bool,
    pub(crate) idle: Option<Duration>,
    pub(crate) max_requests: u32,
    pub(crate) max_age: Duration,
    pub(crate) under_pressure: Duration,
}

/// The default idle timeout on direct listeners.
pub(crate) const IDLE_DIRECT: Duration = Duration::from_secs(20);
/// The default idle timeout behind a front end.
pub(crate) const IDLE_BEHIND_PROXY: Duration = Duration::from_secs(60);

impl KeepAlive {
    /// The defaults: idle by ingress (20 s direct, 60 s behind a front end),
    /// 1,000 requests, 1 h, 2 s under pressure.
    #[must_use]
    pub const fn new() -> Self {
        KeepAlive {
            on: true,
            idle: None,
            max_requests: 1000,
            max_age: Duration::from_secs(3600),
            under_pressure: Duration::from_secs(2),
        }
    }

    /// One request per connection.
    #[must_use]
    pub const fn off() -> Self {
        let mut k = KeepAlive::new();
        k.on = false;
        k
    }

    /// The idle timeout between requests.
    #[must_use]
    pub const fn idle(mut self, d: Duration) -> Self {
        self.idle = Some(d);
        self
    }

    /// Requests per connection; the last response carries the close signal.
    #[must_use]
    pub const fn max_requests(mut self, n: u32) -> Self {
        self.max_requests = n;
        self
    }

    /// The age after which the next response carries the close signal.
    #[must_use]
    pub const fn max_age(mut self, d: Duration) -> Self {
        self.max_age = d;
        self
    }

    /// The idle timeout under pressure (blocking driver); `Duration::ZERO`
    /// turns adaptation off.
    #[must_use]
    pub const fn under_pressure(mut self, idle: Duration) -> Self {
        self.under_pressure = idle;
        self
    }

    pub(crate) fn idle_for(&self, behind_front_end: bool) -> Duration {
        match self.idle {
            Some(d) => d,
            None if behind_front_end => IDLE_BEHIND_PROXY,
            None => IDLE_DIRECT,
        }
    }
}

impl Default for KeepAlive {
    fn default() -> Self {
        KeepAlive::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_defaults_match_docs() {
        let l = Limits::new();
        assert_eq!(l.head_timeout, Duration::from_secs(10));
        assert_eq!(l.request_timeout, Duration::from_secs(30));
        assert_eq!(l.max_body, 1 << 20);
        assert_eq!(l.max_pending_output, 256 * 1024);
        assert_eq!(l.max_pipelined_per_wake, 16);
        assert_eq!(l, Limits::default());
    }

    #[test]
    fn test_headroom_default_and_floor() {
        let l = Limits::new();
        assert_eq!(l.headroom_for(80), 16);
        assert_eq!(l.headroom_for(10_000), 1250);
        assert_eq!(l.hard_cap_headroom(3).headroom_for(10_000), 3);
    }

    #[test]
    fn test_keep_alive_idle_by_ingress() {
        let k = KeepAlive::new();
        assert_eq!(k.idle_for(false), Duration::from_secs(20));
        assert_eq!(k.idle_for(true), Duration::from_secs(60));
        assert_eq!(
            k.idle(Duration::from_secs(5)).idle_for(true),
            Duration::from_secs(5)
        );
        assert!(!KeepAlive::off().on);
    }
}
