//! The rules `build` and `reload` run (dev/PLAN.md section 9.3).
//!
//! Each rule is one function that pushes errors or warnings; `check` runs
//! them all and never stops at the first failure.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::config::{
    ForwardedSource, Ingress, KeepAlive, Limits, ListenerSource, ListenerSpec, Profile, ProfileId,
    ProxyKind, Workers, range,
};
use crate::error::{ConfigError, ConfigWarning, RuleId, Subject};
use crate::net::DriverKind;

/// The configuration being checked.
pub(crate) struct Draft<'a> {
    pub(crate) listeners: &'a [ListenerSpec],
    pub(crate) profiles: &'a [Profile],
    pub(crate) limits: &'a Limits,
    pub(crate) keep_alive: &'a KeepAlive,
    pub(crate) workers: &'a Workers,
    pub(crate) drain_deadline: Duration,
    /// Whether the owner gave a control line (lockdown can happen).
    pub(crate) has_control: bool,
}

/// Errors and warnings found.
#[derive(Default)]
pub(crate) struct Findings {
    pub(crate) errors: Vec<ConfigError>,
    pub(crate) warnings: Vec<ConfigWarning>,
}

impl Findings {
    fn error(&mut self, rule: RuleId, subject: Subject, message: &'static str, hint: &'static str) {
        self.errors
            .push(ConfigError::new(rule, subject, message, hint));
    }
    fn warn(&mut self, rule: RuleId, subject: Subject, message: &'static str) {
        self.warnings
            .push(ConfigWarning::new(rule, subject, message));
    }
}

/// The most listeners and profiles a server holds.
pub(crate) const MAX_LISTENERS: usize = 64;
pub(crate) const MAX_PROFILES: usize = 255;

/// Runs every rule.
pub(crate) fn check(d: &Draft<'_>) -> Findings {
    let mut f = Findings::default();
    counts(d, &mut f);
    names(d, &mut f);
    binds(d, &mut f);
    profiles(d, &mut f);
    for l in d.listeners {
        public_bind(l, &mut f);
        trust(l, &mut f);
        scheme_warning(l, &mut f);
        ingress_needs_http(l, d.profiles, &mut f);
    }
    limits(Subject::Server, d.limits, &mut f);
    for p in d.profiles {
        if let Some(l) = &p.limits {
            limits(Subject::Profile(p.id), l, &mut f);
        }
        caps(
            Subject::Profile(p.id),
            p.budget.max_connections,
            p.budget.max_in_flight,
            &mut f,
        );
        if let Some(k) = &p.keep_alive {
            keep_alive(Subject::Profile(p.id), k, &mut f);
        }
    }
    keep_alive(Subject::Server, d.keep_alive, &mut f);
    short_idle_behind_proxy(d, &mut f);
    workers(d.workers, &mut f);
    drain(d.drain_deadline, &mut f);
    lockdown(d, &mut f);
    f
}

fn counts(d: &Draft<'_>, f: &mut Findings) {
    if d.listeners.len() > MAX_LISTENERS {
        f.error(
            RuleId::TooMany,
            Subject::Server,
            "more than 64 listeners",
            "split the listeners across servers",
        );
    }
    if d.profiles.len() > MAX_PROFILES {
        f.error(
            RuleId::TooMany,
            Subject::Server,
            "more than 255 profiles",
            "merge profiles that share their settings",
        );
    }
    if d.listeners.is_empty() {
        f.warn(
            RuleId::NoListeners,
            Subject::Server,
            "no listener: the server accepts nothing",
        );
    }
}

/// `[a-z0-9._-]`, 1 to 64 bytes.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
}

fn names(d: &Draft<'_>, f: &mut Findings) {
    let mut seen = HashSet::new();
    for l in d.listeners {
        let subject = Subject::Listener(l.name.clone());
        if !valid_name(&l.name) {
            f.error(
                RuleId::BadName,
                subject.clone(),
                "the name is not 1 to 64 bytes of a-z, 0-9, '.', '_', '-'",
                "rename the listener, for example \"web\" or \"admin-1\"",
            );
        }
        if !seen.insert(l.name.as_str()) {
            f.error(
                RuleId::DuplicateName,
                subject,
                "two listeners have this name",
                "give every listener its own name",
            );
        }
    }
}

fn binds(d: &Draft<'_>, f: &mut Findings) {
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    for l in d.listeners {
        let subject = Subject::Listener(l.name.clone());
        match l.source {
            ListenerSource::Unresolved => {
                f.error(
                    RuleId::AddressResolve,
                    subject,
                    "the address resolved to nothing",
                    "give an address such as 127.0.0.1:8080 or a host name that resolves",
                );
            }
            ListenerSource::Tcp(addr) => {
                // Port 0 picks a free port each time, so two port-0 listeners never collide.
                if addr.port() != 0 && !seen.insert(addr) {
                    f.error(
                        RuleId::DuplicateBind,
                        subject,
                        "another listener binds the same address",
                        "remove one listener or change its port",
                    );
                }
            }
        }
        if let Some(b) = l.backlog {
            if b == 0 || b > 65_535 {
                f.error(
                    RuleId::DeadlineRange,
                    Subject::Listener(l.name.clone()),
                    "the backlog is outside 1 to 65,535",
                    "use a backlog between 1 and 65,535 (default 1,024)",
                );
            }
        }
        if l.max_connections == Some(0) {
            f.error(
                RuleId::ZeroCap,
                Subject::Listener(l.name.clone()),
                "the connection cap is 0",
                "set max_connections to 1 or more, or leave it unset",
            );
        }
    }
}

fn profiles(d: &Draft<'_>, f: &mut Findings) {
    let mut ids: Vec<u8> = d.profiles.iter().map(|p| p.id.0).collect();
    for p in d.profiles {
        if p.id == ProfileId::MAX {
            f.error(
                RuleId::ProfileIdReserved,
                Subject::Profile(p.id),
                "profile id 255 is reserved",
                "number profiles from 0",
            );
        }
    }
    ids.sort_unstable();
    let dense = ids.iter().enumerate().all(|(i, &id)| usize::from(id) == i);
    if !dense {
        f.error(
            RuleId::ProfileGap,
            Subject::Server,
            "profile ids are not dense from 0 or repeat",
            "number profiles 0, 1, 2, ... with no gap and no repeat",
        );
    }
    // Profile 0 is created with defaults when none is given, so an empty list is fine.
    let known = |id: ProfileId| {
        (d.profiles.is_empty() && id == ProfileId(0)) || d.profiles.iter().any(|p| p.id == id)
    };
    for l in d.listeners {
        if !known(l.profile) {
            f.error(
                RuleId::UnknownProfile,
                Subject::Listener(l.name.clone()),
                "the listener names a profile that does not exist",
                "add the profile, or point the listener at an existing one",
            );
        }
    }
}

/// Loopback, private, unique local, or link-local: reachable only from the
/// host or its own network.
pub(crate) fn is_local_or_private(ip: IpAddr) -> bool {
    match crate::net::normalize(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            v6.is_loopback() || (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
    }
}

fn public_bind(l: &ListenerSpec, f: &mut Findings) {
    if !matches!(l.ingress, Ingress::Proxy(_)) || l.public_bind.is_some() {
        return;
    }
    if let ListenerSource::Tcp(addr) = l.source {
        if addr.ip().is_unspecified() || !is_local_or_private(addr.ip()) {
            f.error(
                RuleId::PublicBind,
                Subject::Listener(l.name.clone()),
                "a listener that trusts a front end is bound to a public or unspecified address, so anyone who reaches it can forge client facts",
                "bind 127.0.0.1, a private address, or a Unix socket, or call allow_public_bind with the reason",
            );
        }
    }
}

fn trust(l: &ListenerSpec, f: &mut Findings) {
    let Some(p) = l.ingress.proxy() else { return };
    let subject = || Subject::Listener(l.name.clone());
    if p.trusted.is_empty() {
        f.error(
            RuleId::TrustEmpty,
            subject(),
            "a proxy listener trusts no proxy",
            "list the proxies' addresses, for example TrustedProxies::loopback()",
        );
    }
    for block in p.trusted.iter() {
        let prefix = block.prefix_len();
        if prefix == 0 {
            f.error(
                RuleId::TrustWildcard,
                subject(),
                "a trust entry covers every address",
                "list the proxies' own addresses or subnets",
            );
        } else if l.broad_trust.is_none()
            && ((block.is_ipv4() && prefix < 8) || (!block.is_ipv4() && prefix < 32))
        {
            f.error(
                RuleId::TrustTooBroad,
                subject(),
                "a trust entry is broader than /8 (IPv4) or /32 (IPv6)",
                "narrow the entry, or call allow_broad_trust with the reason",
            );
        }
    }
    if p.max_hops == 0 || p.max_hops > 64 {
        f.error(
            RuleId::DeadlineRange,
            subject(),
            "max_hops is outside 1 to 64",
            "use max_hops between 1 and 64 (default 16)",
        );
    }
    if let ProxyKind::Headers(ForwardedSource::SingleAddress(name)) = p.kind {
        let token = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !token {
            f.error(
                RuleId::BadHeaderName,
                subject(),
                "the single-address field name is not a valid field name",
                "use a field name such as \"x-real-ip\"",
            );
        }
    }
}

fn scheme_warning(l: &ListenerSpec, f: &mut Findings) {
    if let Some(p) = l.ingress.proxy() {
        if l.scheme == crate::client::Scheme::Http && !p.trust_scheme {
            f.warn(RuleId::DeclaredSchemeHttp, Subject::Listener(l.name.clone()), "every request is reported as http; if the front end terminates TLS, declare Scheme::Https or turn on trust_scheme");
        }
    }
}

fn ingress_needs_http(l: &ListenerSpec, profiles: &[Profile], f: &mut Findings) {
    if l.ingress
        .proxy()
        .is_some_and(|p| matches!(p.kind, ProxyKind::Headers(_)))
    {
        let custom = profiles
            .iter()
            .find(|p| p.id == l.profile)
            .is_some_and(|p| matches!(p.engine, crate::config::EngineChoice::Custom { .. }));
        if custom {
            f.error(
                RuleId::IngressNeedsHttp,
                Subject::Listener(l.name.clone()),
                "forwarded headers need the HTTP family, but the profile serves a custom engine",
                "use direct or PROXY protocol ingress for custom engines",
            );
        }
    }
}

fn caps(subject: Subject, connections: Option<u32>, in_flight: Option<u32>, f: &mut Findings) {
    if connections == Some(0) || in_flight == Some(0) {
        f.error(
            RuleId::ZeroCap,
            subject,
            "a connection or in-flight cap is 0",
            "set the cap to 1 or more, or leave it unset",
        );
    }
}

fn limits(subject: Subject, l: &Limits, f: &mut Findings) {
    let out = |f: &mut Findings, message: &'static str, hint: &'static str| {
        f.error(RuleId::DeadlineRange, subject.clone(), message, hint)
    };
    if l.head_timeout < range::HEAD_MIN || l.head_timeout > range::HEAD_MAX {
        out(
            f,
            "head_timeout is outside 100 ms to 300 s",
            "use a head_timeout between 100 ms and 300 s (default 10 s)",
        );
    }
    if l.request_timeout > range::REQUEST_MAX {
        out(
            f,
            "request_timeout is above 1 h",
            "use a request_timeout of at most 1 h (default 30 s)",
        );
    }
    if l.request_timeout < l.head_timeout {
        f.error(
            RuleId::DeadlineOrder,
            subject.clone(),
            "request_timeout is shorter than head_timeout",
            "raise request_timeout to at least head_timeout",
        );
    }
    if l.reply_timeout < range::REPLY_MIN || l.reply_timeout > range::REPLY_MAX {
        out(
            f,
            "reply_timeout is outside 1 ms to 1 h",
            "use a reply_timeout between 1 ms and 1 h (default 30 s)",
        );
    }
    if l.write_stall < range::STALL_MIN || l.write_stall > range::STALL_MAX {
        out(
            f,
            "write_stall is outside 100 ms to 1 h",
            "use a write_stall between 100 ms and 1 h (default 30 s)",
        );
    }
    if l.max_pending_output < range::PENDING_MIN || l.max_pending_output > range::PENDING_MAX {
        out(
            f,
            "max_pending_output is outside 4 KiB to 64 MiB",
            "use a max_pending_output between 4 KiB and 64 MiB (default 256 KiB)",
        );
    }
    if l.max_pipelined_per_wake == 0 || l.max_pipelined_per_wake > range::PIPELINED_MAX {
        out(
            f,
            "max_pipelined_per_wake is outside 1 to 1,024",
            "use a value between 1 and 1,024 (default 16)",
        );
    }
    if l.linger_total > range::LINGER_MAX {
        out(
            f,
            "linger is above 60 s",
            "use a linger of at most 60 s (default 2 s)",
        );
    }
    if l.min_rate_bytes > 0 && l.min_rate_window.is_zero() {
        out(
            f,
            "min_rate has a zero window",
            "use a window of at least 1 s (default 10 s)",
        );
    }
    if l.min_rate_bytes == 0 {
        f.warn(
            RuleId::MinRateOff,
            subject.clone(),
            "the minimum transfer rate is off: a trickling peer is held only by the deadlines",
        );
    }
    if l.max_connections == Some(0) || l.max_deferred_per_worker == 0 {
        f.error(
            RuleId::ZeroCap,
            subject.clone(),
            "a connection or deferral cap is 0",
            "set the cap to 1 or more",
        );
    }
}

fn keep_alive(subject: Subject, k: &KeepAlive, f: &mut Findings) {
    if !k.on {
        return;
    }
    if k.idle == Some(Duration::ZERO) {
        f.error(
            RuleId::DeadlineOrder,
            subject.clone(),
            "keep-alive is on with an idle timeout of 0",
            "set an idle timeout, or use KeepAlive::off()",
        );
    }
    if k.max_requests == 0 {
        f.error(
            RuleId::ZeroCap,
            subject.clone(),
            "keep-alive allows 0 requests per connection",
            "set max_requests to 1 or more, or use KeepAlive::off()",
        );
    }
    if k.max_age.is_zero() {
        f.error(
            RuleId::DeadlineRange,
            subject,
            "keep-alive max_age is 0",
            "set max_age to 1 s or more (default 1 h)",
        );
    }
}

fn short_idle_behind_proxy(d: &Draft<'_>, f: &mut Findings) {
    for l in d.listeners {
        if l.ingress.proxy().is_none() {
            continue;
        }
        let k = d
            .profiles
            .iter()
            .find(|p| p.id == l.profile)
            .and_then(|p| p.keep_alive)
            .unwrap_or(*d.keep_alive);
        if k.on && k.idle_for(true) < Duration::from_secs(5) {
            f.warn(RuleId::ShortIdleBehindProxy, Subject::Listener(l.name.clone()), "keep-alive idle under 5 s behind a proxy: the front end may reuse a connection this server is closing and answer 502");
        }
    }
}

fn workers(w: &Workers, f: &mut Findings) {
    match w.kind {
        DriverKind::Blocking | DriverKind::Auto => {}
        _ => f.error(
            RuleId::DriverUnavailable,
            Subject::Server,
            "this build has only the blocking driver",
            "use Workers::blocking or Workers::auto",
        ),
    }
    if w.count == Some(0) || w.count.is_some_and(|n| n > 4096) {
        f.error(
            RuleId::DeadlineRange,
            Subject::Server,
            "the worker count is outside 1 to 4,096",
            "use between 1 and 4,096 workers",
        );
    }
}

fn drain(deadline: Duration, f: &mut Findings) {
    if deadline.is_zero() || deadline > Duration::from_secs(3600) {
        f.error(
            RuleId::DrainRange,
            Subject::Server,
            "the drain deadline is 0 or above 1 h",
            "use a drain deadline between 1 ms and 1 h (default 30 s)",
        );
    }
}

fn lockdown(d: &Draft<'_>, f: &mut Findings) {
    if d.has_control && !d.profiles.iter().any(|p| p.critical) {
        f.warn(
            RuleId::LockdownWithoutCritical,
            Subject::Server,
            "no profile is critical: under lockdown every request is refused",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxySource;
    use crate::net::TrustedProxies;

    fn run(listeners: &[ListenerSpec], profiles: &[Profile]) -> Findings {
        check(&Draft {
            listeners,
            profiles,
            limits: &Limits::new(),
            keep_alive: &KeepAlive::new(),
            workers: &Workers::auto(),
            drain_deadline: Duration::from_secs(30),
            has_control: false,
        })
    }

    fn rules(f: &Findings) -> Vec<RuleId> {
        f.errors.iter().map(|e| e.rule).collect()
    }

    fn proxy(name: &str, addr: &str, trusted: &str) -> ListenerSpec {
        ListenerSpec::tcp(name, addr).ingress(Ingress::Proxy(ProxySource::forwarded_for(
            TrustedProxies::parse(trusted).unwrap(),
        )))
    }

    #[test]
    fn test_build_valid_default_config_passes() {
        let f = run(&[ListenerSpec::tcp("web", "127.0.0.1:8080")], &[]);
        assert!(f.errors.is_empty(), "{:?}", rules(&f));
    }

    #[test]
    fn test_build_proxy_listener_public_bind_refused() {
        let f = run(&[proxy("site", "0.0.0.0:8080", "127.0.0.1")], &[]);
        assert!(rules(&f).contains(&RuleId::PublicBind));
        let f = run(&[proxy("site", "203.0.113.5:8080", "127.0.0.1")], &[]);
        assert!(rules(&f).contains(&RuleId::PublicBind));
        for ok in [
            "127.0.0.1:8080",
            "10.1.2.3:8080",
            "192.168.1.1:8080",
            "[::1]:8080",
            "[fd00::1]:8080",
        ] {
            let f = run(&[proxy("site", ok, "127.0.0.1")], &[]);
            assert!(!rules(&f).contains(&RuleId::PublicBind), "{ok}");
        }
        let f = run(
            &[proxy("site", "0.0.0.0:8080", "10.0.0.0/8").allow_public_bind("firewalled subnet")],
            &[],
        );
        assert!(!rules(&f).contains(&RuleId::PublicBind));
    }

    #[test]
    fn test_build_direct_public_bind_allowed() {
        let f = run(&[ListenerSpec::tcp("web", "0.0.0.0:8080")], &[]);
        assert!(f.errors.is_empty());
    }

    #[test]
    fn test_build_trust_rules() {
        assert!(
            rules(&run(&[proxy("a", "127.0.0.1:1", "0.0.0.0/0")], &[]))
                .contains(&RuleId::TrustWildcard)
        );
        assert!(
            rules(&run(&[proxy("a", "127.0.0.1:1", "10.0.0.0/7")], &[]))
                .contains(&RuleId::TrustTooBroad)
        );
        assert!(
            !rules(&run(&[proxy("a", "127.0.0.1:1", "10.0.0.0/8")], &[]))
                .contains(&RuleId::TrustTooBroad)
        );
        assert!(
            rules(&run(&[proxy("a", "127.0.0.1:1", "2001::/31")], &[]))
                .contains(&RuleId::TrustTooBroad)
        );
        let broad = proxy("a", "127.0.0.1:1", "10.0.0.0/7").allow_broad_trust("provider range");
        assert!(!rules(&run(&[broad], &[])).contains(&RuleId::TrustTooBroad));
        let wild = proxy("a", "127.0.0.1:1", "0.0.0.0/0").allow_broad_trust("x");
        assert!(rules(&run(&[wild], &[])).contains(&RuleId::TrustWildcard));
        let empty = ListenerSpec::tcp("a", "127.0.0.1:1").ingress(Ingress::Proxy(
            ProxySource::forwarded_for(TrustedProxies::none()),
        ));
        assert!(rules(&run(&[empty], &[])).contains(&RuleId::TrustEmpty));
    }

    #[test]
    fn test_build_names() {
        for bad in ["", "Web", "a b", "\u{e9}", &"a".repeat(65)] {
            assert!(
                rules(&run(&[ListenerSpec::tcp(bad, "127.0.0.1:1")], &[]))
                    .contains(&RuleId::BadName),
                "{bad:?}"
            );
        }
        for good in ["a", "web-1", "x.y_z", &"a".repeat(64)] {
            assert!(
                !rules(&run(&[ListenerSpec::tcp(good, "127.0.0.1:1")], &[]))
                    .contains(&RuleId::BadName),
                "{good:?}"
            );
        }
        let f = run(
            &[
                ListenerSpec::tcp("a", "127.0.0.1:1"),
                ListenerSpec::tcp("a", "127.0.0.1:2"),
            ],
            &[],
        );
        assert!(rules(&f).contains(&RuleId::DuplicateName));
    }

    #[test]
    fn test_build_duplicate_bind_and_resolve() {
        let f = run(
            &[
                ListenerSpec::tcp("a", "127.0.0.1:9"),
                ListenerSpec::tcp("b", "127.0.0.1:9"),
            ],
            &[],
        );
        assert!(rules(&f).contains(&RuleId::DuplicateBind));
        let f = run(
            &[
                ListenerSpec::tcp("a", "127.0.0.1:0"),
                ListenerSpec::tcp("b", "127.0.0.1:0"),
            ],
            &[],
        );
        assert!(!rules(&f).contains(&RuleId::DuplicateBind));
        assert!(
            rules(&run(&[ListenerSpec::tcp("a", "nope")], &[])).contains(&RuleId::AddressResolve)
        );
    }

    #[test]
    fn test_build_profile_rules() {
        let f = run(
            &[],
            &[Profile::new(ProfileId(0)), Profile::new(ProfileId(2))],
        );
        assert!(rules(&f).contains(&RuleId::ProfileGap));
        let f = run(
            &[],
            &[Profile::new(ProfileId(0)), Profile::new(ProfileId(0))],
        );
        assert!(rules(&f).contains(&RuleId::ProfileGap));
        let f = run(&[], &[Profile::new(ProfileId::MAX)]);
        assert!(rules(&f).contains(&RuleId::ProfileIdReserved));
        let f = run(
            &[ListenerSpec::tcp("a", "127.0.0.1:1").profile(ProfileId(3))],
            &[Profile::new(ProfileId(0))],
        );
        assert!(rules(&f).contains(&RuleId::UnknownProfile));
        assert!(
            rules(&run(
                &[ListenerSpec::tcp("a", "127.0.0.1:1").profile(ProfileId(1))],
                &[]
            ))
            .contains(&RuleId::UnknownProfile)
        );
    }

    #[test]
    fn test_build_deadline_rules() {
        let d = |l: Limits| {
            check(&Draft {
                listeners: &[],
                profiles: &[],
                limits: &l,
                keep_alive: &KeepAlive::new(),
                workers: &Workers::auto(),
                drain_deadline: Duration::from_secs(30),
                has_control: false,
            })
        };
        let f = d(Limits::new()
            .head_timeout(Duration::from_secs(60))
            .request_timeout(Duration::from_secs(30)));
        assert!(rules(&f).contains(&RuleId::DeadlineOrder));
        let f = d(Limits::new().head_timeout(Duration::from_millis(99)));
        assert!(rules(&f).contains(&RuleId::DeadlineRange));
        let f = d(Limits::new()
            .head_timeout(Duration::from_millis(100))
            .request_timeout(Duration::from_millis(100)));
        assert!(f.errors.is_empty(), "{:?}", rules(&f));
        let f = d(Limits::new().max_connections(0));
        assert!(rules(&f).contains(&RuleId::ZeroCap));
        let f = d(Limits::new().min_rate(0, Duration::from_secs(10)));
        assert!(f.warnings.iter().any(|w| w.rule == RuleId::MinRateOff));
    }

    #[test]
    fn test_build_keep_alive_and_drain_rules() {
        let f = check(&Draft {
            listeners: &[],
            profiles: &[],
            limits: &Limits::new(),
            keep_alive: &KeepAlive::new().idle(Duration::ZERO).max_requests(0),
            workers: &Workers::blocking(0),
            drain_deadline: Duration::ZERO,
            has_control: true,
        });
        let r = rules(&f);
        assert!(r.contains(&RuleId::DeadlineOrder));
        assert!(r.contains(&RuleId::ZeroCap));
        assert!(r.contains(&RuleId::DrainRange));
        assert!(r.contains(&RuleId::DeadlineRange));
        assert!(
            f.warnings
                .iter()
                .any(|w| w.rule == RuleId::LockdownWithoutCritical)
        );
        assert!(f.warnings.iter().any(|w| w.rule == RuleId::NoListeners));
    }

    #[test]
    fn test_build_warnings_behind_proxy() {
        let f = run(&[proxy("site", "127.0.0.1:1", "127.0.0.1")], &[]);
        assert!(
            f.warnings
                .iter()
                .any(|w| w.rule == RuleId::DeclaredSchemeHttp)
        );
        let f = check(&Draft {
            listeners: &[proxy("site", "127.0.0.1:1", "127.0.0.1")],
            profiles: &[],
            limits: &Limits::new(),
            keep_alive: &KeepAlive::new().idle(Duration::from_secs(2)),
            workers: &Workers::auto(),
            drain_deadline: Duration::from_secs(30),
            has_control: false,
        });
        assert!(
            f.warnings
                .iter()
                .any(|w| w.rule == RuleId::ShortIdleBehindProxy)
        );
    }

    #[test]
    fn test_build_same_input_same_errors() {
        let ls = [
            ListenerSpec::tcp("Bad", "nope"),
            proxy("site", "0.0.0.0:1", "0.0.0.0/0"),
        ];
        let a = rules(&run(&ls, &[]));
        let b = rules(&run(&ls, &[]));
        assert_eq!(a, b);
        assert!(a.len() >= 4);
    }
}
