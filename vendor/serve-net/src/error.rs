//! Errors: configuration errors and warnings, start-up and run-time errors,
//! and the reason every connection ended.

use core::fmt;

use crate::config::ProfileId;
use crate::net::CloseReason;

/// Which configuration rule an error or warning comes from.
///
/// Every rule is described in `docs/API.md` with what it refuses and how to
/// override it, if it can be overridden. `as_str` gives a stable name for
/// logs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleId {
    /// A proxy or FastCGI listener on an unspecified or public address.
    PublicBind,
    /// Forwarded-header trust on a direct listener.
    ForwardedOnDirect,
    /// A FastCGI TCP listener with an empty trust list.
    FastCgiTrust,
    /// A trust entry of prefix length 0.
    TrustWildcard,
    /// A trust entry broader than /8 (IPv4) or /32 (IPv6).
    TrustTooBroad,
    /// Two client-address sources on one listener.
    TwoClientSources,
    /// A proxy listener with no trusted entry.
    TrustEmpty,
    /// A trust entry in text that did not parse.
    TrustParse,
    /// A Unix socket mode writable by others.
    WorldWritableSocket,
    /// A uid or gid allowlist where the platform has no peer credentials.
    PeerCredentialsUnavailable,
    /// Two listeners with one name.
    DuplicateName,
    /// A listener name outside 1 to 64 bytes of `[a-z0-9._-]`.
    BadName,
    /// `ProfileId(255)`, which is reserved.
    ProfileIdReserved,
    /// Profile ids not dense from 0, or repeated.
    ProfileGap,
    /// A listener naming a profile that does not exist.
    UnknownProfile,
    /// Deadlines in the wrong order.
    DeadlineOrder,
    /// A value outside its documented range.
    DeadlineRange,
    /// A connection or in-flight cap of 0.
    ZeroCap,
    /// Two listeners on one address or path.
    DuplicateBind,
    /// A driver this build or platform does not provide.
    DriverUnavailable,
    /// A reload that changes the workers.
    ReloadWorkers,
    /// A drain deadline of 0 or above 1 h.
    DrainRange,
    /// ALPN engine choice on a listener without TLS.
    AlpnWithoutTls,
    /// TLS on a FastCGI listener.
    TlsOnFastCgi,
    /// `trust_scheme` or `trust_host` with no source that can carry them.
    SchemeTrustWithoutSource,
    /// A listener address that resolved to nothing.
    AddressResolve,
    /// A TLS listener with no TLS acceptor.
    TlsWithoutAcceptor,
    /// A field name that is not a token.
    BadHeaderName,
    /// Forwarded headers or FastCGI on a listener whose profile serves a custom family.
    IngressNeedsHttp,
    /// Lane reserves summing above 100%.
    ReserveOverflow,
    /// More than 64 listeners or 255 profiles.
    TooMany,
    /// Warning: a proxy listener left at `Scheme::Http` with `trust_scheme` off.
    DeclaredSchemeHttp,
    /// Warning: the minimum transfer rate is off.
    MinRateOff,
    /// Warning: `catch_service_panics` in a build that aborts on panic.
    PanicCatchInAbortBuild,
    /// Warning: `Offload` on the blocking driver behaves as `Inline`.
    OffloadOnBlocking,
    /// Warning: keep-alive idle under 5 s behind a proxy.
    ShortIdleBehindProxy,
    /// Warning: lockdown would refuse every profile (none is critical).
    LockdownWithoutCritical,
    /// Warning: no listener.
    NoListeners,
}

impl RuleId {
    /// A stable snake_case name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleId::PublicBind => "public_bind",
            RuleId::ForwardedOnDirect => "forwarded_on_direct",
            RuleId::FastCgiTrust => "fastcgi_trust",
            RuleId::TrustWildcard => "trust_wildcard",
            RuleId::TrustTooBroad => "trust_too_broad",
            RuleId::TwoClientSources => "two_client_sources",
            RuleId::TrustEmpty => "trust_empty",
            RuleId::TrustParse => "trust_parse",
            RuleId::WorldWritableSocket => "world_writable_socket",
            RuleId::PeerCredentialsUnavailable => "peer_credentials_unavailable",
            RuleId::DuplicateName => "duplicate_name",
            RuleId::BadName => "bad_name",
            RuleId::ProfileIdReserved => "profile_id_reserved",
            RuleId::ProfileGap => "profile_gap",
            RuleId::UnknownProfile => "unknown_profile",
            RuleId::DeadlineOrder => "deadline_order",
            RuleId::DeadlineRange => "deadline_range",
            RuleId::ZeroCap => "zero_cap",
            RuleId::DuplicateBind => "duplicate_bind",
            RuleId::DriverUnavailable => "driver_unavailable",
            RuleId::ReloadWorkers => "reload_workers",
            RuleId::DrainRange => "drain_range",
            RuleId::AlpnWithoutTls => "alpn_without_tls",
            RuleId::TlsOnFastCgi => "tls_on_fastcgi",
            RuleId::SchemeTrustWithoutSource => "scheme_trust_without_source",
            RuleId::AddressResolve => "address_resolve",
            RuleId::TlsWithoutAcceptor => "tls_without_acceptor",
            RuleId::BadHeaderName => "bad_header_name",
            RuleId::IngressNeedsHttp => "ingress_needs_http",
            RuleId::ReserveOverflow => "reserve_overflow",
            RuleId::TooMany => "too_many",
            RuleId::DeclaredSchemeHttp => "declared_scheme_http",
            RuleId::MinRateOff => "min_rate_off",
            RuleId::PanicCatchInAbortBuild => "panic_catch_in_abort_build",
            RuleId::OffloadOnBlocking => "offload_on_blocking",
            RuleId::ShortIdleBehindProxy => "short_idle_behind_proxy",
            RuleId::LockdownWithoutCritical => "lockdown_without_critical",
            RuleId::NoListeners => "no_listeners",
        }
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a configuration error or warning is about.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// The server as a whole.
    Server,
    /// One listener, by name.
    Listener(String),
    /// One profile, by id.
    Profile(ProfileId),
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::Server => f.write_str("server"),
            Subject::Listener(name) => write!(f, "listener {name}"),
            Subject::Profile(id) => write!(f, "profile {}", id.0),
        }
    }
}

/// One configuration error: the rule, its subject, what is wrong, and what to
/// change.
///
/// Messages and hints are fixed text: they never quote configuration values,
/// which may be secret, and never request data.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// The rule that refused the configuration.
    pub rule: RuleId,
    /// The server, listener, or profile it concerns.
    pub subject: Subject,
    /// What is wrong.
    pub message: &'static str,
    /// What to change.
    pub hint: &'static str,
}

impl ConfigError {
    pub(crate) fn new(
        rule: RuleId,
        subject: Subject,
        message: &'static str,
        hint: &'static str,
    ) -> Self {
        ConfigError {
            rule,
            subject,
            message,
            hint,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({}; rule {})",
            self.subject, self.message, self.hint, self.rule
        )
    }
}

/// A value that is allowed but questionable, kept by `Built::warnings`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigWarning {
    /// The rule that noticed it.
    pub rule: RuleId,
    /// The server, listener, or profile it concerns.
    pub subject: Subject,
    /// What was noticed and why it matters.
    pub message: &'static str,
}

impl ConfigWarning {
    pub(crate) fn new(rule: RuleId, subject: Subject, message: &'static str) -> Self {
        ConfigWarning {
            rule,
            subject,
            message,
        }
    }
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} (rule {})", self.subject, self.message, self.rule)
    }
}

/// Every configuration error found, never empty, sorted by subject.
///
/// The same configuration always gives the same errors in the same order, so
/// a configuration can be fixed in one pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigErrors {
    errors: Vec<ConfigError>,
}

impl ConfigErrors {
    /// Builds the list; `None` when there is no error.
    pub(crate) fn from_vec(mut errors: Vec<ConfigError>) -> Option<ConfigErrors> {
        if errors.is_empty() {
            return None;
        }
        // Stable: rules keep their check order within one subject.
        errors.sort_by(|a, b| a.subject.cmp(&b.subject));
        Some(ConfigErrors { errors })
    }

    /// The errors, sorted by subject.
    pub fn iter(&self) -> impl Iterator<Item = &ConfigError> {
        self.errors.iter()
    }

    /// The number of errors (at least 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Always false: a `ConfigErrors` holds at least one error.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Whether any error comes from `rule`.
    #[must_use]
    pub fn has(&self, rule: RuleId) -> bool {
        self.errors.iter().any(|e| e.rule == rule)
    }
}

impl IntoIterator for ConfigErrors {
    type Item = ConfigError;
    type IntoIter = std::vec::IntoIter<ConfigError>;
    fn into_iter(self) -> Self::IntoIter {
        self.errors.into_iter()
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.errors.len();
        write!(
            f,
            "{n} configuration error{}:",
            if n == 1 { "" } else { "s" }
        )?;
        for e in &self.errors {
            write!(f, "\n  {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// A start-up or run-time error.
#[non_exhaustive]
#[derive(Debug)]
pub enum ServeError {
    /// The configuration was refused; every error is listed.
    Config(ConfigErrors),
    /// A listener could not be bound.
    Bind {
        /// The listener's name.
        listener: String,
        /// Why: in use, permission, or not on this host.
        source: net_io::NetError,
    },
    /// net-io could not start its workers or open the door.
    Start(net_io::NetError),
    /// The operation needs a server that is not draining.
    Draining,
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::Config(errors) => write!(f, "{errors}"),
            ServeError::Bind { listener, source } => {
                write!(f, "listener `{listener}` could not be bound: {source}")
            }
            ServeError::Start(source) => write!(f, "the server could not start: {source}"),
            ServeError::Draining => {
                f.write_str("the server is draining; start a new server instead")
            }
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::Config(errors) => Some(errors),
            ServeError::Bind { source, .. } | ServeError::Start(source) => Some(source),
            ServeError::Draining => None,
        }
    }
}

impl From<ConfigErrors> for ServeError {
    fn from(errors: ConfigErrors) -> Self {
        ServeError::Config(errors)
    }
}

/// Why a connection ended. Every connection ends with exactly one reason.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EndReason {
    /// net-io closed it: the peer, idle, a read or write timeout, a slow
    /// peer, a kill.
    Transport(CloseReason),
    /// No complete head within `head_timeout`.
    HeadTimeout,
    /// The body did not finish within `request_timeout`.
    RequestTimeout,
    /// A deferred reply did not come within `reply_timeout`.
    ReplyTimeout,
    /// The client or the protocol ended keep-alive.
    ClientClose,
    /// `max_requests` reached.
    RequestLimit,
    /// `max_age` reached.
    MaxAge,
    /// Finished after a drain started.
    Drained,
    /// The engine refused a malformed request.
    ProtocolError,
    /// A forwarded header or FastCGI parameter was missing or malformed, or
    /// the peer was not trusted.
    IngressRefused,
    /// A soft connection cap was full.
    CapacityRefused,
    /// Admission refused a request.
    Shed,
    /// `Checkpoint` denied a request.
    Denied,
    /// `Checkpoint` killed the connection.
    CheckpointKill,
    /// The service returned `Outcome::Close`.
    ServiceClosed,
    /// The service panicked.
    ServicePanic,
    /// A deferred reply's token was dropped without completing it.
    ReplyDropped,
    /// No engine for the negotiated protocol.
    NoEngine,
    /// The service refused the request in `head`.
    Refused,
}

impl EndReason {
    /// A stable snake_case name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            EndReason::Transport(_) => "transport",
            EndReason::HeadTimeout => "head_timeout",
            EndReason::RequestTimeout => "request_timeout",
            EndReason::ReplyTimeout => "reply_timeout",
            EndReason::ClientClose => "client_close",
            EndReason::RequestLimit => "request_limit",
            EndReason::MaxAge => "max_age",
            EndReason::Drained => "drained",
            EndReason::ProtocolError => "protocol_error",
            EndReason::IngressRefused => "ingress_refused",
            EndReason::CapacityRefused => "capacity_refused",
            EndReason::Shed => "shed",
            EndReason::Denied => "denied",
            EndReason::CheckpointKill => "checkpoint_kill",
            EndReason::ServiceClosed => "service_closed",
            EndReason::ServicePanic => "service_panic",
            EndReason::ReplyDropped => "reply_dropped",
            EndReason::NoEngine => "no_engine",
            EndReason::Refused => "refused",
        }
    }

    /// Whether the connection was closed with a reset rather than a graceful close.
    #[must_use]
    pub fn is_abortive(self) -> bool {
        match self {
            EndReason::CheckpointKill | EndReason::ServicePanic => true,
            EndReason::Transport(reason) => reason.is_abortive(),
            _ => false,
        }
    }
}

impl fmt::Display for EndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(rule: RuleId, subject: Subject) -> ConfigError {
        ConfigError::new(rule, subject, "m", "h")
    }

    #[test]
    fn test_config_errors_empty_is_none() {
        assert!(ConfigErrors::from_vec(Vec::new()).is_none());
    }

    #[test]
    fn test_config_errors_sorted_by_subject_stable() {
        let errors = ConfigErrors::from_vec(vec![
            err(RuleId::BadName, Subject::Listener("b".into())),
            err(RuleId::ZeroCap, Subject::Server),
            err(RuleId::PublicBind, Subject::Listener("a".into())),
            err(RuleId::DuplicateName, Subject::Listener("b".into())),
        ])
        .unwrap();
        let rules: Vec<RuleId> = errors.iter().map(|e| e.rule).collect();
        assert_eq!(
            rules,
            [
                RuleId::ZeroCap,
                RuleId::PublicBind,
                RuleId::BadName,
                RuleId::DuplicateName
            ]
        );
        assert!(errors.has(RuleId::ZeroCap));
        assert!(!errors.has(RuleId::TrustEmpty));
        assert_eq!(errors.len(), 4);
    }

    #[test]
    fn test_config_errors_display_lists_every_error() {
        let errors = ConfigErrors::from_vec(vec![
            ConfigError::new(
                RuleId::ZeroCap,
                Subject::Server,
                "a cap is 0",
                "set it to 1 or more",
            ),
            ConfigError::new(
                RuleId::BadName,
                Subject::Listener("X".into()),
                "bad name",
                "use lowercase",
            ),
        ])
        .unwrap();
        let text = errors.to_string();
        assert!(text.starts_with("2 configuration errors:"));
        assert!(text.contains("server: a cap is 0 (set it to 1 or more; rule zero_cap)"));
        assert!(text.contains("listener X: bad name"));
    }

    #[test]
    fn test_serve_error_config_has_source() {
        let errors = ConfigErrors::from_vec(vec![err(RuleId::ZeroCap, Subject::Server)]).unwrap();
        let e = ServeError::from(errors);
        assert!(std::error::Error::source(&e).is_some());
        assert!(std::error::Error::source(&ServeError::Draining).is_none());
    }

    #[test]
    fn test_end_reason_names_unique() {
        let all = [
            EndReason::Transport(CloseReason::PeerClosed),
            EndReason::HeadTimeout,
            EndReason::RequestTimeout,
            EndReason::ReplyTimeout,
            EndReason::ClientClose,
            EndReason::RequestLimit,
            EndReason::MaxAge,
            EndReason::Drained,
            EndReason::ProtocolError,
            EndReason::IngressRefused,
            EndReason::CapacityRefused,
            EndReason::Shed,
            EndReason::Denied,
            EndReason::CheckpointKill,
            EndReason::ServiceClosed,
            EndReason::ServicePanic,
            EndReason::ReplyDropped,
            EndReason::NoEngine,
            EndReason::Refused,
        ];
        let mut names: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len());
    }

    #[test]
    fn test_subject_display() {
        assert_eq!(Subject::Server.to_string(), "server");
        assert_eq!(Subject::Listener("web".into()).to_string(), "listener web");
        assert_eq!(Subject::Profile(ProfileId(1)).to_string(), "profile 1");
    }
}
