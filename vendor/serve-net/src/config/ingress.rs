//! How clients reach a listener, and whom to believe about them.

use crate::net::{ProxyVersions, TrustedProxies};

/// How clients reach a listener, and therefore where the real client comes from.
///
/// ```
/// use serve_net::{Ingress, ProxySource, TrustedProxies};
///
/// let direct = Ingress::Direct;
/// let behind_apache = Ingress::Proxy(ProxySource::forwarded_for(TrustedProxies::loopback()));
/// # let _ = (direct, behind_apache);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub enum Ingress {
    /// Clients connect to this listener themselves.
    #[default]
    Direct,
    /// Behind a reverse proxy or a load balancer.
    Proxy(ProxySource),
}

impl Ingress {
    pub(crate) fn proxy(&self) -> Option<&ProxySource> {
        match self {
            Ingress::Proxy(p) => Some(p),
            Ingress::Direct => None,
        }
    }
}

/// Where the real client comes from behind a front end, and whom to believe.
///
/// ```
/// use serve_net::{ForwardedSource, MissingHeader, ProxySource, TrustedProxies};
///
/// // nginx in front, sending X-Real-IP and X-Forwarded-Proto.
/// let nginx = ProxySource::headers(ForwardedSource::SingleAddress("x-real-ip"), TrustedProxies::loopback())
///     .trust_scheme(true);
/// assert!(nginx.trusted().contains("127.0.0.1".parse().unwrap()));
///
/// // A health checker on the proxy host sends no header: treat it as the client.
/// let lenient = ProxySource::forwarded_for(TrustedProxies::loopback()).missing(MissingHeader::UsePeer);
/// # let _ = lenient;
/// ```
#[must_use]
#[derive(Clone, Debug)]
pub struct ProxySource {
    pub(crate) kind: ProxyKind,
    pub(crate) trusted: TrustedProxies,
    pub(crate) trust_scheme: bool,
    pub(crate) trust_host: bool,
    pub(crate) max_hops: u8,
    pub(crate) missing: MissingHeader,
    pub(crate) unknown: UnknownClient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProxyKind {
    Headers(ForwardedSource),
    #[allow(dead_code)] // the PROXY protocol ingress ships in 0.4
    ProxyProtocol(ProxyVersions),
}

impl ProxySource {
    /// `X-Forwarded-For` (with `X-Forwarded-Proto` and `X-Forwarded-Host` when trusted).
    pub fn forwarded_for(trusted: TrustedProxies) -> Self {
        Self::headers(ForwardedSource::XForwardedFor, trusted)
    }

    /// Forwarded headers of the given kind.
    pub fn headers(source: ForwardedSource, trusted: TrustedProxies) -> Self {
        ProxySource {
            kind: ProxyKind::Headers(source),
            trusted,
            trust_scheme: false,
            trust_host: false,
            max_hops: 16,
            missing: MissingHeader::Refuse,
            unknown: UnknownClient::Allow,
        }
    }

    /// Take the scheme from the trusted proxy (default off).
    pub fn trust_scheme(mut self, on: bool) -> Self {
        self.trust_scheme = on;
        self
    }

    /// Take the authority from the trusted proxy (default off).
    pub fn trust_host(mut self, on: bool) -> Self {
        self.trust_host = on;
        self
    }

    /// The most entries walked (default 16, 1 to 64).
    pub fn max_hops(mut self, n: u8) -> Self {
        self.max_hops = n;
        self
    }

    /// What to do when a trusted peer sends no forwarded field (default `Refuse`).
    pub fn missing(mut self, policy: MissingHeader) -> Self {
        self.missing = policy;
        self
    }

    /// What a walk that ends at `unknown` means (default `Allow`).
    pub fn unknown(mut self, policy: UnknownClient) -> Self {
        self.unknown = policy;
        self
    }

    /// The proxies whose claims are believed.
    #[must_use]
    pub fn trusted(&self) -> &TrustedProxies {
        &self.trusted
    }
}

/// Which forwarded field carries the client.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardedSource {
    /// RFC 7239 `Forwarded`: `for=`, `proto=`, `host=`.
    Forwarded,
    /// `X-Forwarded-For`, with `X-Forwarded-Proto` and `X-Forwarded-Host`.
    XForwardedFor,
    /// One address in a named field, for example `"x-real-ip"`; a list is refused.
    SingleAddress(&'static str),
}

/// What to do when a trusted peer sends no forwarded field.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MissingHeader {
    /// Answer 400 (fail closed: a misconfigured front end shows at once).
    #[default]
    Refuse,
    /// Treat the peer as the client (health checks from the proxy host).
    UsePeer,
}

/// What a walk that ends at `unknown` or an obfuscated identifier means.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownClient {
    /// The request proceeds with no client address.
    #[default]
    Allow,
    /// Answer 400.
    Refuse,
}
