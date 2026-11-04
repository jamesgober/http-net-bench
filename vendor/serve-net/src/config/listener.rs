//! Listener specifications.

use std::net::{SocketAddr, ToSocketAddrs};

use crate::client::Scheme;
use crate::config::{Ingress, ProfileId};

/// Where a listener's socket comes from.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerSource {
    /// Bind this TCP address.
    Tcp(SocketAddr),
    /// The address resolved to nothing; `build` reports it (rule `AddressResolve`).
    Unresolved,
}

/// One listener: a name, where its socket comes from, how clients arrive, and
/// which profile its connections use.
///
/// ```
/// use serve_net::{Ingress, ListenerSpec, ProfileId, ProxySource, Scheme, TrustedProxies};
///
/// let site = ListenerSpec::tcp("site", "127.0.0.1:8080")
///     .ingress(Ingress::Proxy(ProxySource::forwarded_for(TrustedProxies::loopback())))
///     .scheme(Scheme::Https)
///     .profile(ProfileId(0))
///     .max_connections(20_000);
/// assert_eq!(site.name(), "site");
/// ```
#[must_use]
#[derive(Debug)]
pub struct ListenerSpec {
    pub(crate) name: String,
    pub(crate) source: ListenerSource,
    pub(crate) ingress: Ingress,
    pub(crate) profile: ProfileId,
    pub(crate) scheme: Scheme,
    pub(crate) backlog: Option<u32>,
    pub(crate) max_connections: Option<u32>,
    pub(crate) public_bind: Option<&'static str>,
    pub(crate) broad_trust: Option<&'static str>,
}

impl ListenerSpec {
    /// A TCP listener on the first address `addr` resolves to.
    pub fn tcp<A: ToSocketAddrs>(name: &str, addr: A) -> Self {
        let source = match addr.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => ListenerSource::Tcp(a),
            None => ListenerSource::Unresolved,
        };
        ListenerSpec {
            name: name.to_owned(),
            source,
            ingress: Ingress::Direct,
            profile: ProfileId(0),
            scheme: Scheme::Http,
            backlog: None,
            max_connections: None,
            public_bind: None,
            broad_trust: None,
        }
    }

    /// How clients reach this listener.
    pub fn ingress(mut self, ingress: Ingress) -> Self {
        self.ingress = ingress;
        self
    }

    /// The profile its connections use (default 0).
    pub fn profile(mut self, id: ProfileId) -> Self {
        self.profile = id;
        self
    }

    /// The scheme to report when the front end says nothing about it.
    pub fn scheme(mut self, scheme: Scheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// The accept queue length (1 to 65,535; default 1,024).
    pub fn backlog(mut self, n: u32) -> Self {
        self.backlog = Some(n);
        self
    }

    /// The listener's soft connection cap.
    pub fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = Some(n);
        self
    }

    /// Permits a proxy or FastCGI listener on a public or unspecified address.
    /// The reason is kept and reported.
    pub fn allow_public_bind(mut self, reason: &'static str) -> Self {
        self.public_bind = Some(reason);
        self
    }

    /// Permits trust entries broader than /8 (IPv4) or /32 (IPv6).
    pub fn allow_broad_trust(mut self, reason: &'static str) -> Self {
        self.broad_trust = Some(reason);
        self
    }

    /// The listener's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where its socket comes from.
    #[must_use]
    pub fn source(&self) -> &ListenerSource {
        &self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_resolves_now() {
        let l = ListenerSpec::tcp("web", "127.0.0.1:8080");
        assert_eq!(
            l.source(),
            &ListenerSource::Tcp("127.0.0.1:8080".parse().unwrap())
        );
        let bad = ListenerSpec::tcp("web", "not an address");
        assert_eq!(bad.source(), &ListenerSource::Unresolved);
    }
}
