//! The real client of a request, the same whichever way it arrived.

use core::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::net::normalize;

/// The scheme a client used to reach the front of the deployment.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Plain HTTP.
    #[default]
    Http,
    /// HTTP over TLS.
    Https,
}

impl Scheme {
    /// `"http"` or `"https"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a request arrived.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IngressKind {
    /// The client connected to this listener itself.
    Direct,
    /// The client connected itself, over TLS.
    DirectTls,
    /// Behind a proxy that sent a PROXY protocol header.
    ProxyProtocol,
    /// Behind a proxy that sent forwarded headers.
    Forwarded,
    /// Over a Unix socket.
    Unix,
    /// From a FastCGI front end.
    FastCgi,
}

impl IngressKind {
    /// A stable snake_case name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            IngressKind::Direct => "direct",
            IngressKind::DirectTls => "direct_tls",
            IngressKind::ProxyProtocol => "proxy_protocol",
            IngressKind::Forwarded => "forwarded",
            IngressKind::Unix => "unix",
            IngressKind::FastCgi => "fastcgi",
        }
    }
}

impl fmt::Display for IngressKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The real client of a request.
///
/// Addresses are parsed `IpAddr` values, never raw strings, and IPv4-mapped
/// IPv6 addresses are normalized to IPv4, so trust tests, bans, and logs
/// agree on one form.
///
/// ```
/// use serve_net::{ClientInfo, IngressKind, Scheme};
///
/// let client = ClientInfo::direct("192.0.2.7:51000".parse().unwrap(), false);
/// assert_eq!(client.addr(), Some("192.0.2.7".parse().unwrap()));
/// assert_eq!(client.port(), 51000);
/// assert_eq!(client.scheme(), Scheme::Http);
/// assert_eq!(client.ingress(), IngressKind::Direct);
/// assert_eq!(client.hops(), 0);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    addr: Option<IpAddr>,
    port: u16,
    scheme: Scheme,
    hops: u8,
    ingress: IngressKind,
    peer: Option<SocketAddr>,
    proxy_local: bool,
}

impl ClientInfo {
    /// A client that connected directly from `peer`; `tls` says whether the
    /// connection is TLS.
    #[must_use]
    pub fn direct(peer: SocketAddr, tls: bool) -> ClientInfo {
        let peer = SocketAddr::new(normalize(peer.ip()), peer.port());
        ClientInfo {
            addr: Some(peer.ip()),
            port: peer.port(),
            scheme: if tls { Scheme::Https } else { Scheme::Http },
            hops: 0,
            ingress: if tls {
                IngressKind::DirectTls
            } else {
                IngressKind::Direct
            },
            peer: Some(peer),
            proxy_local: false,
        }
    }

    /// The client address; `None` only when a forwarded walk ended at
    /// `unknown` or an obfuscated identifier.
    #[must_use]
    pub fn addr(&self) -> Option<IpAddr> {
        self.addr
    }

    /// The client port; 0 when not known.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address and port together.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addr.map(|a| SocketAddr::new(a, self.port))
    }

    /// The scheme the client used.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Proxies between the client and this server: 0 direct, 1 behind one.
    #[must_use]
    pub fn hops(&self) -> u8 {
        self.hops
    }

    /// How the request arrived.
    #[must_use]
    pub fn ingress(&self) -> IngressKind {
        self.ingress
    }

    /// The socket peer, always kept (`None` on a Unix socket).
    #[must_use]
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Whether a PROXY v2 `LOCAL` command named the proxy itself.
    #[must_use]
    pub fn is_proxy_local(&self) -> bool {
        self.proxy_local
    }

    /// Whether the client address is unknown (see [`addr`](Self::addr)).
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.addr.is_none()
    }

    pub(crate) fn behind_proxy(
        mut self,
        addr: Option<IpAddr>,
        port: u16,
        hops: u8,
        ingress: IngressKind,
    ) -> ClientInfo {
        self.addr = addr.map(normalize);
        self.port = port;
        self.hops = hops;
        self.ingress = ingress;
        self
    }

    pub(crate) fn with_scheme(mut self, scheme: Scheme) -> ClientInfo {
        self.scheme = scheme;
        self
    }

    #[allow(dead_code)] // used by the PROXY ingress (0.4)
    pub(crate) fn with_proxy_local(mut self, on: bool) -> ClientInfo {
        self.proxy_local = on;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_direct_mapped_v6_normalized() {
        let c = ClientInfo::direct("[::ffff:192.0.2.1]:80".parse().unwrap(), true);
        assert_eq!(c.addr(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(c.peer(), Some("192.0.2.1:80".parse().unwrap()));
        assert_eq!(c.scheme(), Scheme::Https);
        assert_eq!(c.ingress(), IngressKind::DirectTls);
    }

    #[test]
    fn test_client_behind_proxy_keeps_peer() {
        let c = ClientInfo::direct("127.0.0.1:5000".parse().unwrap(), false).behind_proxy(
            Some("203.0.113.9".parse().unwrap()),
            0,
            2,
            IngressKind::Forwarded,
        );
        assert_eq!(c.addr(), Some("203.0.113.9".parse().unwrap()));
        assert_eq!(c.peer(), Some("127.0.0.1:5000".parse().unwrap()));
        assert_eq!(c.hops(), 2);
        assert_eq!(c.socket_addr(), Some("203.0.113.9:0".parse().unwrap()));
        let unknown = c.behind_proxy(None, 0, 1, IngressKind::Forwarded);
        assert!(unknown.is_unknown());
        assert_eq!(unknown.socket_addr(), None);
    }

    #[test]
    fn test_client_info_is_small() {
        assert!(core::mem::size_of::<ClientInfo>() <= 64);
    }

    #[test]
    fn test_scheme_and_ingress_names() {
        assert_eq!(Scheme::Https.to_string(), "https");
        assert_eq!(IngressKind::FastCgi.as_str(), "fastcgi");
    }
}
