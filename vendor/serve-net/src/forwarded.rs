//! Forwarded-header parsing and the right-to-left trusted walk.
//!
//! Sans-IO and OS-free: the walk reads borrowed field lines through
//! [`FieldLines`] and asks a [`Trust`] predicate whether an address belongs
//! to a trusted proxy. It never allocates; its work is linear in the bytes of
//! the fields and bounded by the hop limit.
//!
//! The rules (dev/PLAN.md section 8.5.2):
//!
//! - From a peer that is not trusted, the headers are ignored and the client
//!   is the peer.
//! - Every field line of the configured header is joined in order and its
//!   elements are walked from the right. Trusted entries are skipped, the
//!   first untrusted entry is the client, and when every entry is trusted
//!   the leftmost is.
//! - More than `max_hops` walked entries, a malformed entry, a zone
//!   identifier, or a list in a single-address field is a refusal.
//! - IPv4-mapped IPv6 entries are normalized before the trust test.

use std::net::{IpAddr, Ipv6Addr};

use crate::client::Scheme;
use crate::config::{ForwardedSource, MissingHeader, UnknownClient};
use crate::net::{TrustedProxies, normalize};

/// Whether an address belongs to a trusted proxy.
pub(crate) trait Trust {
    fn trusts(&self, ip: IpAddr) -> bool;
}

impl Trust for TrustedProxies {
    #[inline]
    fn trusts(&self, ip: IpAddr) -> bool {
        self.contains(ip)
    }
}

/// Field lines of a request head, by name, in arrival order.
pub(crate) trait FieldLines<'h> {
    fn field_lines(&self, name: &str, out: &mut Lines<'h>) -> Result<(), WalkError>;
}

/// At most this many field lines of one forwarding field are read; more is a refusal.
pub(crate) const MAX_LINES: usize = 32;

/// The field lines of one field, collected without allocation.
pub(crate) struct Lines<'h> {
    lines: [&'h [u8]; MAX_LINES],
    len: usize,
}

impl<'h> Lines<'h> {
    pub(crate) fn new() -> Self {
        Lines {
            lines: [&[]; MAX_LINES],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, line: &'h [u8]) -> Result<(), WalkError> {
        if self.len == MAX_LINES {
            return Err(WalkError::TooManyLines);
        }
        self.lines[self.len] = line;
        self.len += 1;
        Ok(())
    }

    fn as_slice(&self) -> &[&'h [u8]] {
        &self.lines[..self.len]
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// Why the forwarded facts were refused. Every case is answered with 400.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalkError {
    /// A trusted peer sent no forwarded field and the policy is `Refuse`.
    Missing,
    /// More entries than `max_hops` were walked.
    TooManyHops,
    /// More field lines than [`MAX_LINES`].
    TooManyLines,
    /// An entry that is not a valid address or node.
    Malformed,
    /// The walk stopped at `unknown` or an obfuscated id and the policy is `Refuse`.
    UnknownRefused,
    /// A list (or a second line) in a single-address field.
    ListInSingle,
    /// A `proto` that is not `http` or `https`.
    BadProto,
    /// A `host` that is not a valid authority.
    BadHost,
}

/// The rules of one listener.
pub(crate) struct Rules<'a, T: Trust> {
    pub(crate) source: ForwardedSource,
    pub(crate) trusted: &'a T,
    pub(crate) max_hops: u8,
    pub(crate) missing: MissingHeader,
    pub(crate) unknown: UnknownClient,
    pub(crate) trust_scheme: bool,
    pub(crate) trust_host: bool,
}

/// What the walk found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resolved<'h> {
    /// `None` when the walk ended at `unknown` or an obfuscated id.
    pub(crate) client: Option<IpAddr>,
    pub(crate) port: u16,
    pub(crate) hops: u8,
    /// Set only when the peer is trusted and `trust_scheme` is on.
    pub(crate) scheme: Option<Scheme>,
    /// Set only when the peer is trusted and `trust_host` is on.
    pub(crate) host: Option<&'h str>,
    /// Whether the forwarded facts were used (the peer was trusted).
    pub(crate) forwarded: bool,
}

/// Resolves the client of one request.
pub(crate) fn resolve<'h, T: Trust, F: FieldLines<'h>>(
    peer: IpAddr,
    peer_port: u16,
    rules: &Rules<'_, T>,
    head: &F,
) -> Result<Resolved<'h>, WalkError> {
    let peer = normalize(peer);
    if !rules.trusted.trusts(peer) {
        return Ok(Resolved {
            client: Some(peer),
            port: peer_port,
            hops: 0,
            scheme: None,
            host: None,
            forwarded: false,
        });
    }
    let mut lines = Lines::new();
    let name = match rules.source {
        ForwardedSource::Forwarded => "forwarded",
        ForwardedSource::XForwardedFor => "x-forwarded-for",
        ForwardedSource::SingleAddress(name) => name,
    };
    head.field_lines(name, &mut lines)?;
    let has_element = lines
        .as_slice()
        .iter()
        .any(|l| l.iter().any(|&b| b != b',' && b != b' ' && b != b'\t'));
    if !has_element {
        return match rules.missing {
            MissingHeader::Refuse => Err(WalkError::Missing),
            MissingHeader::UsePeer => {
                let mut out = Resolved {
                    client: Some(peer),
                    port: peer_port,
                    hops: 0,
                    scheme: None,
                    host: None,
                    forwarded: true,
                };
                proto_host_x(rules, head, &mut lines, &mut out)?;
                Ok(out)
            }
        };
    }
    let mut out = match rules.source {
        ForwardedSource::SingleAddress(_) => single(&lines)?,
        ForwardedSource::XForwardedFor => walk(rules, lines.as_slice(), parse_xff_entry, false)?,
        ForwardedSource::Forwarded => walk(rules, lines.as_slice(), parse_forwarded_element, true)?,
    };
    if out.client.is_none() && rules.unknown == UnknownClient::Refuse {
        return Err(WalkError::UnknownRefused);
    }
    match rules.source {
        ForwardedSource::Forwarded => proto_host_forwarded(rules, lines.as_slice(), &mut out)?,
        _ => proto_host_x(rules, head, &mut lines, &mut out)?,
    }
    Ok(out)
}

/// The trusted proxy's host for a head that was already resolved once:
/// `X-Forwarded-Host` (or `Forwarded` `host=`) of the nearest hop, when valid.
pub(crate) fn trusted_host<'h, F: FieldLines<'h>>(
    source: ForwardedSource,
    head: &F,
) -> Option<&'h str> {
    let mut lines = Lines::new();
    let value = match source {
        ForwardedSource::Forwarded => {
            head.field_lines("forwarded", &mut lines).ok()?;
            let element = last_element(lines.as_slice(), true).ok()??;
            let mut host = None;
            for_each_pair(element, |name, value| {
                if name.eq_ignore_ascii_case(b"host") {
                    host = Some(value);
                }
                Ok(())
            })
            .ok()?;
            host?
        }
        _ => {
            head.field_lines("x-forwarded-host", &mut lines).ok()?;
            last_element(lines.as_slice(), false).ok()??
        }
    };
    if valid_authority(value) {
        core::str::from_utf8(value).ok()
    } else {
        None
    }
}

/// One parsed entry: an address with an optional port, or an unknown node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Addr(IpAddr, u16),
    Unknown,
}

fn single<'h>(lines: &Lines<'h>) -> Result<Resolved<'h>, WalkError> {
    let mut found: Option<&[u8]> = None;
    for line in lines.as_slice() {
        let trimmed = trim_ows(line);
        if trimmed.is_empty() {
            continue;
        }
        if found.is_some() || trimmed.contains(&b',') {
            return Err(WalkError::ListInSingle);
        }
        found = Some(trimmed);
    }
    let entry = found.ok_or(WalkError::Malformed)?;
    match parse_xff_entry(entry)? {
        Node::Addr(ip, port) => Ok(Resolved {
            client: Some(normalize(ip)),
            port,
            hops: 1,
            scheme: None,
            host: None,
            forwarded: true,
        }),
        Node::Unknown => Err(WalkError::Malformed),
    }
}

/// Walks the elements of `lines` from the right.
fn walk<'h, T: Trust>(
    rules: &Rules<'_, T>,
    lines: &[&'h [u8]],
    parse: fn(&[u8]) -> Result<Node, WalkError>,
    quotes: bool,
) -> Result<Resolved<'h>, WalkError> {
    let max = usize::from(rules.max_hops.max(1));
    let mut walked = 0usize;
    let mut leftmost: Option<Node> = None;
    for line in lines.iter().rev() {
        for element in RevElements::new(line, quotes) {
            let element = element?;
            walked += 1;
            if walked > max {
                return Err(WalkError::TooManyHops);
            }
            match parse(element)? {
                Node::Addr(ip, port) => {
                    let ip = normalize(ip);
                    if rules.trusted.trusts(ip) {
                        leftmost = Some(Node::Addr(ip, port));
                        continue;
                    }
                    return Ok(Resolved {
                        client: Some(ip),
                        port,
                        hops: hops(walked),
                        scheme: None,
                        host: None,
                        forwarded: true,
                    });
                }
                Node::Unknown => {
                    return Ok(Resolved {
                        client: None,
                        port: 0,
                        hops: hops(walked),
                        scheme: None,
                        host: None,
                        forwarded: true,
                    });
                }
            }
        }
    }
    match leftmost {
        Some(Node::Addr(ip, port)) => Ok(Resolved {
            client: Some(ip),
            port,
            hops: hops(walked),
            scheme: None,
            host: None,
            forwarded: true,
        }),
        _ => Err(WalkError::Malformed),
    }
}

fn hops(walked: usize) -> u8 {
    u8::try_from(walked).unwrap_or(u8::MAX)
}

/// The elements of one list line, from the right: commas split (outside
/// quoted strings when `quotes` is set), OWS is trimmed, empty elements are
/// skipped. One backward scan, no storage: a walk that stops after `max_hops`
/// never reads the rest of the line.
///
/// Quoted strings are tracked by toggling on every `"`. That is exact
/// because no field serve-net reads may carry a backslash escape inside a
/// quoted string; a line with a backslash in quoted mode is refused.
struct RevElements<'h> {
    line: &'h [u8],
    end: usize,
    quotes: bool,
    failed: bool,
}

impl<'h> RevElements<'h> {
    fn new(line: &'h [u8], quotes: bool) -> Self {
        let failed = quotes && line.contains(&b'\\');
        RevElements {
            line,
            end: line.len(),
            quotes,
            failed,
        }
    }
}

impl<'h> Iterator for RevElements<'h> {
    type Item = Result<&'h [u8], WalkError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            self.failed = false;
            self.end = 0;
            return Some(Err(WalkError::Malformed));
        }
        while self.end > 0 {
            let mut i = self.end;
            let mut quoted = false;
            while i > 0 {
                let b = self.line[i - 1];
                if self.quotes && b == b'"' {
                    quoted = !quoted;
                } else if b == b',' && !quoted {
                    break;
                }
                i -= 1;
            }
            if quoted {
                self.end = 0;
                return Some(Err(WalkError::Malformed));
            }
            let (s, e) = trim_span(self.line, i, self.end);
            // Past the comma (or at the start of the line).
            self.end = i.saturating_sub(1);
            if i == 0 {
                self.end = 0;
            }
            if s < e {
                return Some(Ok(&self.line[s..e]));
            }
        }
        None
    }
}

fn trim_span(line: &[u8], mut s: usize, mut e: usize) -> (usize, usize) {
    while s < e && is_ows(line[s]) {
        s += 1;
    }
    while e > s && is_ows(line[e - 1]) {
        e -= 1;
    }
    (s, e)
}

fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let (s, e) = trim_span(v, 0, v.len());
    &v[s..e]
}

/// An `X-Forwarded-For` entry: an IPv4 or IPv6 literal, IPv6 optionally in
/// brackets, no port, no zone id.
fn parse_xff_entry(entry: &[u8]) -> Result<Node, WalkError> {
    let text = core::str::from_utf8(entry).map_err(|_| WalkError::Malformed)?;
    let inner = match text.strip_prefix('[') {
        Some(rest) => {
            let v6 = rest.strip_suffix(']').ok_or(WalkError::Malformed)?;
            let ip: Ipv6Addr = v6.parse().map_err(|_| WalkError::Malformed)?;
            return Ok(Node::Addr(IpAddr::V6(ip), 0));
        }
        None => text,
    };
    let ip: IpAddr = inner.parse().map_err(|_| WalkError::Malformed)?;
    Ok(Node::Addr(ip, 0))
}

/// A `Forwarded` element: `;`-separated pairs; its `for=` node is the entry.
fn parse_forwarded_element(element: &[u8]) -> Result<Node, WalkError> {
    let mut node = None;
    for_each_pair(element, |name, value| {
        if name.eq_ignore_ascii_case(b"for") {
            if node.is_some() {
                return Err(WalkError::Malformed);
            }
            node = Some(parse_node(value)?);
        }
        Ok(())
    })?;
    node.ok_or(WalkError::Malformed)
}

/// Calls `f(name, value)` for every `name=value` pair of an element, with the
/// value unquoted. A quoted value with a backslash escape is refused: no
/// parameter serve-net reads may contain one.
fn for_each_pair<'e>(
    element: &'e [u8],
    mut f: impl FnMut(&'e [u8], &'e [u8]) -> Result<(), WalkError>,
) -> Result<(), WalkError> {
    let mut rest = element;
    loop {
        let rest_trim = trim_ows(rest);
        if rest_trim.is_empty() {
            return Err(WalkError::Malformed);
        }
        let eq = rest_trim
            .iter()
            .position(|&b| b == b'=')
            .ok_or(WalkError::Malformed)?;
        let name = &rest_trim[..eq];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err(WalkError::Malformed);
        }
        let after = &rest_trim[eq + 1..];
        let (value, tail) = if after.first() == Some(&b'"') {
            let close = after[1..]
                .iter()
                .position(|&b| b == b'"')
                .ok_or(WalkError::Malformed)?;
            let value = &after[1..1 + close];
            if value.contains(&b'\\') {
                return Err(WalkError::Malformed);
            }
            (value, &after[close + 2..])
        } else {
            let end = after.iter().position(|&b| b == b';').unwrap_or(after.len());
            let value = trim_ows(&after[..end]);
            if value.is_empty() || !value.iter().all(|&b| is_tchar(b)) {
                return Err(WalkError::Malformed);
            }
            (value, &after[end..])
        };
        f(name, value)?;
        let tail = trim_ows(tail);
        if tail.is_empty() {
            return Ok(());
        }
        if tail[0] != b';' {
            return Err(WalkError::Malformed);
        }
        rest = &tail[1..];
    }
}

/// An RFC 7239 node: `ipv4[:port]`, `[ipv6][:port]`, `unknown`, `_obfuscated[:port]`.
fn parse_node(value: &[u8]) -> Result<Node, WalkError> {
    let text = core::str::from_utf8(value).map_err(|_| WalkError::Malformed)?;
    if text.eq_ignore_ascii_case("unknown") || text.starts_with('_') {
        if text.starts_with('_')
            && !text[1..].bytes().all(|b| {
                b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b':'
            })
        {
            return Err(WalkError::Malformed);
        }
        return Ok(Node::Unknown);
    }
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let close = rest.find(']').ok_or(WalkError::Malformed)?;
        let ip: Ipv6Addr = rest[..close].parse().map_err(|_| WalkError::Malformed)?;
        (IpAddr::V6(ip), &rest[close + 1..])
    } else {
        let (h, p) = match text.find(':') {
            Some(at) => (&text[..at], &text[at..]),
            None => (text, ""),
        };
        let ip: std::net::Ipv4Addr = h.parse().map_err(|_| WalkError::Malformed)?;
        (IpAddr::V4(ip), p)
    };
    let port = match port.strip_prefix(':') {
        None if port.is_empty() => 0,
        None => return Err(WalkError::Malformed),
        Some(p) if p.starts_with('_') => 0,
        Some(p) => parse_port(p)?,
    };
    Ok(Node::Addr(host, port))
}

fn parse_port(p: &str) -> Result<u16, WalkError> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WalkError::Malformed);
    }
    p.parse::<u16>().map_err(|_| WalkError::Malformed)
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Scheme and host from the rightmost `Forwarded` element (the nearest trusted hop).
fn proto_host_forwarded<'h, T: Trust>(
    rules: &Rules<'_, T>,
    lines: &[&'h [u8]],
    out: &mut Resolved<'h>,
) -> Result<(), WalkError> {
    if !rules.trust_scheme && !rules.trust_host {
        return Ok(());
    }
    let Some(element) = last_element(lines, true)? else {
        return Ok(());
    };
    let mut proto: Option<&'h [u8]> = None;
    let mut host: Option<&'h [u8]> = None;
    for_each_pair(element, |name, value| {
        if name.eq_ignore_ascii_case(b"proto") {
            proto = Some(value);
        } else if name.eq_ignore_ascii_case(b"host") {
            host = Some(value);
        }
        Ok(())
    })?;
    apply_proto_host(rules, proto, host, out)
}

/// Scheme and host from `X-Forwarded-Proto` and `X-Forwarded-Host`, last element.
fn proto_host_x<'h, T: Trust, F: FieldLines<'h>>(
    rules: &Rules<'_, T>,
    head: &F,
    lines: &mut Lines<'h>,
    out: &mut Resolved<'h>,
) -> Result<(), WalkError> {
    let mut proto = None;
    let mut host = None;
    if rules.trust_scheme {
        lines.clear();
        head.field_lines("x-forwarded-proto", lines)?;
        proto = last_element(lines.as_slice(), false)?;
    }
    if rules.trust_host {
        lines.clear();
        head.field_lines("x-forwarded-host", lines)?;
        host = last_element(lines.as_slice(), false)?;
    }
    apply_proto_host(rules, proto, host, out)
}

/// The rightmost element of the last non-empty line.
fn last_element<'h>(lines: &[&'h [u8]], quotes: bool) -> Result<Option<&'h [u8]>, WalkError> {
    for line in lines.iter().rev() {
        if let Some(element) = RevElements::new(line, quotes).next() {
            return element.map(Some);
        }
    }
    Ok(None)
}

fn apply_proto_host<'h, T: Trust>(
    rules: &Rules<'_, T>,
    proto: Option<&'h [u8]>,
    host: Option<&'h [u8]>,
    out: &mut Resolved<'h>,
) -> Result<(), WalkError> {
    if rules.trust_scheme {
        if let Some(p) = proto {
            out.scheme = Some(if p.eq_ignore_ascii_case(b"https") {
                Scheme::Https
            } else if p.eq_ignore_ascii_case(b"http") {
                Scheme::Http
            } else {
                return Err(WalkError::BadProto);
            });
        }
    }
    if rules.trust_host {
        if let Some(h) = host {
            if !valid_authority(h) {
                return Err(WalkError::BadHost);
            }
            out.host = core::str::from_utf8(h).ok();
        }
    }
    Ok(())
}

/// RFC 3986 `host [ ":" port ]`, at most 255 bytes.
pub(crate) fn valid_authority(a: &[u8]) -> bool {
    if a.is_empty() || a.len() > 255 {
        return false;
    }
    let (host, port) = if a[0] == b'[' {
        let Some(close) = a.iter().position(|&b| b == b']') else {
            return false;
        };
        let inner = &a[1..close];
        let Ok(text) = core::str::from_utf8(inner) else {
            return false;
        };
        if text.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        (&a[..=close], &a[close + 1..])
    } else {
        match a.iter().position(|&b| b == b':') {
            Some(at) => (&a[..at], &a[at..]),
            None => (a, &a[a.len()..]),
        }
    };
    if host.is_empty() {
        return false;
    }
    if host[0] != b'[' {
        let mut i = 0;
        while i < host.len() {
            let b = host[i];
            if b == b'%' {
                if i + 2 >= host.len()
                    || !host[i + 1].is_ascii_hexdigit()
                    || !host[i + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 3;
                continue;
            }
            if !(b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b)) {
                return false;
            }
            i += 1;
        }
    }
    match port.split_first() {
        None => true,
        Some((b':', digits)) => {
            digits.len() <= 5 && digits.iter().all(u8::is_ascii_digit) && {
                digits.is_empty()
                    || core::str::from_utf8(digits)
                        .ok()
                        .and_then(|d| d.parse::<u16>().ok())
                        .is_some()
            }
        }
        Some(_) => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A head given as `(name, value)` field lines.
    pub(crate) struct Fields<'h>(pub(crate) &'h [(&'h str, &'h [u8])]);

    impl<'h> FieldLines<'h> for Fields<'h> {
        fn field_lines(&self, name: &str, out: &mut Lines<'h>) -> Result<(), WalkError> {
            for (n, v) in self.0 {
                if n.eq_ignore_ascii_case(name) {
                    out.push(v)?;
                }
            }
            Ok(())
        }
    }

    fn rules(source: ForwardedSource, trusted: &TrustedProxies) -> Rules<'_, TrustedProxies> {
        Rules {
            source,
            trusted,
            max_hops: 16,
            missing: MissingHeader::Refuse,
            unknown: UnknownClient::Allow,
            trust_scheme: false,
            trust_host: false,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff<'h>(
        peer: &str,
        trusted: &str,
        lines: &'h [(&'h str, &'h [u8])],
    ) -> Result<Resolved<'h>, WalkError> {
        let t = TrustedProxies::parse(trusted).unwrap();
        resolve(
            ip(peer),
            4000,
            &rules(ForwardedSource::XForwardedFor, &t),
            &Fields(lines),
        )
    }

    #[test]
    fn test_xff_from_untrusted_peer_ignored() {
        let r = xff(
            "198.51.100.1",
            "10.0.0.0/8",
            &[("x-forwarded-for", b"1.2.3.4")],
        )
        .unwrap();
        assert_eq!(r.client, Some(ip("198.51.100.1")));
        assert_eq!(r.port, 4000);
        assert_eq!(r.hops, 0);
        assert!(!r.forwarded);
    }

    #[test]
    fn test_xff_left_injection_not_used() {
        let r = xff(
            "10.0.0.2",
            "10.0.0.0/8",
            &[("x-forwarded-for", b"198.51.100.7, 203.0.113.9, 10.0.0.5")],
        )
        .unwrap();
        assert_eq!(r.client, Some(ip("203.0.113.9")));
        assert_eq!(r.hops, 2);
    }

    #[test]
    fn test_xff_all_trusted_uses_leftmost() {
        let r = xff(
            "10.0.0.2",
            "10.0.0.0/8",
            &[("x-forwarded-for", b"10.1.1.1, 10.2.2.2")],
        )
        .unwrap();
        assert_eq!(r.client, Some(ip("10.1.1.1")));
        assert_eq!(r.hops, 2);
    }

    #[test]
    fn test_xff_multiple_lines_joined_in_order() {
        let lines: &[(&str, &[u8])] = &[
            ("x-forwarded-for", b"203.0.113.1"),
            ("x-forwarded-for", b"10.0.0.9"),
        ];
        let r = xff("10.0.0.2", "10.0.0.0/8", lines).unwrap();
        assert_eq!(r.client, Some(ip("203.0.113.1")));
        assert_eq!(r.hops, 2);
    }

    #[test]
    fn test_xff_missing_refused_by_default() {
        assert_eq!(xff("127.0.0.1", "127.0.0.1", &[]), Err(WalkError::Missing));
        assert_eq!(
            xff("127.0.0.1", "127.0.0.1", &[("x-forwarded-for", b" , ")]),
            Err(WalkError::Missing)
        );
    }

    #[test]
    fn test_xff_missing_use_peer_policy() {
        let t = TrustedProxies::loopback();
        let mut r = rules(ForwardedSource::XForwardedFor, &t);
        r.missing = MissingHeader::UsePeer;
        let out = resolve(ip("127.0.0.1"), 9, &r, &Fields(&[])).unwrap();
        assert_eq!(out.client, Some(ip("127.0.0.1")));
        assert_eq!(out.port, 9);
    }

    #[test]
    fn test_xff_hop_limit_boundaries() {
        // 16 entries walk; 17 refuse (all trusted so the walk goes all the way).
        let sixteen = "10.0.0.1, ".repeat(15) + "10.0.0.1";
        let seventeen = "10.0.0.1, ".repeat(16) + "10.0.0.1";
        let lines16: Vec<(&str, &[u8])> = vec![("x-forwarded-for", sixteen.as_bytes())];
        let lines17: Vec<(&str, &[u8])> = vec![("x-forwarded-for", seventeen.as_bytes())];
        assert!(xff("10.0.0.2", "10.0.0.0/8", &lines16).is_ok());
        assert_eq!(
            xff("10.0.0.2", "10.0.0.0/8", &lines17),
            Err(WalkError::TooManyHops)
        );
    }

    #[test]
    fn test_xff_1000_entries_refused_at_hop_limit() {
        let many = "10.0.0.1,".repeat(1000);
        let lines: Vec<(&str, &[u8])> = vec![("x-forwarded-for", many.as_bytes())];
        assert_eq!(
            xff("10.0.0.2", "10.0.0.0/8", &lines),
            Err(WalkError::TooManyHops)
        );
        // An untrusted entry on the right stops the walk at once, whatever is to its left.
        let tail = many.clone() + "203.0.113.4";
        let lines: Vec<(&str, &[u8])> = vec![("x-forwarded-for", tail.as_bytes())];
        assert_eq!(
            xff("10.0.0.2", "10.0.0.0/8", &lines).unwrap().client,
            Some(ip("203.0.113.4"))
        );
    }

    #[test]
    fn test_xff_malformed_entries_refused() {
        for bad in [
            &b"1.2.3"[..],
            b"1.2.3.4:80",
            b"fe80::1%eth0",
            b"[::1",
            b"garbage",
            b"01.2.3.4",
            b"[1.2.3.4]",
        ] {
            let lines: &[(&str, &[u8])] = &[("x-forwarded-for", bad)];
            assert_eq!(
                xff("127.0.0.1", "127.0.0.1", lines),
                Err(WalkError::Malformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn test_xff_ipv6_forms_and_whitespace() {
        let lines: &[(&str, &[u8])] = &[("x-forwarded-for", b"  2001:DB8::1 ,\t[2001:db8::2]  ")];
        let r = xff("127.0.0.1", "127.0.0.1", lines).unwrap();
        assert_eq!(r.client, Some(ip("2001:db8::2")));
        let lines: &[(&str, &[u8])] = &[("x-forwarded-for", b"203.0.113.1,,")];
        assert_eq!(
            xff("127.0.0.1", "127.0.0.1", lines).unwrap().client,
            Some(ip("203.0.113.1"))
        );
    }

    #[test]
    fn test_mapped_v6_trusted_as_v4() {
        // A mapped form of a trusted address is trusted; a mapped untrusted one is the client, as IPv4.
        let lines: &[(&str, &[u8])] =
            &[("x-forwarded-for", b"::ffff:203.0.113.5, ::ffff:10.0.0.3")];
        let r = xff("::ffff:10.0.0.2", "10.0.0.0/8", lines).unwrap();
        assert_eq!(r.client, Some(ip("203.0.113.5")));
    }

    #[test]
    fn test_forwarded_rfc7239_forms() {
        let t = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let r = rules(ForwardedSource::Forwarded, &t);
        let lines: &[(&str, &[u8])] = &[(
            "forwarded",
            b"for=\"[2001:db8:cafe::17]:4711\";proto=https, For=10.0.0.4;by=10.0.0.1",
        )];
        let out = resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)).unwrap();
        assert_eq!(out.client, Some(ip("2001:db8:cafe::17")));
        assert_eq!(out.port, 4711);
        assert_eq!(out.hops, 2);
        assert_eq!(out.scheme, None, "proto ignored without trust_scheme");

        let lines: &[(&str, &[u8])] = &[("forwarded", b"for=\"192.0.2.43:47011\"")];
        let out = resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)).unwrap();
        assert_eq!((out.client, out.port), (Some(ip("192.0.2.43")), 47011));
    }

    #[test]
    fn test_forwarded_unknown_and_obfuscated() {
        let t = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let mut r = rules(ForwardedSource::Forwarded, &t);
        for v in [
            &b"for=unknown"[..],
            b"for=_hidden",
            b"for=\"_hidden:_port\"",
        ] {
            let lines: &[(&str, &[u8])] = &[("forwarded", v)];
            let out = resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)).unwrap();
            assert_eq!(out.client, None, "{v:?}");
        }
        r.unknown = UnknownClient::Refuse;
        let lines: &[(&str, &[u8])] = &[("forwarded", b"for=unknown")];
        assert_eq!(
            resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)),
            Err(WalkError::UnknownRefused)
        );
    }

    #[test]
    fn test_forwarded_malformed_refused() {
        let t = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let r = rules(ForwardedSource::Forwarded, &t);
        for v in [
            &b"for=1.2.3.4;for=5.6.7.8"[..],
            b"by=10.0.0.1",
            b"for=[::1]",
            b"for=\"1.2.3.4",
            b"for=\"1.2\\.3.4\"",
            b"for=1.2.3.4:99999",
            b"for=\"[fe80::1%25eth0]\"",
            b"for",
            b"for=192.0.2.43:47011",
        ] {
            let lines: &[(&str, &[u8])] = &[("forwarded", v)];
            assert_eq!(
                resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)),
                Err(WalkError::Malformed),
                "{v:?}"
            );
        }
    }

    #[test]
    fn test_forwarded_quoted_comma_does_not_split() {
        let t = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let mut r = rules(ForwardedSource::Forwarded, &t);
        r.trust_host = true;
        let lines: &[(&str, &[u8])] = &[("forwarded", b"for=203.0.113.8;host=\"a.example\"")];
        let out = resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)).unwrap();
        assert_eq!(out.host, Some("a.example"));
        let lines: &[(&str, &[u8])] = &[("forwarded", b"for=203.0.113.8;host=\"a/b\"")];
        assert_eq!(
            resolve(ip("10.0.0.2"), 1, &r, &Fields(lines)),
            Err(WalkError::BadHost)
        );
    }

    #[test]
    fn test_xfp_from_untrusted_ignored() {
        let t = TrustedProxies::loopback();
        let mut r = rules(ForwardedSource::XForwardedFor, &t);
        r.trust_scheme = true;
        let lines: &[(&str, &[u8])] = &[
            ("x-forwarded-for", b"203.0.113.1"),
            ("x-forwarded-proto", b"https"),
        ];
        let out = resolve(ip("198.51.100.3"), 1, &r, &Fields(lines)).unwrap();
        assert_eq!(out.scheme, None);
        let out = resolve(ip("127.0.0.1"), 1, &r, &Fields(lines)).unwrap();
        assert_eq!(out.scheme, Some(Scheme::Https));
    }

    #[test]
    fn test_xfp_bad_value_refused() {
        let t = TrustedProxies::loopback();
        let mut r = rules(ForwardedSource::XForwardedFor, &t);
        r.trust_scheme = true;
        let lines: &[(&str, &[u8])] = &[
            ("x-forwarded-for", b"203.0.113.1"),
            ("x-forwarded-proto", b"ftp"),
        ];
        assert_eq!(
            resolve(ip("127.0.0.1"), 1, &r, &Fields(lines)),
            Err(WalkError::BadProto)
        );
        // The rightmost value is the one the trusted proxy wrote.
        let lines: &[(&str, &[u8])] = &[
            ("x-forwarded-for", b"203.0.113.1"),
            ("x-forwarded-proto", b"ftp, HTTPS"),
        ];
        assert_eq!(
            resolve(ip("127.0.0.1"), 1, &r, &Fields(lines))
                .unwrap()
                .scheme,
            Some(Scheme::Https)
        );
    }

    #[test]
    fn test_xfh_invalid_authority_refused() {
        let t = TrustedProxies::loopback();
        let mut r = rules(ForwardedSource::XForwardedFor, &t);
        r.trust_host = true;
        for bad in [
            &b"a b"[..],
            b"a/b",
            b"[::1",
            b"host:99999",
            b"host:8x",
            b"%zz",
        ] {
            let lines: &[(&str, &[u8])] = &[
                ("x-forwarded-for", b"203.0.113.1"),
                ("x-forwarded-host", bad),
            ];
            assert_eq!(
                resolve(ip("127.0.0.1"), 1, &r, &Fields(lines)),
                Err(WalkError::BadHost),
                "{bad:?}"
            );
        }
        let lines: &[(&str, &[u8])] = &[
            ("x-forwarded-for", b"203.0.113.1"),
            ("x-forwarded-host", b"example.com:8443"),
        ];
        assert_eq!(
            resolve(ip("127.0.0.1"), 1, &r, &Fields(lines))
                .unwrap()
                .host,
            Some("example.com:8443")
        );
    }

    #[test]
    fn test_single_address_header() {
        let t = TrustedProxies::loopback();
        let r = rules(ForwardedSource::SingleAddress("x-real-ip"), &t);
        let lines: &[(&str, &[u8])] = &[("X-Real-IP", b" 203.0.113.7 ")];
        let out = resolve(ip("127.0.0.1"), 1, &r, &Fields(lines)).unwrap();
        assert_eq!((out.client, out.hops), (Some(ip("203.0.113.7")), 1));
        let list: &[(&str, &[u8])] = &[("x-real-ip", b"1.2.3.4, 5.6.7.8")];
        assert_eq!(
            resolve(ip("127.0.0.1"), 1, &r, &Fields(list)),
            Err(WalkError::ListInSingle)
        );
        let two: &[(&str, &[u8])] = &[("x-real-ip", b"1.2.3.4"), ("x-real-ip", b"5.6.7.8")];
        assert_eq!(
            resolve(ip("127.0.0.1"), 1, &r, &Fields(two)),
            Err(WalkError::ListInSingle)
        );
    }

    #[test]
    fn test_too_many_lines_refused() {
        let line: (&str, &[u8]) = ("x-forwarded-for", b"10.0.0.1");
        let lines = vec![line; MAX_LINES + 1];
        assert_eq!(
            xff("10.0.0.2", "10.0.0.0/8", &lines),
            Err(WalkError::TooManyLines)
        );
    }

    #[test]
    fn test_valid_authority_cases() {
        for good in [
            &b"example.com"[..],
            b"example.com:80",
            b"[::1]:8080",
            b"192.0.2.1",
            b"a%20b",
            b"host:",
        ] {
            assert!(valid_authority(good), "{good:?}");
        }
        for bad in [&b""[..], b":80", b"[::1]x", b"ex ample", b"\xff"] {
            assert!(!valid_authority(bad), "{bad:?}");
        }
        assert!(!valid_authority(&[b'a'; 256]));
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        /// Pieces a forwarding field is built from: addresses in canonical
        /// text, trusted and untrusted, and hostile fragments.
        fn piece() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("10.0.0.1".to_string()),
                Just("10.9.9.9".to_string()),
                Just("203.0.113.7".to_string()),
                Just("198.51.100.1".to_string()),
                Just("2001:db8::1".to_string()),
                Just("[2001:db8::2]".to_string()),
                Just("::ffff:10.0.0.3".to_string()),
                Just("::ffff:203.0.113.4".to_string()),
                Just("fe80::1%eth0".to_string()),
                Just("unknown".to_string()),
                Just("_hidden".to_string()),
                Just(" ".to_string()),
                Just(",".to_string()),
                Just("\"".to_string()),
                Just(";".to_string()),
                Just("for=".to_string()),
                Just("1.2.3.4:80".to_string()),
                "[ -~]{0,8}",
            ]
        }

        fn line() -> impl Strategy<Value = String> {
            proptest::collection::vec(piece(), 0..12).prop_map(|v| v.join(","))
        }

        fn forms_of(ip: IpAddr) -> Vec<String> {
            let mut forms = vec![ip.to_string()];
            if let IpAddr::V4(v4) = ip {
                forms.push(format!("::ffff:{v4}"));
            }
            forms
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// The walk never panics, stays within its bounds, and returns
            /// only the peer or an address that appears in the input.
            #[test]
            fn test_walk_never_panics_and_client_comes_from_input(
                lines in proptest::collection::vec(line(), 0..4),
                forwarded in any::<bool>(),
                peer_trusted in any::<bool>(),
                max_hops in 1u8..=64,
            ) {
                let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
                let peer: IpAddr = if peer_trusted { "10.0.0.2".parse().unwrap() } else { "192.0.2.1".parse().unwrap() };
                let name = if forwarded { "forwarded" } else { "x-forwarded-for" };
                let owned: Vec<(String, Vec<u8>)> = lines
                    .iter()
                    .map(|l| {
                        let value = if forwarded {
                            l.split(',').map(|p| format!("for={p}")).collect::<Vec<_>>().join(",")
                        } else {
                            l.clone()
                        };
                        (name.to_string(), value.into_bytes())
                    })
                    .collect();
                let fields: Vec<(&str, &[u8])> = owned.iter().map(|(n, v)| (n.as_str(), v.as_slice())).collect();
                let source = if forwarded { ForwardedSource::Forwarded } else { ForwardedSource::XForwardedFor };
                let mut r = rules(source, &trusted);
                r.max_hops = max_hops;
                match resolve(peer, 1, &r, &Fields(&fields)) {
                    Err(_) => prop_assert!(peer_trusted, "an untrusted peer is never refused"),
                    Ok(found) => {
                        prop_assert!(usize::from(found.hops) <= usize::from(max_hops));
                        if let Some(client) = found.client {
                            let text: String = owned
                                .iter()
                                .map(|(_, v)| String::from_utf8_lossy(v).to_ascii_lowercase())
                                .collect::<Vec<_>>()
                                .join(",");
                            let from_input = forms_of(client).iter().any(|f| text.contains(&f.to_ascii_lowercase()));
                            prop_assert!(client == peer || from_input, "{} is neither the peer nor in the input", client);
                            if !peer_trusted {
                                prop_assert_eq!(client, peer);
                            }
                        }
                    }
                }
            }

            /// Arbitrary bytes in every forwarding field never panic, and an
            /// accepted host is always a valid authority.
            #[test]
            fn test_walk_arbitrary_bytes_never_panic(
                xff in proptest::collection::vec(any::<u8>(), 0..300),
                fwd in proptest::collection::vec(any::<u8>(), 0..300),
                proto in proptest::collection::vec(any::<u8>(), 0..40),
                host in proptest::collection::vec(any::<u8>(), 0..300),
            ) {
                let trusted = TrustedProxies::loopback();
                for source in [ForwardedSource::XForwardedFor, ForwardedSource::Forwarded, ForwardedSource::SingleAddress("x-real-ip")] {
                    let mut r = rules(source, &trusted);
                    r.trust_scheme = true;
                    r.trust_host = true;
                    let fields: Vec<(&str, &[u8])> = vec![
                        ("x-forwarded-for", &xff),
                        ("forwarded", &fwd),
                        ("x-real-ip", &xff),
                        ("x-forwarded-proto", &proto),
                        ("x-forwarded-host", &host),
                    ];
                    if let Ok(found) = resolve("127.0.0.1".parse().unwrap(), 1, &r, &Fields(&fields)) {
                        if let Some(h) = found.host {
                            prop_assert!(valid_authority(h.as_bytes()));
                        }
                    }
                }
            }
        }
    }
}
