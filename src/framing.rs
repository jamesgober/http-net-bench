//! The framing pass that runs after `httparse` (workloads H1 and H3).
//!
//! `httparse` stops at syntax: it splits the start line and the fields and
//! validates their characters. http-net's `parse_request_head` and
//! `parse_response_head` also interpret the head: they decide how the body
//! is framed, whether the connection stays open, and whether the head is
//! acceptable at all. A bench that timed `httparse` alone would compare
//! unequal work, so the httparse side of H1 and H3 runs this pass after the
//! parse.
//!
//! # What the pass does
//!
//! It is shaped like hyper's role code (`proto::h1::role`, `Server::parse`
//! and `Client::parse`): one walk over the parsed fields with a match on the
//! name, then the framing decision. The rules applied are http-net's
//! (RFC 9112 section 6, strict), not hyper's, so that both sides do the same
//! checks, no more and no less:
//!
//! 1. Method: classified into a small enum by exact match on its bytes
//!    (as `http_net::Method::from_bytes` does; hyper does the same).
//! 2. Target: validated as http-net validates an origin-form target: every
//!    byte in the RFC 3986 set and every `%` followed by two hex digits.
//!    `httparse` has already checked a looser byte set; the percent-escape
//!    check is the part it does not do. Targets that do not start with `/`
//!    are classified by their first byte only (no bench input uses them).
//! 3. Fields, one pass, names compared ASCII case-insensitively in this
//!    order (the order http-net uses):
//!    - `content-length`: a second one is an error (hyper accepts an equal
//!      duplicate; http-net does not), the value must be `1*DIGIT` with no
//!      list, sign, or overflow.
//!    - `transfer-encoding`: split as a list (quoted strings respected);
//!      each coding must be a token; `chunked` may not carry parameters,
//!      may appear once, and must be last; any other coding is unsupported.
//!    - `connection`: list elements `close`, `keep-alive`, `upgrade`.
//!    - `upgrade`: whether any offered protocol is something other than
//!      `h2c`.
//!    - `host`: counted, and its value kept.
//!    - `expect`: `100-continue` versus any other expectation.
//! 4. Framing: a `transfer-encoding` in HTTP/1.0 is an error, as is one next
//!    to a `content-length` (hyper drops the length instead); otherwise
//!    chunked, a length (checked against the body budget), or no body.
//!    Responses also apply the status rules (1xx, 204, 304, a response to
//!    HEAD) and read to close when nothing delimits the body.
//! 5. Requests: more than one `host`, or a `host` value that is not
//!    `uri-host [":" port]`, is an error; HTTP/1.1 without `host` is an
//!    error (hyper does not check `host` at all).
//! 6. Keep-alive: HTTP/1.1 unless `close`; HTTP/1.0 only with `keep-alive`
//!    and no `close`. Upgrade and `Expect: 100-continue` as http-net
//!    decides them.
//!
//! What it does not do, because `httparse` already did it during the parse:
//! validate field names (tokens) and field values (no control bytes), find
//! line ends, refuse bare CR, obsolete line folding, and whitespace before
//! a colon. http-net does those during its own scan.
//!
//! `tests/equivalence.rs` runs this pass and http-net on the bench inputs
//! and on a set of malformed heads, and checks that both agree.

use httparse::Header;

/// How a message's body is delimited: the common form both sides are
/// compared in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// Exactly this many bytes.
    Length(u64),
    /// Chunked.
    Chunked,
    /// Until the peer closes (responses only).
    UntilClose,
}

impl From<http_net::BodyFraming> for Framing {
    fn from(f: http_net::BodyFraming) -> Self {
        match f {
            http_net::BodyFraming::None => Self::None,
            http_net::BodyFraming::Length(n) => Self::Length(n),
            http_net::BodyFraming::Chunked => Self::Chunked,
            http_net::BodyFraming::UntilClose => Self::UntilClose,
            // `BodyFraming` is non-exhaustive; 0.9 has exactly the four.
            _ => unreachable!("a BodyFraming variant http-net 0.9 does not have"),
        }
    }
}

/// Why the framing pass refused a head. The variants mirror the
/// `http_net::HttpError` variants the same rule produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramingError {
    /// The method is not a token.
    InvalidMethod,
    /// The target is not valid for its form.
    InvalidTarget,
    /// The HTTP version is not 1.0 or 1.1.
    UnsupportedVersion,
    /// The status code is outside 100..=599.
    InvalidStatus,
    /// Two `content-length` fields.
    DuplicateContentLength,
    /// A `content-length` that is not `1*DIGIT` in range.
    InvalidContentLength,
    /// A malformed `transfer-encoding`, or one that does not end in
    /// `chunked`.
    InvalidTransferEncoding,
    /// A transfer coding other than `chunked`.
    UnsupportedTransferEncoding,
    /// `transfer-encoding` and `content-length` together.
    ConflictingFraming,
    /// `transfer-encoding` in an HTTP/1.0 message.
    TransferEncodingInHttp10,
    /// The declared length exceeds the body budget.
    BodyTooLarge,
    /// More than one `host`, or an invalid `host` value.
    InvalidHost,
    /// An HTTP/1.1 request without `host`.
    MissingHost,
}

/// The method, classified (as `http_net::Method`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// CONNECT
    Connect,
    /// OPTIONS
    Options,
    /// TRACE
    Trace,
    /// PATCH
    Patch,
    /// Any other token.
    Other,
}

impl Method {
    #[inline]
    fn from_bytes(token: &[u8]) -> Self {
        match token {
            b"GET" => Self::Get,
            b"HEAD" => Self::Head,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"CONNECT" => Self::Connect,
            b"OPTIONS" => Self::Options,
            b"TRACE" => Self::Trace,
            b"PATCH" => Self::Patch,
            _ => Self::Other,
        }
    }
}

/// What the framing pass learned from a request head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestFacts {
    /// The method.
    pub method: Method,
    /// HTTP/1.1 (`true`) or HTTP/1.0.
    pub http11: bool,
    /// How the body is framed.
    pub framing: Framing,
    /// Whether the connection stays open after this exchange.
    pub keep_alive: bool,
    /// Whether a `host` field is present.
    pub host_present: bool,
    /// Whether the request is an upgrade offer http-net would honour.
    pub upgrade: bool,
    /// Whether the client waits for `100 Continue`.
    pub expect_continue: bool,
    /// Whether an `Expect` element other than `100-continue` is present.
    pub unknown_expectation: bool,
}

/// What the framing pass learned from a response head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseFacts {
    /// The status code.
    pub status: u16,
    /// How the body is framed.
    pub framing: Framing,
    /// Whether the connection stays open after this exchange.
    pub keep_alive: bool,
}

#[derive(Default)]
struct FieldFacts {
    content_length: Option<u64>,
    te_seen: bool,
    te_codings: usize,
    te_chunked: usize,
    te_last_chunked: bool,
    te_other: bool,
    close: bool,
    keep_alive: bool,
    upgrade_token: bool,
    upgrade_offer: bool,
    expect_continue: bool,
    expect_other: bool,
    hosts: usize,
    host: Option<usize>,
}

/// The framing pass for a request `httparse` parsed completely.
///
/// # Errors
///
/// The [`FramingError`] for the first rule the head breaks.
///
/// # Panics
///
/// If `req` is not a complete parse (its method, path, or version is
/// missing).
#[inline]
pub fn request_framing(
    req: &httparse::Request<'_, '_>,
    max_body: u64,
) -> Result<RequestFacts, FramingError> {
    let (Some(method_str), Some(target), Some(minor)) = (req.method, req.path, req.version) else {
        panic!("request_framing needs a complete parse");
    };
    let http11 = match minor {
        1 => true,
        0 => false,
        _ => return Err(FramingError::UnsupportedVersion),
    };
    let method = Method::from_bytes(method_str.as_bytes());
    check_target(method, target.as_bytes())?;

    let facts = scan_fields(req.headers)?;
    let framing = match transfer_framing(&facts, http11)? {
        Some(f) => f,
        None => match facts.content_length {
            Some(n) if n > max_body => return Err(FramingError::BodyTooLarge),
            Some(0) | None => Framing::None,
            Some(n) => Framing::Length(n),
        },
    };
    if facts.hosts > 1 {
        return Err(FramingError::InvalidHost);
    }
    match facts.host {
        Some(i) => {
            if !is_host_value(req.headers[i].value) {
                return Err(FramingError::InvalidHost);
            }
        }
        None if http11 => return Err(FramingError::MissingHost),
        None => {}
    }
    let keep_alive = if http11 {
        !facts.close
    } else {
        facts.keep_alive && !facts.close
    };
    Ok(RequestFacts {
        method,
        http11,
        framing,
        keep_alive,
        host_present: facts.host.is_some(),
        upgrade: http11 && facts.upgrade_token && facts.upgrade_offer,
        expect_continue: http11 && facts.expect_continue && framing != Framing::None,
        unknown_expectation: facts.expect_other,
    })
}

/// The framing pass for a response `httparse` parsed completely, to a
/// request that was `HEAD` when `asked_head` is true.
///
/// # Errors
///
/// The [`FramingError`] for the first rule the head breaks.
///
/// # Panics
///
/// If `resp` is not a complete parse.
#[inline]
pub fn response_framing(
    resp: &httparse::Response<'_, '_>,
    asked_head: bool,
    max_body: u64,
) -> Result<ResponseFacts, FramingError> {
    let (Some(minor), Some(status)) = (resp.version, resp.code) else {
        panic!("response_framing needs a complete parse");
    };
    let http11 = match minor {
        1 => true,
        0 => false,
        _ => return Err(FramingError::UnsupportedVersion),
    };
    if !(100..=599).contains(&status) {
        return Err(FramingError::InvalidStatus);
    }
    let facts = scan_fields(resp.headers)?;
    let bodiless = asked_head || (100..200).contains(&status) || status == 204 || status == 304;
    let framing = if bodiless {
        Framing::None
    } else {
        match transfer_framing(&facts, http11)? {
            Some(f) => f,
            None => match facts.content_length {
                Some(n) if n > max_body => return Err(FramingError::BodyTooLarge),
                Some(0) => Framing::None,
                Some(n) => Framing::Length(n),
                None => Framing::UntilClose,
            },
        }
    };
    let keep_alive = framing != Framing::UntilClose
        && if http11 {
            !facts.close
        } else {
            facts.keep_alive && !facts.close
        };
    Ok(ResponseFacts {
        status,
        framing,
        keep_alive,
    })
}

#[inline]
fn scan_fields(headers: &[Header<'_>]) -> Result<FieldFacts, FramingError> {
    let mut facts = FieldFacts::default();
    for (i, field) in headers.iter().enumerate() {
        let name = field.name.as_bytes();
        let value = field.value;
        if name.eq_ignore_ascii_case(b"content-length") {
            if facts.content_length.is_some() {
                return Err(FramingError::DuplicateContentLength);
            }
            facts.content_length =
                Some(parse_decimal(value).ok_or(FramingError::InvalidContentLength)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            facts.te_seen = true;
            for element in list_elements(value) {
                let (coding, params) = match element.iter().position(|&b| b == b';') {
                    Some(at) => (trim_ows(&element[..at]), true),
                    None => (element, false),
                };
                if !is_token(coding) {
                    return Err(FramingError::InvalidTransferEncoding);
                }
                facts.te_codings += 1;
                if coding.eq_ignore_ascii_case(b"chunked") {
                    if params {
                        return Err(FramingError::InvalidTransferEncoding);
                    }
                    facts.te_chunked += 1;
                    facts.te_last_chunked = true;
                } else {
                    facts.te_other = true;
                    facts.te_last_chunked = false;
                }
            }
        } else if name.eq_ignore_ascii_case(b"connection") {
            for token in list_elements(value) {
                if token.eq_ignore_ascii_case(b"close") {
                    facts.close = true;
                } else if token.eq_ignore_ascii_case(b"keep-alive") {
                    facts.keep_alive = true;
                } else if token.eq_ignore_ascii_case(b"upgrade") {
                    facts.upgrade_token = true;
                }
            }
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            facts.upgrade_offer |= list_elements(value).any(|e| !is_h2c(e));
        } else if name.eq_ignore_ascii_case(b"host") {
            facts.hosts += 1;
            facts.host = Some(i);
        } else if name.eq_ignore_ascii_case(b"expect") {
            for e in list_elements(value) {
                if e.eq_ignore_ascii_case(b"100-continue") {
                    facts.expect_continue = true;
                } else {
                    facts.expect_other = true;
                }
            }
        }
    }
    Ok(facts)
}

#[inline]
fn transfer_framing(facts: &FieldFacts, http11: bool) -> Result<Option<Framing>, FramingError> {
    if !facts.te_seen {
        return Ok(None);
    }
    if !http11 {
        return Err(FramingError::TransferEncodingInHttp10);
    }
    if facts.content_length.is_some() {
        return Err(FramingError::ConflictingFraming);
    }
    if facts.te_codings == 0 || facts.te_chunked > 1 || !facts.te_last_chunked {
        return Err(FramingError::InvalidTransferEncoding);
    }
    if facts.te_other {
        return Err(FramingError::UnsupportedTransferEncoding);
    }
    Ok(Some(Framing::Chunked))
}

#[inline]
fn check_target(method: Method, target: &[u8]) -> Result<(), FramingError> {
    let ok = match target.first() {
        None => false,
        Some(b'/') => method != Method::Connect && is_target_chars(target),
        Some(b'*') if target.len() == 1 => method == Method::Options,
        // Authority and absolute forms: not exercised by any bench input.
        Some(_) => true,
    };
    if ok {
        Ok(())
    } else {
        Err(FramingError::InvalidTarget)
    }
}

#[inline]
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[inline]
fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| is_tchar(b))
}

#[inline]
fn is_target_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'?'
                | b'%'
        )
}

#[inline]
fn is_target_chars(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if !is_target_byte(b) {
            return false;
        }
        if b == b'%' {
            match (s.get(i + 1), s.get(i + 2)) {
                (Some(h1), Some(h2)) if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() => i += 3,
                _ => return false,
            }
        } else {
            i += 1;
        }
    }
    true
}

#[inline]
fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

#[inline]
fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if is_ows(*first) {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if is_ows(*last) {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[inline]
fn parse_decimal(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(n)
}

fn is_h2c(protocol: &[u8]) -> bool {
    let name = protocol
        .iter()
        .position(|&b| b == b'/')
        .map_or(protocol, |i| &protocol[..i]);
    name.eq_ignore_ascii_case(b"h2c")
}

/// `uri-host [":" port]`, possibly empty, as http-net checks it.
fn is_host_value(s: &[u8]) -> bool {
    if s.is_empty() {
        return true;
    }
    let (host, port) = if s[0] == b'[' {
        match s.iter().position(|&b| b == b']') {
            Some(close) => {
                let inner = &s[1..close];
                if inner.is_empty()
                    || !inner
                        .iter()
                        .all(|&b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.' | b'v' | b'V'))
                {
                    return false;
                }
                match &s[close + 1..] {
                    [] => (&s[..0], None),
                    [b':', port @ ..] => (&s[..0], Some(port)),
                    _ => return false,
                }
            }
            None => return false,
        }
    } else {
        match s.iter().rposition(|&b| b == b':') {
            Some(0) => return false,
            Some(colon) => (&s[..colon], Some(&s[colon + 1..])),
            None => (s, None),
        }
    };
    let mut i = 0;
    while let Some(off) = host[i..].iter().position(|&b| b == b'%') {
        let at = i + off;
        match (host.get(at + 1), host.get(at + 2)) {
            (Some(h1), Some(h2)) if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() => i = at + 3,
            _ => return false,
        }
    }
    let host_ok = host.iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    });
    let port_ok = port.is_none_or(|p| p.iter().all(u8::is_ascii_digit));
    host_ok && port_ok
}

/// The elements of a comma-separated list value: trimmed of OWS, empty
/// elements skipped, commas inside quoted strings not treated as
/// separators.
#[inline]
fn list_elements(value: &[u8]) -> ListSplit<'_> {
    ListSplit {
        rest: value,
        quoted: value.contains(&b'"'),
    }
}

struct ListSplit<'a> {
    rest: &'a [u8],
    quoted: bool,
}

impl<'a> Iterator for ListSplit<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<&'a [u8]> {
        while !self.rest.is_empty() {
            let end = if self.quoted {
                element_end(self.rest)
            } else {
                self.rest
                    .iter()
                    .position(|&b| b == b',')
                    .unwrap_or(self.rest.len())
            };
            let element = trim_ows(&self.rest[..end]);
            self.rest = self.rest.get(end + 1..).unwrap_or(&[]);
            if !element.is_empty() {
                return Some(element);
            }
        }
        None
    }
}

fn element_end(s: &[u8]) -> usize {
    let mut i = 0;
    let mut quoted = false;
    while i < s.len() {
        match s[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => i += 1,
            b',' if !quoted => return i,
            _ => {}
        }
        i += 1;
    }
    s.len()
}

/// Why the httparse side refused a head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// `httparse` refused the bytes.
    Parse(httparse::Error),
    /// The input ends before the head does.
    Partial,
    /// The framing pass refused the head.
    Framing(FramingError),
}

/// H1, httparse: `Request::parse` with the default (strict) configuration
/// into the caller's header array, then [`request_framing`].
///
/// # Errors
///
/// The [`HeadError`] for the parse or the framing pass.
#[inline]
pub fn httparse_head<'b>(
    input: &'b [u8],
    headers: &mut [Header<'b>],
    max_body: u64,
) -> Result<crate::net::HeadSummary, HeadError> {
    let mut req = httparse::Request::new(headers);
    let len = match req.parse(input) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Err(HeadError::Partial),
        Err(e) => return Err(HeadError::Parse(e)),
    };
    let facts = request_framing(&req, max_body).map_err(HeadError::Framing)?;
    let (Some(method), Some(target)) = (req.method, req.path) else {
        return Err(HeadError::Partial);
    };
    Ok(crate::net::HeadSummary {
        method_at: crate::net::offset_in(input, method),
        target_at: crate::net::offset_in(input, target),
        fields: req.headers.len(),
        len,
        framing: facts.framing,
        keep_alive: facts.keep_alive,
        host_present: facts.host_present,
    })
}

/// H3, httparse: `Response::parse` with the default configuration, then
/// [`response_framing`] (the request was not `HEAD`). Returns
/// `(status, fields, len, framing, keep_alive)`, as
/// [`crate::net::parse_response`] does.
///
/// # Errors
///
/// The [`HeadError`] for the parse or the framing pass.
#[inline]
pub fn httparse_response<'b>(
    input: &'b [u8],
    headers: &mut [Header<'b>],
    max_body: u64,
) -> Result<(u16, usize, usize, Framing, bool), HeadError> {
    let mut resp = httparse::Response::new(headers);
    let len = match resp.parse(input) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Err(HeadError::Partial),
        Err(e) => return Err(HeadError::Parse(e)),
    };
    let facts = response_framing(&resp, false, max_body).map_err(HeadError::Framing)?;
    Ok((
        facts.status,
        resp.headers.len(),
        len,
        facts.framing,
        facts.keep_alive,
    ))
}
