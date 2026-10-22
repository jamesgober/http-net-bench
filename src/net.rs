//! The http-net side of each workload.

use std::hint::black_box;

use http_net::{
    Asked, ClientConn, ClientEvent, FieldSpan, HttpError, Limits, Parsed, Request, Response,
    ServerConn, ServerEvent, parse_request_head, parse_response_head,
};

use crate::framing::Framing;

/// What a head parse answered, in a form both sides produce: the bench
/// returns it (through `black_box`) and the equivalence test compares it.
///
/// The method and target are offsets into the parsed input (both parsers
/// return borrowed views of it), read back with [`HeadSummary::method`] and
/// [`HeadSummary::target`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadSummary {
    /// The method's offset and length in the input.
    pub method_at: (usize, usize),
    /// The request target's offset and length in the input.
    pub target_at: (usize, usize),
    /// Fields parsed.
    pub fields: usize,
    /// Bytes of input the head took.
    pub len: usize,
    /// How the body is framed.
    pub framing: Framing,
    /// Whether the connection stays open.
    pub keep_alive: bool,
    /// Whether `host` is present.
    pub host_present: bool,
}

impl HeadSummary {
    /// The method, from the `input` that was parsed.
    #[must_use]
    pub fn method<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        &input[self.method_at.0..self.method_at.0 + self.method_at.1]
    }

    /// The request target, from the `input` that was parsed.
    #[must_use]
    pub fn target<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        &input[self.target_at.0..self.target_at.0 + self.target_at.1]
    }
}

/// Where `part` (a view the parser returned) sits inside `input`.
#[inline]
pub(crate) fn offset_in(input: &[u8], part: &str) -> (usize, usize) {
    (
        (part.as_ptr() as usize).wrapping_sub(input.as_ptr() as usize),
        part.len(),
    )
}

/// H1, http-net: the stateless Tier-3 parser into the caller's field array,
/// then the framing facts read from the view.
///
/// # Errors
///
/// The parse error, or [`HttpError::UnexpectedEof`] for a partial head.
#[inline]
pub fn parse_head(
    input: &[u8],
    limits: &Limits,
    fields: &mut [FieldSpan],
) -> Result<HeadSummary, HttpError> {
    match parse_request_head(input, limits, fields)? {
        Parsed::Complete { head, len } => {
            let view = head.view();
            Ok(HeadSummary {
                method_at: offset_in(input, view.method_str()),
                target_at: offset_in(input, view.target()),
                fields: view.headers().len(),
                len,
                framing: view.framing().into(),
                keep_alive: view.keep_alive(),
                host_present: view.host().is_some(),
            })
        }
        _ => Err(HttpError::UnexpectedEof),
    }
}

/// H1 reference, http-net: the same head through a reused [`ServerConn`]
/// (buffer copy, resumable scanner, connection state), read up to the head
/// event, then [`ServerConn::reset`] for the next iteration. Returns
/// `(fields, framing, keep_alive, host_present)`.
///
/// # Errors
///
/// The parse error, or [`HttpError::UnexpectedEof`] if no head came out.
#[inline]
pub fn server_conn_head(
    conn: &mut ServerConn,
    input: &[u8],
) -> Result<(usize, Framing, bool, bool), HttpError> {
    let _ = conn.feed(input);
    let out = match conn.poll()? {
        ServerEvent::Request(req) => Ok((
            req.headers().len(),
            req.framing().into(),
            req.keep_alive(),
            req.host().is_some(),
        )),
        _ => Err(HttpError::UnexpectedEof),
    };
    conn.reset();
    out
}

/// Drives a server connection over `input` in `read`-sized pieces,
/// answering every request with `response` into `out` (cleared per
/// response, so it holds the last one). Returns the request count. The same
/// driver as http-net's own `benches/bench.rs`.
pub fn serve_all(
    conn: &mut ServerConn,
    input: &[u8],
    read: usize,
    response: &Response,
    out: &mut Vec<u8>,
) -> usize {
    let mut pending = input;
    let mut requests = 0;
    loop {
        match conn.poll() {
            Ok(ServerEvent::Request(r)) => {
                black_box(r.path());
            }
            Ok(ServerEvent::Body(b)) => {
                black_box(b);
            }
            Ok(ServerEvent::RequestEnd) => {
                requests += 1;
                out.clear();
                conn.respond(response, out).unwrap_or_default();
            }
            Ok(ServerEvent::NeedInput) => {
                if pending.is_empty() {
                    return requests;
                }
                let take = pending.len().min(read);
                let n = conn.feed(&pending[..take]);
                pending = &pending[n..];
            }
            _ => return requests,
        }
    }
}

/// H2 variant, http-net: like [`serve_all`] for one request, but the
/// [`Response`] is built for each request (as a hyper service must build
/// its `http::Response`), from `fields` and a borrowed `body`.
pub fn serve_one_building(
    conn: &mut ServerConn,
    input: &[u8],
    fields: &[(&str, &str)],
    body: &'static [u8],
    out: &mut Vec<u8>,
) -> usize {
    let _ = conn.feed(input);
    loop {
        match conn.poll() {
            Ok(ServerEvent::Request(r)) => {
                black_box(r.path());
            }
            Ok(ServerEvent::RequestEnd) => {
                out.clear();
                let mut response = Response::new(200);
                for (name, value) in fields {
                    response = response.header(name, value);
                }
                conn.respond(&response.body(body), out).unwrap_or_default();
                return 1;
            }
            _ => return 0,
        }
    }
}

/// H3, http-net: the stateless response parser plus its framing facts.
/// Returns `(status, fields, len, framing, keep_alive)`.
///
/// # Errors
///
/// The parse error, or [`HttpError::UnexpectedEof`] for a partial head.
#[inline]
pub fn parse_response(
    input: &[u8],
    limits: &Limits,
    fields: &mut [FieldSpan],
) -> Result<(u16, usize, usize, Framing, bool), HttpError> {
    match parse_response_head(input, limits, Asked::default(), fields)? {
        Parsed::Complete { head, len } => {
            let view = head.view();
            Ok((
                view.status(),
                view.headers().len(),
                len,
                view.framing().into(),
                view.keep_alive(),
            ))
        }
        _ => Err(HttpError::UnexpectedEof),
    }
}

/// H3, http-net: a full client exchange on a reused [`ClientConn`]: the
/// request serialized into `out`, the response bytes fed, the events polled
/// to the end of the body (as http-net's own `response_parse` bench). Body
/// runs go to `sink`. Returns the status.
pub fn client_exchange(
    conn: &mut ClientConn,
    request: &Request,
    wire: &[u8],
    out: &mut Vec<u8>,
    mut sink: impl FnMut(&[u8]),
) -> u16 {
    out.clear();
    conn.send_request(request, out).unwrap_or_default();
    let _ = conn.feed(wire);
    let mut status = 0;
    loop {
        match conn.poll() {
            Ok(ClientEvent::Response(head)) => status = head.status(),
            Ok(ClientEvent::Body(b)) => sink(b),
            Ok(ClientEvent::ResponseEnd) | Err(_) => break,
            Ok(_) => {}
        }
    }
    // Back to idle, ready for the next request (http-net's bench does the
    // same extra poll).
    black_box(conn.poll().is_ok());
    status
}
