//! The HTTP/1.1 engine: an adapter over http-net's `ServerConn`.

use http_net::{
    HttpError, OutgoingBody, Progress, RequestHead, ResponseHeadRef, ServerConn, ServerEvent,
};

use crate::engine::{
    Engine, EngineError, EngineEvent, EngineProgress, OutBuf, Refusal, RefusalKind,
};

/// The HTTP/1.1 engine.
///
/// Adds no `Server` field; maps every http-net error to a refusal with the
/// error's status; zeroes each finished request's bytes when the profile
/// wipes buffers.
pub struct Http1 {
    pub(crate) conn: ServerConn,
    pub(crate) dates: http_net::DateCache,
}

impl Http1 {
    pub(crate) fn new(limits: http_net::Limits, wipe: bool) -> Self {
        let mut conn = ServerConn::with_limits(limits);
        conn.set_wipe(wipe);
        Http1 {
            conn,
            dates: http_net::DateCache::new(),
        }
    }
}

impl core::fmt::Debug for Http1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Http1").field("conn", &self.conn).finish()
    }
}

pub(crate) fn engine_error(e: HttpError) -> EngineError {
    let status = e.status().unwrap_or(400);
    let kind = match status {
        413 | 414 | 431 => RefusalKind::TooLarge,
        _ => RefusalKind::Malformed,
    };
    EngineError { kind, status }
}

impl Engine for Http1 {
    type Head<'a> = RequestHead<'a>;

    fn feed(&mut self, bytes: &[u8]) -> usize {
        self.conn.feed(bytes)
    }

    fn feed_eof(&mut self) {
        self.conn.feed_eof();
    }

    fn poll(&mut self) -> Result<EngineEvent<'_>, EngineError> {
        Ok(match self.conn.poll().map_err(engine_error)? {
            ServerEvent::Request(_) => EngineEvent::Head,
            ServerEvent::Body(bytes) => EngineEvent::Body(bytes),
            ServerEvent::RequestEnd => EngineEvent::BodyEnd,
            ServerEvent::NeedInput => EngineEvent::NeedInput,
            ServerEvent::AwaitingResponse => EngineEvent::AwaitingReply,
            ServerEvent::Upgraded => EngineEvent::Upgraded,
            ServerEvent::Closed => EngineEvent::Closed,
            // Trailers are reported only when asked for, which this engine
            // never does; any other event is one it does not know.
            _ => {
                return Err(EngineError {
                    kind: RefusalKind::Internal,
                    status: 500,
                });
            }
        })
    }

    fn head(&self) -> Option<RequestHead<'_>> {
        self.conn.request()
    }

    fn declared_length(&self) -> Option<u64> {
        self.conn.request().and_then(|h| h.content_length())
    }

    fn expects_continue(&self) -> bool {
        self.conn.request().is_some_and(|h| h.expects_continue())
    }

    fn head_len(&self) -> usize {
        self.conn.request().map_or(0, |h| h.raw().bytes().len())
    }

    fn progress(&self) -> EngineProgress {
        match self.conn.progress() {
            Progress::Idle => EngineProgress::Idle,
            Progress::Head => EngineProgress::Head,
            Progress::Body => EngineProgress::Body,
            Progress::AwaitingResponse => EngineProgress::AwaitingReply,
            Progress::WritingBody => EngineProgress::WritingReply,
            Progress::Upgraded => EngineProgress::Upgraded,
            _ => EngineProgress::Closed,
        }
    }

    fn send_continue(&mut self, out: &mut OutBuf) -> Result<(), EngineError> {
        self.conn
            .send_continue(&mut out.bytes)
            .map_err(engine_error)
    }

    fn refuse(&mut self, refusal: &Refusal, out: &mut OutBuf) {
        let status = if (400..=599).contains(&refusal.status) {
            refusal.status
        } else {
            500
        };
        let body = refusal_body(status);
        let mut digits = [0u8; 20];
        let retry = refusal
            .retry_after
            .map(|d| format_u64(d.as_secs().max(1), &mut digits));
        let with_retry: [(&str, &[u8]); 2] = [
            ("content-type", b"text/plain; charset=utf-8"),
            ("retry-after", retry.unwrap_or(b"")),
        ];
        let fields: &[(&str, &[u8])] = if retry.is_some() {
            &with_retry
        } else {
            &with_retry[..1]
        };
        let mut head = ResponseHeadRef::new(status, fields, OutgoingBody::Full(body.len() as u64));
        head.close = true;
        self.conn.set_keep_alive(false);
        let start = out.len();
        match self.conn.write_head(&head, None, out) {
            Ok(http_net::BodyPlan::Raw) => out.push(body),
            Ok(_) => {}
            Err(_) => {
                // No request to answer (a head that never completed, a cap
                // refusal before any byte): write the bytes directly.
                out.bytes.truncate(start);
                raw_refusal(status, retry, body, out);
            }
        }
    }

    fn close_after_reply(&mut self) {
        self.conn.set_keep_alive(false);
    }

    fn keep_alive(&self) -> bool {
        self.conn.keep_alive()
    }

    fn requests_served(&self) -> u64 {
        self.conn.requests_served()
    }

    fn remaining_input(&self) -> &[u8] {
        self.conn.remaining_input()
    }

    fn reset(&mut self) {
        self.conn.reset();
    }

    fn shrink_idle(&mut self) -> bool {
        self.conn.shrink_idle()
    }
}

/// The fixed body of a refusal: the status and its reason phrase, never the
/// internal reason.
pub(crate) fn refusal_body(status: u16) -> &'static [u8] {
    match status {
        400 => b"400 Bad Request\n",
        403 => b"403 Forbidden\n",
        404 => b"404 Not Found\n",
        405 => b"405 Method Not Allowed\n",
        408 => b"408 Request Timeout\n",
        413 => b"413 Content Too Large\n",
        414 => b"414 URI Too Long\n",
        417 => b"417 Expectation Failed\n",
        429 => b"429 Too Many Requests\n",
        431 => b"431 Request Header Fields Too Large\n",
        500 => b"500 Internal Server Error\n",
        501 => b"501 Not Implemented\n",
        502 => b"502 Bad Gateway\n",
        503 => b"503 Service Unavailable\n",
        504 => b"504 Gateway Timeout\n",
        505 => b"505 HTTP Version Not Supported\n",
        s if s < 500 => b"Client Error\n",
        _ => b"Server Error\n",
    }
}

fn format_u64(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

fn raw_refusal(status: u16, retry: Option<&[u8]>, body: &[u8], out: &mut OutBuf) {
    let mut digits = [0u8; 20];
    out.push(b"HTTP/1.1 ");
    out.push(format_u64(u64::from(status), &mut digits));
    out.push(b" ");
    out.push(http_net::reason_phrase(status).as_bytes());
    out.push(b"\r\ncontent-type: text/plain; charset=utf-8\r\n");
    if let Some(r) = retry {
        out.push(b"retry-after: ");
        out.push(r);
        out.push(b"\r\n");
    }
    out.push(b"content-length: ");
    out.push(format_u64(body.len() as u64, &mut digits));
    out.push(b"\r\nconnection: close\r\n\r\n");
    out.push(body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn engine() -> Http1 {
        Http1::new(http_net::Limits::new(), false)
    }

    #[test]
    fn test_http1_head_then_body_end() {
        let mut e = engine();
        let msg = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(e.feed(msg), msg.len());
        assert_eq!(e.poll(), Ok(EngineEvent::Head));
        assert_eq!(e.declared_length(), Some(2));
        assert_eq!(e.head().map(|h| h.path()), Some("/a"));
        assert_eq!(e.poll(), Ok(EngineEvent::Body(b"hi")));
        assert_eq!(e.poll(), Ok(EngineEvent::BodyEnd));
    }

    #[test]
    fn test_http1_parse_error_maps_status() {
        let mut e = engine();
        let _ = e.feed(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            e.poll(),
            Err(EngineError {
                kind: RefusalKind::Malformed,
                status: 400
            })
        );
        let mut out = OutBuf::new();
        e.refuse(
            &Refusal {
                kind: RefusalKind::Malformed,
                status: 400,
                retry_after: None,
            },
            &mut out,
        );
        let text = String::from_utf8_lossy(out.as_slice()).into_owned();
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(text.contains("connection: close"));
        assert!(text.ends_with("\r\n\r\n400 Bad Request\n"));
    }

    #[test]
    fn test_http1_refusal_without_request_is_raw() {
        let mut e = engine();
        let mut out = OutBuf::new();
        let mut r = Refusal {
            kind: RefusalKind::Busy,
            status: 503,
            retry_after: None,
        };
        r.retry_after = Some(Duration::from_secs(2));
        e.refuse(&r, &mut out);
        let text = String::from_utf8_lossy(out.as_slice()).into_owned();
        assert_eq!(
            text,
            "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=utf-8\r\nretry-after: 2\r\ncontent-length: 24\r\nconnection: close\r\n\r\n503 Service Unavailable\n"
        );
    }

    #[test]
    fn test_http1_refusal_status_out_of_range_becomes_500() {
        let mut e = engine();
        let mut out = OutBuf::new();
        e.refuse(
            &Refusal {
                kind: RefusalKind::Service,
                status: 399,
                retry_after: None,
            },
            &mut out,
        );
        assert!(out.as_slice().starts_with(b"HTTP/1.1 500 "));
    }

    #[test]
    fn test_http1_refusal_to_head_request_has_no_body() {
        let mut e = engine();
        let _ = e.feed(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(e.poll(), Ok(EngineEvent::Head));
        let mut out = OutBuf::new();
        e.refuse(
            &Refusal {
                kind: RefusalKind::Service,
                status: 403,
                retry_after: None,
            },
            &mut out,
        );
        assert!(out.as_slice().ends_with(b"\r\n\r\n"));
        assert!(out.as_slice().starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    }

    #[test]
    fn test_format_u64() {
        let mut b = [0u8; 20];
        assert_eq!(format_u64(0, &mut b), b"0");
        assert_eq!(format_u64(u64::MAX, &mut b), b"18446744073709551615");
    }
}
