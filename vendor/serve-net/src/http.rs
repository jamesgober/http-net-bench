//! The HTTP family: one request view and one reply for every HTTP ingress.

use core::fmt;
use std::time::Duration;

use http_net::{BodyPlan, Headers, Method, OutgoingBody, RequestHead, ResponseHeadRef, Version};

use crate::Finished;
use crate::client::{ClientInfo, IngressKind};
use crate::config::{Limits, Profile, ProxyKind};
use crate::engine::http1::engine_error;
use crate::engine::{EngineError, Family, HeadContext, Http1, OutBuf, RefusalKind, Service};
use crate::envelope::Envelope;
use crate::forwarded::{self, FieldLines, Lines, WalkError};
use crate::reply::Reply;
use crate::service::{HeadAction, Outcome, WorkClass};

/// The reply an HTTP service writes.
pub type HttpReply = Reply<HttpFamily>;

/// The HTTP family: HTTP/1.1 today, FastCGI and HTTP/2 later, all producing
/// [`HttpHead`], [`HttpRequest`], and [`HttpReply`].
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpFamily;

/// A request head, borrowed from the engine's buffer.
///
/// Every accessor is a slice of the bytes that arrived. `authority` is the
/// normalized authority: the trusted proxy's when `trust_host` is on, else
/// the absolute-form authority or the `Host` field.
#[derive(Clone, Copy)]
pub struct HttpHead<'a> {
    raw: RequestHead<'a>,
    client: ClientInfo,
    authority: Option<&'a str>,
}

impl<'a> HttpHead<'a> {
    /// The method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.raw.method()
    }

    /// The method exactly as received.
    #[must_use]
    pub fn method_str(&self) -> &'a str {
        self.raw.method_str()
    }

    /// The target exactly as received.
    #[must_use]
    pub fn target(&self) -> &'a str {
        self.raw.target()
    }

    /// The path, percent-encoding kept.
    #[must_use]
    pub fn path(&self) -> &'a str {
        self.raw.path()
    }

    /// The query, after the first `?`.
    #[must_use]
    pub fn query(&self) -> Option<&'a str> {
        self.raw.query()
    }

    /// The protocol version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.raw.version()
    }

    /// The first field with this name (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.raw.header(name)
    }

    /// The first field with this name, when it is UTF-8.
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&'a str> {
        self.raw.header_str(name)
    }

    /// Every field with this name, in order.
    pub fn header_all<'n>(&self, name: &'n str) -> impl Iterator<Item = &'a [u8]> + use<'a, 'n> {
        self.raw.header_all(name)
    }

    /// Every field in arrival order.
    #[must_use]
    pub fn headers(&self) -> Fields<'a> {
        Fields {
            inner: self.raw.headers(),
        }
    }

    /// The normalized authority.
    #[must_use]
    pub fn authority(&self) -> Option<&'a str> {
        self.authority
    }

    /// The request's client.
    #[must_use]
    pub fn client(&self) -> &ClientInfo {
        &self.client
    }

    /// The declared body length.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.raw.content_length()
    }

    /// Whether the client waits for `100 Continue` before its body.
    #[must_use]
    pub fn expects_continue(&self) -> bool {
        self.raw.expects_continue()
    }

    /// Whether the request offers an upgrade (never true for `h2c` alone).
    #[must_use]
    pub fn is_upgrade(&self) -> bool {
        self.raw.is_upgrade()
    }
}

impl fmt::Debug for HttpHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // http-net's Debug redacts credential fields.
        f.debug_struct("HttpHead")
            .field("head", &self.raw)
            .field("client", &self.client)
            .finish()
    }
}

/// Every field of a head in arrival order: `(name, value)`.
#[derive(Clone)]
pub struct Fields<'a> {
    inner: Headers<'a>,
}

impl<'a> Iterator for Fields<'a> {
    type Item = (&'a str, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Fields<'_> {}

/// The request body.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpBody<'a> {
    /// No body.
    Empty,
    /// The whole buffered body.
    Full(&'a [u8]),
}

impl<'a> HttpBody<'a> {
    /// The body bytes (empty for `Empty`).
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            HttpBody::Empty => &[],
            HttpBody::Full(b) => b,
        }
    }
}

/// The request an HTTP service answers.
#[derive(Clone, Copy)]
pub struct HttpRequest<'a> {
    head: HttpHead<'a>,
    body: &'a [u8],
}

impl<'a> HttpRequest<'a> {
    /// The head.
    #[must_use]
    pub fn head(&self) -> &HttpHead<'a> {
        &self.head
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.head.method()
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &'a str {
        self.head.path()
    }

    /// The query.
    #[must_use]
    pub fn query(&self) -> Option<&'a str> {
        self.head.query()
    }

    /// The first field with this name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.head.header(name)
    }

    /// The request's client.
    #[must_use]
    pub fn client(&self) -> &ClientInfo {
        self.head.client()
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> HttpBody<'a> {
        if self.body.is_empty() {
            HttpBody::Empty
        } else {
            HttpBody::Full(self.body)
        }
    }

    /// The buffered body bytes, or empty.
    #[must_use]
    pub fn body_bytes(&self) -> &'a [u8] {
        self.body
    }
}

impl fmt::Debug for HttpRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("head", &self.head)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The most fields one reply may carry; more turns it into the 500 refusal.
const MAX_FIELDS: usize = 64;

/// The HTTP family's reply data. Services use [`HttpReply`]'s methods.
#[derive(Default)]
pub struct HttpParts {
    status: u16,
    names: Vec<u8>,
    values: Vec<u8>,
    spans: Vec<(u32, u32, u32, u32)>,
    body: Vec<u8>,
    body_static: Option<&'static [u8]>,
    close: bool,
    retry_after: Option<u64>,
    invalid: bool,
}

impl HttpParts {
    fn clear(&mut self, wipe: bool) {
        if wipe {
            crate::engine::wipe_bytes(&mut self.values);
            crate::engine::wipe_bytes(&mut self.body);
        }
        self.status = 0;
        self.names.clear();
        self.values.clear();
        self.spans.clear();
        self.body.clear();
        self.body_static = None;
        self.close = false;
        self.retry_after = None;
        self.invalid = false;
    }
}

impl fmt::Debug for HttpParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Field values may hold credentials (set-cookie): only names and sizes.
        let names: Vec<&str> = self
            .spans
            .iter()
            .map(|&(s, e, _, _)| {
                core::str::from_utf8(&self.names[s as usize..e as usize]).unwrap_or("?")
            })
            .collect();
        f.debug_struct("HttpParts")
            .field("status", &self.status)
            .field("fields", &names)
            .field(
                "body_len",
                &self.body_static.map_or(self.body.len(), <[u8]>::len),
            )
            .finish()
    }
}

impl Reply<HttpFamily> {
    /// Sets the status (default 200).
    pub fn status(&mut self, status: u16) -> &mut Self {
        self.parts.status = status;
        self
    }

    /// Adds a field. An invalid name or value (a CR or LF, a control byte, a
    /// framing field such as `content-length`) turns the reply into the 500
    /// refusal when it is written.
    pub fn header(&mut self, name: &str, value: impl AsRef<[u8]>) -> &mut Self {
        let p = &mut self.parts;
        if p.spans.len() >= MAX_FIELDS {
            p.invalid = true;
            return self;
        }
        let value = value.as_ref();
        let (ns, vs) = (p.names.len() as u32, p.values.len() as u32);
        p.names.extend_from_slice(name.as_bytes());
        p.values.extend_from_slice(value);
        p.spans
            .push((ns, p.names.len() as u32, vs, p.values.len() as u32));
        self
    }

    /// Sets the body, copied into the reply's reused buffer.
    pub fn body(&mut self, bytes: &[u8]) -> &mut Self {
        let p = &mut self.parts;
        p.body.clear();
        p.body.extend_from_slice(bytes);
        p.body_static = None;
        self
    }

    /// Sets a static body, not copied.
    pub fn body_static(&mut self, bytes: &'static [u8]) -> &mut Self {
        self.parts.body.clear();
        self.parts.body_static = Some(bytes);
        self
    }

    /// Status, `content-type: text/plain; charset=utf-8`, and the text as body.
    pub fn text(&mut self, status: u16, text: &str) -> &mut Self {
        self.status(status)
            .header("content-type", "text/plain; charset=utf-8")
            .body(text.as_bytes())
    }

    /// Status, `content-type: text/html; charset=utf-8`, and the HTML as body.
    pub fn html(&mut self, status: u16, html: &str) -> &mut Self {
        self.status(status)
            .header("content-type", "text/html; charset=utf-8")
            .body(html.as_bytes())
    }

    /// Ends the connection after this reply.
    pub fn close(&mut self) -> &mut Self {
        self.parts.close = true;
        self
    }

    /// Adds `Retry-After` in whole seconds (at least 1).
    pub fn retry_after(&mut self, after: Duration) -> &mut Self {
        self.parts.retry_after = Some(after.as_secs().max(1));
        self
    }
}

/// Reads forwarding fields from an http-net head.
impl<'h> FieldLines<'h> for RequestHead<'h> {
    fn field_lines(&self, name: &str, out: &mut Lines<'h>) -> Result<(), WalkError> {
        for v in self.header_all(name) {
            out.push(v)?;
        }
        Ok(())
    }
}

impl Family for HttpFamily {
    type Engine = Http1;
    type Head<'a> = HttpHead<'a>;
    type Request<'a> = HttpRequest<'a>;
    type Parts = HttpParts;

    fn engine(&self, profile: &Profile, limits: &Limits) -> Http1 {
        let engine_limits = limits
            .engine
            .with_max_body(limits.max_body.min(limits.engine.max_body()));
        Http1::new(engine_limits, profile.wipe_buffers)
    }

    fn head<'a>(
        &self,
        raw: RequestHead<'a>,
        cx: &HeadContext<'_>,
    ) -> Result<(HttpHead<'a>, ClientInfo), EngineError>
    where
        Self: 'a,
    {
        let base = *cx.client;
        let ingress_error = EngineError {
            kind: RefusalKind::Ingress,
            status: 400,
        };
        let Some(proxy) = cx.proxy else {
            return Ok((
                HttpHead {
                    raw,
                    client: base,
                    authority: raw.host(),
                },
                base,
            ));
        };
        match proxy.kind {
            ProxyKind::Headers(source) => {
                if let Some(client) = cx.resolved {
                    // Built again for the call: the walk already ran at the head.
                    let host = if proxy.trust_host {
                        forwarded::trusted_host(source, &raw)
                    } else {
                        None
                    };
                    let authority = host.or_else(|| raw.host());
                    return Ok((
                        HttpHead {
                            raw,
                            client,
                            authority,
                        },
                        client,
                    ));
                }
                let peer = base.peer().ok_or(ingress_error)?;
                let rules = forwarded::Rules {
                    source,
                    trusted: &proxy.trusted,
                    max_hops: proxy.max_hops,
                    missing: proxy.missing,
                    unknown: proxy.unknown,
                    trust_scheme: proxy.trust_scheme,
                    trust_host: proxy.trust_host,
                };
                let found = forwarded::resolve(peer.ip(), peer.port(), &rules, &raw)
                    .map_err(|_| ingress_error)?;
                let client = if found.forwarded {
                    base.behind_proxy(found.client, found.port, found.hops, IngressKind::Forwarded)
                        .with_scheme(found.scheme.unwrap_or(cx.declared_scheme))
                } else {
                    base
                };
                let authority = found.host.or_else(|| raw.host());
                Ok((
                    HttpHead {
                        raw,
                        client,
                        authority,
                    },
                    client,
                ))
            }
            ProxyKind::ProxyProtocol(_) => {
                let client = base.with_scheme(cx.declared_scheme);
                Ok((
                    HttpHead {
                        raw,
                        client,
                        authority: raw.host(),
                    },
                    client,
                ))
            }
        }
    }

    fn request<'a>(&self, head: HttpHead<'a>, body: &'a [u8]) -> HttpRequest<'a> {
        HttpRequest { head, body }
    }

    fn new_parts(&self) -> HttpParts {
        HttpParts::default()
    }

    fn clear_parts(&self, parts: &mut HttpParts, wipe: bool) {
        parts.clear(wipe);
    }

    fn respond(
        &self,
        engine: &mut Http1,
        parts: &mut HttpParts,
        unix_secs: u64,
        out: &mut OutBuf,
    ) -> Result<u16, EngineError> {
        if parts.invalid {
            return Err(EngineError {
                kind: RefusalKind::Internal,
                status: 500,
            });
        }
        let status = if parts.status == 0 { 200 } else { parts.status };
        let mut fields: [(&str, &[u8]); MAX_FIELDS + 1] = [("", &[]); MAX_FIELDS + 1];
        let mut n = 0;
        for &(ns, ne, vs, ve) in &parts.spans {
            let Ok(name) = core::str::from_utf8(&parts.names[ns as usize..ne as usize]) else {
                return Err(EngineError {
                    kind: RefusalKind::Internal,
                    status: 500,
                });
            };
            fields[n] = (name, &parts.values[vs as usize..ve as usize]);
            n += 1;
        }
        let mut digits = [0u8; 20];
        if let Some(secs) = parts.retry_after {
            fields[n] = ("retry-after", format_secs(secs, &mut digits));
            n += 1;
        }
        let body: &[u8] = match parts.body_static {
            Some(b) => b,
            None => &parts.body,
        };
        let mut head = ResponseHeadRef::new(
            status,
            &fields[..n],
            if body.is_empty() {
                OutgoingBody::Empty
            } else {
                OutgoingBody::Full(body.len() as u64)
            },
        );
        head.close = parts.close;
        let date = engine.dates.update(unix_secs);
        let start = out.len();
        match engine.conn.write_head(&head, Some(date), out) {
            Ok(BodyPlan::Raw) => {
                out.push(body);
                Ok(status)
            }
            Ok(_) => Ok(status),
            Err(e) => {
                out.bytes.truncate(start);
                let mut err = engine_error(e);
                err.kind = RefusalKind::Internal;
                err.status = 500;
                Err(err)
            }
        }
    }
}

fn format_secs(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
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

/// The contract between serve-net and an HTTP service, in the order serve-net
/// calls it per request: `head`, then (after admission) `call`, then `done`.
pub trait HttpService: Send + Sync {
    /// How the service behaves.
    const WORK: WorkClass = WorkClass::Quick;

    /// The head is complete; before admission and before any body byte.
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        let _ = (head, env);
        HeadAction::Proceed
    }

    /// The request is complete.
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome;

    /// Exactly once per request that reached `head`, on every path.
    fn done(&self, env: &Envelope, finished: &Finished) {
        let _ = (env, finished);
    }
}

impl<S: HttpService> Service<HttpFamily> for S {
    const WORK: WorkClass = <S as HttpService>::WORK;
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        HttpService::head(self, head, env)
    }
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        HttpService::call(self, request, env, reply)
    }
    fn done(&self, env: &Envelope, finished: &Finished) {
        HttpService::done(self, env, finished);
    }
}

/// A closure as an [`HttpService`].
pub struct Handler<F> {
    f: F,
}

/// Starts an HTTP/1.1 server and returns it running: one direct TCP listener
/// per resolved address (`http-0`, `http-1`, ...), the default limits,
/// keep-alive, workers, and hooks, and net-io's `AllowAll` gate.
///
/// ```no_run
/// let server = serve_net::http("127.0.0.1:8080", |req, reply| {
///     match req.path() {
///         "/" => { reply.html(200, "<h1>It works</h1>"); }
///         _ => { reply.text(404, "not found"); }
///     }
/// })?;
/// server.wait();
/// # Ok::<(), serve_net::ServeError>(())
/// ```
///
/// # Errors
///
/// [`ServeError::Bind`](crate::ServeError::Bind) naming the address;
/// [`ServeError::Config`](crate::ServeError::Config) with
/// `RuleId::AddressResolve` when the address resolved to nothing.
pub fn http<A, F>(addr: A, handler: F) -> Result<crate::Running, crate::ServeError>
where
    A: std::net::ToSocketAddrs,
    F: Fn(&HttpRequest<'_>, &mut HttpReply) + Send + Sync + 'static,
{
    tier1(addr, None, handler)
}

/// As [`http`], behind a reverse proxy on the same host: the real client
/// comes from `X-Forwarded-For`, walked right to left and believed only when
/// the socket peer is in `trusted` (addresses and CIDR blocks separated by
/// commas or whitespace, `"127.0.0.1, ::1"`). A trusted peer that sends no
/// `X-Forwarded-For` is refused with 400; scheme and host are not taken from
/// the proxy (Tier 2 has `trust_scheme` and `trust_host`).
///
/// ```
/// // Refused at start-up: a trusting listener on every interface.
/// let err = serve_net::http_behind_proxy("0.0.0.0:8080", "127.0.0.1", |_req, reply| {
///     reply.text(200, "x");
/// })
/// .unwrap_err();
/// assert!(err.to_string().contains("public"));
/// ```
///
/// # Errors
///
/// As [`http`], plus [`ServeError::Config`](crate::ServeError::Config) with
/// `RuleId::PublicBind`, `TrustParse`, `TrustEmpty`, `TrustTooBroad`, or
/// `TrustWildcard`.
pub fn http_behind_proxy<A, F>(
    addr: A,
    trusted: &str,
    handler: F,
) -> Result<crate::Running, crate::ServeError>
where
    A: std::net::ToSocketAddrs,
    F: Fn(&HttpRequest<'_>, &mut HttpReply) + Send + Sync + 'static,
{
    use crate::error::{ConfigError, ConfigErrors, RuleId, Subject};
    let trusted = crate::TrustedProxies::parse(trusted).map_err(|e| {
        let error = match e {
            crate::AddrError::Empty => ConfigError::new(
                RuleId::TrustEmpty,
                Subject::Listener("http-0".to_owned()),
                "the trusted proxy list is empty",
                "list the proxies' addresses, for example \"127.0.0.1, ::1\"",
            ),
            _ => ConfigError::new(
                RuleId::TrustParse,
                Subject::Listener("http-0".to_owned()),
                "the trusted proxy list does not parse",
                "use addresses or CIDR blocks separated by commas, for example \"10.0.0.0/8\"",
            ),
        };
        crate::ServeError::Config(
            ConfigErrors::from_vec(vec![error]).unwrap_or_else(|| unreachable!()),
        )
    })?;
    tier1(addr, Some(trusted), handler)
}

/// The listeners of Tier 1: one per resolved address, `http-0`, `http-1`, ...
fn tier1<A, F>(
    addr: A,
    trusted: Option<crate::TrustedProxies>,
    handler: F,
) -> Result<crate::Running, crate::ServeError>
where
    A: std::net::ToSocketAddrs,
    F: Fn(&HttpRequest<'_>, &mut HttpReply) + Send + Sync + 'static,
{
    let addrs: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default();
    let spec = |name: &str, a: &[std::net::SocketAddr]| {
        let l = crate::ListenerSpec::tcp(name, a);
        match &trusted {
            None => l,
            Some(t) => l.ingress(crate::Ingress::Proxy(crate::ProxySource::forwarded_for(
                t.clone(),
            ))),
        }
    };
    let mut builder = crate::Server::builder();
    if addrs.is_empty() {
        // Resolves to nothing: validation names the rule.
        builder = builder.listener(spec("http-0", &[]));
    }
    for (i, a) in addrs.iter().enumerate() {
        builder = builder.listener(spec(&format!("http-{i}"), core::slice::from_ref(a)));
    }
    builder.serve(Handler { f: handler })
}

/// Turns a closure into an [`HttpService`] where a type is expected; the
/// closure needs no annotations.
///
/// ```
/// let site = serve_net::handler(|req, reply| { reply.text(200, req.path()); });
/// let reply = serve_net::testing::respond(&site, b"GET /hi HTTP/1.1\r\nHost: a\r\n\r\n");
/// assert_eq!(reply.text(), "/hi");
/// ```
pub fn handler<F>(f: F) -> Handler<F>
where
    F: Fn(&HttpRequest<'_>, &mut HttpReply) + Send + Sync + 'static,
{
    Handler { f }
}

impl<F> HttpService for Handler<F>
where
    F: Fn(&HttpRequest<'_>, &mut HttpReply) + Send + Sync + 'static,
{
    fn call(&self, request: &HttpRequest<'_>, _env: &Envelope, reply: &mut HttpReply) -> Outcome {
        (self.f)(request, reply);
        Outcome::Done
    }
}

impl<F> fmt::Debug for Handler<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handler")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_debug_redacts_values() {
        let mut r = HttpReply::new(HttpParts::default());
        r.header("set-cookie", "sid=secret").text(200, "x");
        let text = format!("{r:?}");
        assert!(!text.contains("secret"));
        assert!(text.contains("set-cookie"));
    }

    #[test]
    fn test_reply_too_many_fields_is_invalid() {
        let mut r = HttpReply::new(HttpParts::default());
        for _ in 0..=MAX_FIELDS {
            r.header("x-a", "1");
        }
        assert!(r.parts.invalid);
    }

    #[test]
    fn test_parts_clear_wipes() {
        let mut r = HttpReply::new(HttpParts::default());
        r.header("x", "secret").body(b"secret");
        r.parts.clear(true);
        assert!(r.parts.values.is_empty() && r.parts.body.is_empty() && r.parts.spans.is_empty());
    }
}
