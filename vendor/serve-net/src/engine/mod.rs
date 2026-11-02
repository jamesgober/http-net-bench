//! Protocol engines and families (Tier 3).
//!
//! An engine is a sans-IO state machine: bytes in, events out; replies in,
//! bytes out. serve-net does every read and write. A family is a set of
//! engines that produce the same request view, so a service never depends on
//! how its requests arrived.

use core::fmt;
use std::time::Duration;

use crate::Finished;
use crate::client::ClientInfo;
use crate::config::{Limits, Profile, ProxySource};
use crate::envelope::Envelope;
use crate::reply::Reply;
use crate::service::{HeadAction, Outcome, WorkClass};

#[cfg(feature = "http1")]
pub(crate) mod http1;
#[cfg(feature = "http1")]
pub use http1::Http1;

/// A sans-IO protocol engine bound to one connection.
pub trait Engine: Send + 'static {
    /// The current request's head, borrowed from the engine.
    type Head<'a>: Copy
    where
        Self: 'a;

    /// Copies what fits of `bytes` into the engine; returns the count taken.
    fn feed(&mut self, bytes: &[u8]) -> usize;
    /// The peer closed its sending side.
    fn feed_eof(&mut self);
    /// Advances one step. `EngineEvent::Head` means [`head`](Self::head) now
    /// returns the new request's head.
    fn poll(&mut self) -> Result<EngineEvent<'_>, EngineError>;
    /// The current request's head.
    fn head(&self) -> Option<Self::Head<'_>>;
    /// The current request's declared body length, when it has one.
    fn declared_length(&self) -> Option<u64>;
    /// Whether the current request waits for a go-ahead before its body.
    fn expects_continue(&self) -> bool {
        false
    }
    /// The size of the current request's head in bytes, for accounting.
    fn head_len(&self) -> usize {
        0
    }
    /// The phase, for deadlines.
    fn progress(&self) -> EngineProgress;
    /// Tells a client that waits for a go-ahead to send its body.
    fn send_continue(&mut self, out: &mut OutBuf) -> Result<(), EngineError> {
        let _ = out;
        Ok(())
    }
    /// Writes a refusal in the protocol's terms. Never fails: an engine that
    /// cannot write one writes nothing and the connection closes.
    fn refuse(&mut self, refusal: &Refusal, out: &mut OutBuf);
    /// The next reply carries the close signal and ends the connection.
    fn close_after_reply(&mut self);
    /// Whether the connection can carry another request after the current one.
    fn keep_alive(&self) -> bool;
    /// Replies completed on this connection.
    fn requests_served(&self) -> u64;
    /// Unread input after an upgrade.
    fn remaining_input(&self) -> &[u8];
    /// Back to the initial state for a new connection, keeping allocations.
    fn reset(&mut self);
    /// Releases memory while idle; returns whether any was released.
    fn shrink_idle(&mut self) -> bool {
        false
    }
}

/// What an engine reports.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum EngineEvent<'a> {
    /// A request head is complete; read it with [`Engine::head`].
    Head,
    /// Body bytes, valid until the next call on the engine.
    Body(&'a [u8]),
    /// The request body is complete.
    BodyEnd,
    /// More input is needed.
    NeedInput,
    /// The request is complete and waits for its reply.
    AwaitingReply,
    /// The connection now speaks another protocol.
    Upgraded,
    /// The connection is finished.
    Closed,
}

/// An engine's phase, which chooses the running deadline.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineProgress {
    /// Between requests.
    Idle,
    /// Some bytes of a head have arrived.
    Head,
    /// The head is complete; body bytes are outstanding.
    Body,
    /// The request is complete; its reply is not.
    AwaitingReply,
    /// A streamed reply is being written.
    WritingReply,
    /// The connection belongs to another protocol.
    Upgraded,
    /// Finished.
    Closed,
}

/// Why serve-net refuses a request; the engine formats it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefusalKind {
    /// The request was malformed.
    Malformed,
    /// A head or body over its budget.
    TooLarge,
    /// No complete head within the head deadline.
    HeadTimeout,
    /// The body did not finish within the request deadline.
    BodyTimeout,
    /// A deferred reply did not come in time.
    ReplyTimeout,
    /// Over a cap: admission or a soft connection cap.
    Busy,
    /// The server is draining.
    Draining,
    /// A checkpoint denied it.
    Denied,
    /// Forwarded facts or FastCGI parameters were missing or malformed.
    Ingress,
    /// The service refused it in `head`.
    Service,
    /// A service bug (an invalid reply, a dropped token, a panic).
    Internal,
}

impl RefusalKind {
    /// A stable snake_case name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RefusalKind::Malformed => "malformed",
            RefusalKind::TooLarge => "too_large",
            RefusalKind::HeadTimeout => "head_timeout",
            RefusalKind::BodyTimeout => "body_timeout",
            RefusalKind::ReplyTimeout => "reply_timeout",
            RefusalKind::Busy => "busy",
            RefusalKind::Draining => "draining",
            RefusalKind::Denied => "denied",
            RefusalKind::Ingress => "ingress",
            RefusalKind::Service => "service",
            RefusalKind::Internal => "internal",
        }
    }
}

/// A refusal serve-net asks the engine to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// Why.
    pub kind: RefusalKind,
    /// The protocol status (HTTP: 400 to 599).
    pub status: u16,
    /// `Retry-After`, when given.
    pub retry_after: Option<Duration>,
}

/// A peer error from [`Engine::poll`]: serve-net writes one refusal with this
/// status and closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineError {
    /// The kind of refusal it becomes.
    pub kind: RefusalKind,
    /// The status of that refusal.
    pub status: u16,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "engine refused the request: {} ({})",
            self.kind.as_str(),
            self.status
        )
    }
}

impl std::error::Error for EngineError {}

/// Where an engine encodes a reply: a reused byte buffer.
///
/// serve-net hands its whole content to the transport before writing, so the
/// egress check sees the whole reply.
#[derive(Default)]
pub struct OutBuf {
    pub(crate) bytes: Vec<u8>,
}

impl OutBuf {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        OutBuf { bytes: Vec::new() }
    }

    /// Appends `bytes`.
    pub fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// The number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The bytes held.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Empties it, zeroing the used bytes first when `wipe` is set.
    pub(crate) fn clear(&mut self, wipe: bool) {
        if wipe {
            wipe_bytes(&mut self.bytes);
        }
        self.bytes.clear();
    }

    /// Releases capacity above `retain` bytes.
    pub(crate) fn shrink(&mut self, retain: usize) {
        if self.bytes.capacity() > retain {
            self.bytes.shrink_to(retain);
        }
    }
}

impl fmt::Debug for OutBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutBuf")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(feature = "http1")]
impl http_net::Output for OutBuf {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
    fn reserve(&mut self, additional: usize) {
        self.bytes.reserve(additional);
    }
}

/// Zeroes `bytes` with writes the optimizer keeps.
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(&mut *bytes);
}

/// What a family's head conversion may read: the connection's client and the
/// listener's ingress rules.
pub struct HeadContext<'c> {
    pub(crate) client: &'c ClientInfo,
    pub(crate) proxy: Option<&'c ProxySource>,
    pub(crate) declared_scheme: crate::client::Scheme,
    /// The request's client as resolved at its head, when the view is built
    /// again for the service call: the walk is not repeated.
    pub(crate) resolved: Option<ClientInfo>,
}

impl HeadContext<'_> {
    /// The connection's client (the socket peer, or the PROXY header's client).
    #[must_use]
    pub fn client(&self) -> &ClientInfo {
        self.client
    }

    /// The request's client, when the head was already resolved once.
    #[must_use]
    pub fn resolved(&self) -> Option<&ClientInfo> {
        self.resolved.as_ref()
    }
}

/// A set of engines that produce the same request view.
pub trait Family: Send + Sync + 'static {
    /// The engine connections of this family run.
    type Engine: Engine;
    /// The head view a service sees.
    type Head<'a>;
    /// The request a service answers.
    type Request<'a>;
    /// The reply data a service fills.
    type Parts: Default + Send + 'static;

    /// A new engine for a connection of `profile`.
    fn engine(&self, profile: &Profile, limits: &Limits) -> Self::Engine;
    /// The service's head view and the request's client, from the engine's head.
    fn head<'a>(
        &self,
        raw: <Self::Engine as Engine>::Head<'a>,
        cx: &HeadContext<'_>,
    ) -> Result<(Self::Head<'a>, ClientInfo), EngineError>;
    /// The request view, from the head view and the buffered body.
    fn request<'a>(&self, head: Self::Head<'a>, body: &'a [u8]) -> Self::Request<'a>;
    /// Fresh reply data.
    fn new_parts(&self) -> Self::Parts;
    /// Readies reply data for reuse; zeroes it when `wipe` is set.
    fn clear_parts(&self, parts: &mut Self::Parts, wipe: bool);
    /// Encodes the reply for the current request; returns the status written.
    fn respond(
        &self,
        engine: &mut Self::Engine,
        parts: &mut Self::Parts,
        unix_secs: u64,
        out: &mut OutBuf,
    ) -> Result<u16, EngineError>;
}

/// A service over a family's types: the same calls in the same order as
/// [`HttpService`](crate::HttpService).
pub trait Service<F: Family>: Send + Sync {
    /// How the service behaves.
    const WORK: WorkClass = WorkClass::Quick;
    /// The head is complete; before admission and any body byte.
    fn head(&self, head: &F::Head<'_>, env: &mut Envelope) -> HeadAction {
        let _ = (head, env);
        HeadAction::Proceed
    }
    /// The request is complete.
    fn call(&self, request: &F::Request<'_>, env: &Envelope, reply: &mut Reply<F>) -> Outcome;
    /// Exactly once per request that reached `head`.
    fn done(&self, env: &Envelope, finished: &Finished) {
        let _ = (env, finished);
    }
}

/// The custom engine of a server that serves no custom family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCustom {}

impl Engine for NoCustom {
    type Head<'a> = ();
    fn feed(&mut self, _bytes: &[u8]) -> usize {
        match *self {}
    }
    fn feed_eof(&mut self) {
        match *self {}
    }
    fn poll(&mut self) -> Result<EngineEvent<'_>, EngineError> {
        match *self {}
    }
    fn head(&self) -> Option<()> {
        match *self {}
    }
    fn declared_length(&self) -> Option<u64> {
        match *self {}
    }
    fn progress(&self) -> EngineProgress {
        match *self {}
    }
    fn refuse(&mut self, _refusal: &Refusal, _out: &mut OutBuf) {
        match *self {}
    }
    fn close_after_reply(&mut self) {
        match *self {}
    }
    fn keep_alive(&self) -> bool {
        match *self {}
    }
    fn requests_served(&self) -> u64 {
        match *self {}
    }
    fn remaining_input(&self) -> &[u8] {
        match *self {}
    }
    fn reset(&mut self) {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbuf_clear_and_wipe() {
        let mut o = OutBuf::new();
        o.push(b"hello world");
        assert_eq!(o.as_slice(), b"hello world");
        o.clear(true);
        assert!(o.is_empty());
    }

    #[test]
    fn test_refusal_kind_names() {
        assert_eq!(RefusalKind::Busy.as_str(), "busy");
        assert_eq!(
            Refusal {
                kind: RefusalKind::Malformed,
                status: 400,
                retry_after: None
            }
            .status,
            400
        );
    }
}
