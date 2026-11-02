//! The seams a wrapper uses to put its own policy around serve-net.
//!
//! Every hook has a real default: `InFlightCap` is real admission control,
//! `Inline` really calls the service. Hooks run on the worker that owns the
//! connection, so they must be fast; slow work belongs behind `Dispatch`.

mod admit;

use std::time::Duration;

pub use admit::{Admit, Admitted, InFlightCap, Shed};

use crate::Finished;
use crate::engine::{Family, Service};
use crate::envelope::Envelope;
use crate::error::EndReason;
use crate::net::{AllowAll, ConnectionId, ControlLine, EventSink, Gate, NoControl, NoopSink};
use crate::reply::Reply;
use crate::service::Outcome;

/// The one call between "request complete" and the service.
pub trait Dispatch: Send + Sync + 'static {
    /// Runs the service for one request.
    fn run<F: Family, S: Service<F>>(
        &self,
        service: &S,
        request: &F::Request<'_>,
        env: &Envelope,
        reply: &mut Reply<F>,
    ) -> Outcome;
}

/// Calls the service in place.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inline;

impl Dispatch for Inline {
    #[inline]
    fn run<F: Family, S: Service<F>>(
        &self,
        service: &S,
        request: &F::Request<'_>,
        env: &Envelope,
        reply: &mut Reply<F>,
    ) -> Outcome {
        service.call(request, env, reply)
    }
}

/// Where a checkpoint runs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAt {
    /// Right after admission, before any body byte.
    Admitted,
    /// Before the service call.
    BeforeDispatch,
    /// Before the reply leaves; a denial replaces it whole.
    BeforeReply,
}

/// What a checkpoint decided.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Continue.
    Pass,
    /// Answer the refusal for `status` and close.
    Deny {
        /// The status (400 to 599).
        status: u16,
    },
    /// Close abortively with nothing written.
    Kill,
}

/// Revocation during a request: a ban, a revoked session, or a lockdown that
/// arrives while the request is in flight.
///
/// A checkpoint backed by remote state fails closed (denies) when the remote
/// is unreachable.
pub trait Checkpoint: Send + Sync + 'static {
    /// Decides at one point of a request.
    fn check(&self, env: &Envelope, at: CheckpointAt) -> Verdict;
}

/// Always `Pass`; compiles to nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCheckpoint;

impl Checkpoint for NoCheckpoint {
    #[inline(always)]
    fn check(&self, _env: &Envelope, _at: CheckpointAt) -> Verdict {
        Verdict::Pass
    }
}

/// Request-level events for logs, metrics, and detection. Every method has an
/// empty default, so `NoObserver` compiles to nothing. Events carry ids,
/// enums, and numbers, never request bytes.
#[allow(unused_variables)]
pub trait Observer: Send + Sync + 'static {
    /// A head is complete.
    fn request_head(&self, env: &Envelope) {}
    /// Admission admitted a request.
    fn request_admitted(&self, env: &Envelope) {}
    /// Admission refused a request.
    fn request_shed(&self, env: &Envelope, shed: &Shed) {}
    /// A request finished, whatever the path.
    fn request_finished(&self, env: &Envelope, finished: &Finished) {}
    /// A connection ended.
    fn connection_ended(&self, connection: ConnectionId, end: EndReason, requests: u32) {}
    /// A soft connection cap refused a connection.
    fn capacity_refused(&self, listener: &str, profile: crate::config::ProfileId) {}
    /// A listener runs with a public-bind exception.
    fn public_bind(&self, listener: &str, reason: &'static str) {}
    /// A `Quick` service took longer than 1 ms (debug builds).
    fn service_misdeclared(&self, env: &Envelope, took: Duration) {}
    /// A service bug serve-net answered for it: `Deferred` without a token,
    /// a lane set after `head`, a reply that could not be encoded.
    fn service_error(&self, env: &Envelope, what: &'static str) {}
}

/// The observer that observes nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoObserver;

impl Observer for NoObserver {}

/// The bundle of hook types a builder carries.
pub trait Hooks: Send + Sync + 'static {
    /// Admission.
    type Admit: Admit;
    /// Dispatch.
    type Dispatch: Dispatch;
    /// Revocation checkpoints.
    type Checkpoint: Checkpoint;
    /// Request events.
    type Observer: Observer;
    /// The connection gate net-io consults.
    type Gate: Gate;
    /// The sink for net-io's transport events.
    type Events: EventSink;
    /// The control line.
    type Control: ControlLine;
    /// The TLS acceptor (set from 0.4).
    type Tls: net_io::TlsAcceptor;
}

/// The hook values; programs never name this type.
pub struct HookSet<A, D, K, O, G, E, C, T> {
    pub(crate) admit: A,
    pub(crate) dispatch: D,
    pub(crate) checkpoint: K,
    pub(crate) observer: O,
    pub(crate) gate: G,
    pub(crate) events: E,
    pub(crate) control: std::sync::Arc<C>,
    pub(crate) tls: T,
}

impl<A, D, K, O, G, E, C, T> Hooks for HookSet<A, D, K, O, G, E, C, T>
where
    A: Admit,
    D: Dispatch,
    K: Checkpoint,
    O: Observer,
    G: Gate,
    E: EventSink,
    C: ControlLine,
    T: net_io::TlsAcceptor,
{
    type Admit = A;
    type Dispatch = D;
    type Checkpoint = K;
    type Observer = O;
    type Gate = G;
    type Events = E;
    type Control = C;
    type Tls = T;
}

/// The default hooks.
pub type DefaultHooks = HookSet<
    InFlightCap,
    Inline,
    NoCheckpoint,
    NoObserver,
    AllowAll,
    NoopSink,
    NoControl,
    net_io::NoTls,
>;

impl Default for DefaultHooks {
    fn default() -> Self {
        HookSet {
            admit: InFlightCap::new(),
            dispatch: Inline,
            checkpoint: NoCheckpoint,
            observer: NoObserver,
            gate: AllowAll,
            events: NoopSink,
            control: std::sync::Arc::new(NoControl),
            tls: net_io::NoTls,
        }
    }
}

impl<A, D, K, O, G, E, C, T> core::fmt::Debug for HookSet<A, D, K, O, G, E, C, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HookSet")
    }
}
