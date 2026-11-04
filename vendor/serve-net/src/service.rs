//! What a service decides at the head, what it returns from a call, and how
//! a request ended.

use std::time::{Duration, Instant};

use crate::engine::RefusalKind;

/// How a request body is read.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyPolicy {
    /// Read the whole body before the service call, up to `max` bytes (and
    /// the engine's own limit); a declared length over it is refused with 413
    /// before any body byte is read.
    Buffer {
        /// The largest body accepted.
        max: u64,
    },
    /// Read and drop up to `max` bytes so the connection stays usable; beyond
    /// it, close after the reply.
    Discard {
        /// The most bytes read and dropped.
        max: u64,
    },
}

/// What `head` decided.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadAction {
    /// Continue with the profile's body policy.
    Proceed,
    /// Continue with this body policy.
    ProceedWith(BodyPolicy),
    /// Answer with the engine's refusal for `status` (400 to 599) and close.
    Refuse {
        /// The status; outside 400 to 599 it becomes 500.
        status: u16,
        /// `Retry-After`, when given.
        retry_after: Option<Duration>,
    },
}

impl HeadAction {
    /// `Refuse { status, retry_after: None }`.
    #[must_use]
    pub const fn refuse(status: u16) -> Self {
        HeadAction::Refuse {
            status,
            retry_after: None,
        }
    }
}

/// What a service call returned.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The reply is complete.
    Done,
    /// The service called `reply.defer()` and completes the reply later.
    Deferred,
    /// Send what the reply holds and close the connection.
    Close,
}

/// How a service behaves, for dispatchers that move slow work off the worker.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WorkClass {
    /// Microseconds, never blocks.
    #[default]
    Quick,
    /// Waits on something: a database, a file, a network call.
    Io,
    /// Long computation: password hashing, image work.
    Cpu,
}

/// How a request ended.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestEnd {
    /// The reply was handed to the transport.
    Replied,
    /// serve-net or the service refused it.
    Refused(RefusalKind),
    /// Admission refused it.
    Shed,
    /// `Checkpoint` denied or killed it.
    Denied,
    /// A deadline passed.
    TimedOut,
    /// The peer left before the reply.
    PeerGone,
    /// The server drained before it finished.
    Drained,
    /// The connection was killed.
    Killed,
    /// The service panicked.
    ServicePanic,
    /// A deferred reply's token was dropped without completing it.
    Dropped,
}

/// What happened to a request, given to `done` and the observer.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct Finished {
    /// The status written, if any.
    pub status: Option<u16>,
    /// How it ended.
    pub end: RequestEnd,
    /// Head and body bytes received.
    pub bytes_in: u64,
    /// Reply bytes handed to the transport.
    pub bytes_out: u64,
    /// When the first head byte arrived.
    pub head_at: Instant,
    /// When admission admitted it.
    pub admitted_at: Option<Instant>,
    /// When the reply was handed to the transport.
    pub replied_at: Option<Instant>,
}
