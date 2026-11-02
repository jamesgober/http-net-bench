//! Replies and deferred replies.
//!
//! A service fills a [`Reply`]. `defer()` moves its data into a
//! [`ReplyToken`] that another thread completes; the completion goes through
//! a per-connection slot (allocated once per connection, reused for every
//! later deferral) and wakes the worker that owns the connection.

use core::fmt;
use std::sync::{Arc, PoisonError};

use crate::sync::Mutex;

use crate::engine::Family;
use crate::net::ConnectionId;

/// The wake token serve-net uses for deferred replies.
pub(crate) const WAKE_REPLY: u32 = 1;

/// Why a wake could not be posted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PostFail {
    /// The worker's completion queue is full.
    Full,
    /// The server stopped.
    Stopped,
}

/// Wakes the worker that owns a connection (net-io's `Completer`).
pub(crate) trait Waker: Send + Sync + 'static {
    fn post(&self, connection: ConnectionId, token: u32, value: u64) -> Result<(), PostFail>;
}

/// The state of one connection's deferred reply.
pub(crate) enum SlotState<P> {
    /// Nothing is deferred.
    Idle,
    /// A reply with this generation is outstanding.
    Waiting(u64),
    /// The reply with this generation was completed.
    Completed(u64, P),
    /// The token of this generation was dropped without completing.
    Dropped(u64),
}

/// One connection's deferred-reply slot.
pub(crate) struct DeferSlot<P> {
    pub(crate) state: Mutex<SlotState<P>>,
    pub(crate) waker: Arc<dyn Waker>,
    pub(crate) connection: ConnectionId,
}

impl<P> DeferSlot<P> {
    pub(crate) fn new(waker: Arc<dyn Waker>, connection: ConnectionId) -> Self {
        DeferSlot {
            state: Mutex::new(SlotState::Idle),
            waker,
            connection,
        }
    }

    pub(crate) fn lock(&self) -> crate::sync::MutexGuard<'_, SlotState<P>> {
        // A panic while the lock is held cannot leave a half-written state:
        // every write replaces the whole value.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What a `Reply` needs to defer: the connection's slot and the generation
/// the next deferral gets.
pub(crate) struct Link<P> {
    pub(crate) slot: Arc<DeferSlot<P>>,
    pub(crate) generation: u64,
}

/// The reply a service fills: its family's reply data plus what serve-net
/// needs to defer it. For HTTP this is [`HttpReply`](crate::HttpReply).
pub struct Reply<F: Family> {
    pub(crate) parts: F::Parts,
    pub(crate) link: Option<Link<F::Parts>>,
    pub(crate) deferred: bool,
}

impl<F: Family> Reply<F> {
    pub(crate) fn new(parts: F::Parts) -> Self {
        Reply {
            parts,
            link: None,
            deferred: false,
        }
    }

    /// The family's reply data.
    pub fn parts(&self) -> &F::Parts {
        &self.parts
    }

    /// The family's reply data, to fill.
    pub fn parts_mut(&mut self) -> &mut F::Parts {
        &mut self.parts
    }

    /// Moves the reply into a token that another thread completes. The
    /// service then returns `Outcome::Deferred`.
    pub fn defer(&mut self) -> ReplyToken<F> {
        let parts = core::mem::take(&mut self.parts);
        let inner = match self.link.take() {
            Some(link) if !self.deferred => {
                *link.slot.lock() = SlotState::Waiting(link.generation);
                self.deferred = true;
                Some(TokenInner {
                    slot: link.slot,
                    generation: link.generation,
                })
            }
            other => {
                // A second defer in one call, or a reply that cannot be
                // deferred: the token can only expire.
                self.link = other;
                None
            }
        };
        ReplyToken {
            reply: Some(Reply::new(parts)),
            inner,
        }
    }
}

impl<F: Family> fmt::Debug for Reply<F>
where
    F::Parts: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("parts", &self.parts)
            .field("deferred", &self.deferred)
            .finish()
    }
}

struct TokenInner<P> {
    slot: Arc<DeferSlot<P>>,
    generation: u64,
}

macro_rules! define_token {
    ($($default:tt)*) => {
        /// A reply completed on another thread.
        ///
        /// Fill [`reply`](Self::reply) and call [`complete`](Self::complete).
        /// Dropping the token without completing it closes the connection
        /// with the 500 refusal.
        pub struct ReplyToken<F: Family $($default)*> {
            reply: Option<Reply<F>>,
            inner: Option<TokenInner<F::Parts>>,
        }

        /// Why a completion was not accepted. The token comes back.
        #[non_exhaustive]
        pub enum CompleteError<F: Family $($default)*> {
            /// Too late: the connection already got the timeout refusal or closed.
            Expired(ReplyToken<F>),
            /// The worker's completion queue is full: retry, or drop the token.
            Busy(ReplyToken<F>),
        }
    };
}

#[cfg(feature = "http1")]
define_token!(= crate::http::HttpFamily);
#[cfg(not(feature = "http1"))]
define_token!();

impl<F: Family> ReplyToken<F> {
    /// The reply to fill.
    pub fn reply(&mut self) -> &mut Reply<F> {
        // `reply` is `None` only after `complete` took it, which consumes the token.
        self.reply
            .get_or_insert_with(|| Reply::new(F::Parts::default()))
    }

    /// Whether nobody waits for the reply any more: the deadline passed, the
    /// peer left, or the server is stopping.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        match &self.inner {
            None => true,
            Some(inner) => {
                !matches!(*inner.slot.lock(), SlotState::Waiting(g) if g == inner.generation)
            }
        }
    }

    /// Hands the reply to the worker that owns the connection and wakes it.
    ///
    /// # Errors
    ///
    /// `Expired` when nobody waits any more; `Busy` when the worker's
    /// completion queue is full.
    pub fn complete(mut self) -> Result<(), CompleteError<F>> {
        let Some(inner) = self.inner.take() else {
            return Err(CompleteError::Expired(self));
        };
        let parts = self.reply.take().map(|r| r.parts).unwrap_or_default();
        {
            let mut state = inner.slot.lock();
            if !matches!(*state, SlotState::Waiting(g) if g == inner.generation) {
                drop(state);
                self.reply = Some(Reply::new(parts));
                self.inner = Some(inner);
                return Err(CompleteError::Expired(self));
            }
            *state = SlotState::Completed(inner.generation, parts);
        }
        match inner
            .slot
            .waker
            .post(inner.slot.connection, WAKE_REPLY, inner.generation)
        {
            Ok(()) => Ok(()),
            Err(fail) => {
                // Take the reply back so the caller can retry or drop it.
                let mut state = inner.slot.lock();
                let parts =
                    match core::mem::replace(&mut *state, SlotState::Waiting(inner.generation)) {
                        SlotState::Completed(_, p) => p,
                        other => {
                            *state = other;
                            F::Parts::default()
                        }
                    };
                if fail == PostFail::Stopped {
                    *state = SlotState::Idle;
                }
                drop(state);
                self.reply = Some(Reply::new(parts));
                self.inner = Some(inner);
                Err(match fail {
                    PostFail::Full => CompleteError::Busy(self),
                    PostFail::Stopped => CompleteError::Expired(self),
                })
            }
        }
    }
}

impl<F: Family> Drop for ReplyToken<F> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            let mut state = inner.slot.lock();
            if matches!(*state, SlotState::Waiting(g) if g == inner.generation) {
                *state = SlotState::Dropped(inner.generation);
                drop(state);
                // Wake the worker so the connection is answered at once; when
                // the queue is full the reply deadline answers it instead.
                let _ = inner
                    .slot
                    .waker
                    .post(inner.slot.connection, WAKE_REPLY, inner.generation);
            }
        }
    }
}

impl<F: Family> fmt::Debug for ReplyToken<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplyToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl<F: Family> fmt::Debug for CompleteError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompleteError::Expired(_) => f.write_str("Expired"),
            CompleteError::Busy(_) => f.write_str("Busy"),
        }
    }
}

impl<F: Family> fmt::Display for CompleteError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompleteError::Expired(_) => f.write_str(
                "the reply came too late: the connection was already answered or closed",
            ),
            CompleteError::Busy(_) => {
                f.write_str("the worker's completion queue is full: retry or drop the token")
            }
        }
    }
}

impl<F: Family> std::error::Error for CompleteError<F> {}
