//! Health and listener state, computed on call from net-io's transport
//! events and serve-net's own counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use net_io::{Endpoint, Event, EventSink};

use crate::client::IngressKind;
use crate::config::ProfileId;
use crate::stats::Counters;

/// Whether a running server is doing its job.
///
/// ```no_run
/// # #[cfg(feature = "http1")]
/// # fn main() -> Result<(), serve_net::ServeError> {
/// # let server = serve_net::http("127.0.0.1:0", |_req, reply| { reply.text(200, "ok"); })?;
/// match server.health() {
///     serve_net::Health::Ok => {}
///     other => eprintln!("health: {other:?}"),
/// }
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "http1"))]
/// # fn main() {}
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    /// Every listener accepts and every worker makes progress.
    Ok,
    /// Serving, with these issues.
    Degraded(Vec<HealthIssue>),
    /// Not serving: no listener accepts, or every worker is stalled.
    Failing(Vec<HealthIssue>),
}

impl Health {
    /// Whether it is `Ok`.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Health::Ok)
    }
}

/// One reason a server is not fully healthy.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthIssue {
    /// The listener has reported accept errors for longer than
    /// `accept_failure_window`, or net-io gave it up.
    ListenerAcceptFailing {
        /// The listener's name.
        listener: String,
    },
    /// The worker has been inside one service call since the last check.
    WorkerStalled {
        /// The worker's index.
        index: u16,
    },
    /// More than 20% of requests were refused as busy since the last check.
    Overloaded {
        /// The refused share, in thousandths.
        shed_permille: u16,
    },
    /// A drain is running.
    Draining,
    /// The service manager could not be told about a state change (0.4).
    NotifyFailing,
}

/// Where a listener is.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerState {
    /// Bound; the door is not open yet.
    Bound,
    /// Accepting.
    Accepting,
    /// The door is closed (a drain, or `close_door`).
    DoorClosed,
    /// Accept errors for longer than `accept_failure_window`.
    Failing,
}

/// One listener of a running server.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ListenerInfo {
    /// Its name.
    pub name: String,
    /// The bound address.
    pub local: Endpoint,
    /// How clients reach it.
    pub ingress: IngressKind,
    /// The profile its connections use.
    pub profile: ProfileId,
    /// Where it is.
    pub state: ListenerState,
    /// The reason given to `allow_public_bind`, if any.
    pub public_bind_reason: Option<&'static str>,
}

/// Milliseconds since the server started; 0 means "never".
type Millis = AtomicU64;

/// What the event tap and `health` share.
pub(crate) struct HealthState {
    started: Instant,
    /// Per listener: when accept errors began (0: accepting normally).
    failing_since: Box<[Millis]>,
    window: Duration,
    memory: Mutex<Memory>,
}

/// What the previous `health` call saw.
#[derive(Default)]
struct Memory {
    progress: Vec<u64>,
    requests: u64,
    shed: u64,
}

impl HealthState {
    pub(crate) fn new(listeners: usize, window: Duration) -> HealthState {
        HealthState {
            started: Instant::now(),
            failing_since: (0..listeners).map(|_| AtomicU64::new(0)).collect(),
            window,
            memory: Mutex::new(Memory::default()),
        }
    }

    fn now_ms(&self) -> u64 {
        // At least 2: 0 means "never" and 1 means "given up".
        (self.started.elapsed().as_millis() as u64).max(2)
    }

    fn on_event(&self, event: &Event) {
        match event {
            Event::AcceptError { listener, .. } => {
                if let Some(c) = self.failing_since.get(usize::from(listener.get())) {
                    let _ =
                        c.compare_exchange(0, self.now_ms(), Ordering::AcqRel, Ordering::Relaxed);
                }
            }
            Event::ListenerFailed { listener, .. } => {
                if let Some(c) = self.failing_since.get(usize::from(listener.get())) {
                    // Given up by net-io: failing at once.
                    c.store(1, Ordering::Release);
                }
            }
            Event::Accepted { listener, .. } => {
                if let Some(c) = self.failing_since.get(usize::from(listener.get())) {
                    if c.load(Ordering::Relaxed) > 1 {
                        c.store(0, Ordering::Release);
                    }
                }
            }
            _ => {}
        }
    }

    /// Whether the listener with this index counts as failing.
    pub(crate) fn listener_failing(&self, index: usize) -> bool {
        let Some(c) = self.failing_since.get(index) else {
            return false;
        };
        match c.load(Ordering::Acquire) {
            0 => false,
            1 => true,
            since => Duration::from_millis(self.now_ms().saturating_sub(since)) >= self.window,
        }
    }

    /// Computes health. `names` are the listener names in declaration order.
    pub(crate) fn compute(&self, names: &[String], counters: &Counters, draining: bool) -> Health {
        let mut issues = Vec::new();
        let mut failing_listeners = 0;
        for (i, name) in names.iter().enumerate() {
            if self.listener_failing(i) {
                failing_listeners += 1;
                issues.push(HealthIssue::ListenerAcceptFailing {
                    listener: name.clone(),
                });
            }
        }
        let mut memory = self.memory.lock().unwrap_or_else(PoisonError::into_inner);
        let now: Vec<(u64, bool)> = counters.workers().collect();
        let mut stalled = 0;
        if memory.progress.len() == now.len() {
            for (i, ((progress, in_call), before)) in now.iter().zip(&memory.progress).enumerate() {
                if *in_call && progress == before {
                    stalled += 1;
                    issues.push(HealthIssue::WorkerStalled {
                        index: u16::try_from(i).unwrap_or(u16::MAX),
                    });
                }
            }
        }
        memory.progress = now.iter().map(|(p, _)| *p).collect();
        let sum = counters.sum();
        let requests = sum.requests.saturating_sub(memory.requests);
        let shed = sum.shed.saturating_sub(memory.shed);
        memory.requests = sum.requests;
        memory.shed = sum.shed;
        drop(memory);
        if requests > 0 {
            let permille = (shed.saturating_mul(1000) / requests.max(shed)).min(1000);
            if permille > 200 {
                issues.push(HealthIssue::Overloaded {
                    shed_permille: permille as u16,
                });
            }
        }
        if draining {
            issues.push(HealthIssue::Draining);
        }
        let all_workers_stalled = !now.is_empty() && stalled == now.len();
        if (!names.is_empty() && failing_listeners == names.len()) || all_workers_stalled {
            Health::Failing(issues)
        } else if issues.is_empty() {
            Health::Ok
        } else {
            Health::Degraded(issues)
        }
    }
}

/// The owner's event sink with serve-net's health tap in front.
pub(crate) struct Tap<E: EventSink> {
    pub(crate) inner: E,
    pub(crate) state: Arc<HealthState>,
}

impl<E: EventSink> EventSink for Tap<E> {
    #[inline]
    fn event(&self, event: &Event) {
        self.state.on_event(event);
        self.inner.event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::RefusalKind;
    use crate::stats::Count;

    #[test]
    fn test_health_ok_then_overloaded_then_stalled() {
        let state = HealthState::new(1, Duration::from_secs(30));
        let counters = Counters::new(1);
        let names = vec!["web".to_owned()];
        assert_eq!(state.compute(&names, &counters, false), Health::Ok);
        for _ in 0..10 {
            counters.count(0, Count::Requests);
        }
        for _ in 0..5 {
            counters.count(0, Count::Shed);
            counters.count(
                0,
                Count::Refused {
                    kind: RefusalKind::Busy,
                    draining: false,
                },
            );
        }
        let h = state.compute(&names, &counters, false);
        assert!(
            matches!(&h, Health::Degraded(i) if matches!(i[0], HealthIssue::Overloaded { shed_permille: 500 })),
            "{h:?}"
        );
        // A worker inside a call with no progress since the last check: stalled.
        counters.in_call(0, true);
        let _ = state.compute(&names, &counters, false);
        let h = state.compute(&names, &counters, true);
        assert!(matches!(h, Health::Failing(_)), "{h:?}");
        counters.in_call(0, false);
        assert_eq!(state.compute(&names, &counters, false), Health::Ok);
    }
}
