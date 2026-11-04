//! Request counters: one set per worker, written only by that worker, summed
//! on call.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::engine::RefusalKind;

/// The number of [`RefusalKind`] variants.
const KINDS: usize = 11;

fn kind_index(kind: RefusalKind) -> usize {
    match kind {
        RefusalKind::Malformed => 0,
        RefusalKind::TooLarge => 1,
        RefusalKind::HeadTimeout => 2,
        RefusalKind::BodyTimeout => 3,
        RefusalKind::ReplyTimeout => 4,
        RefusalKind::Busy => 5,
        RefusalKind::Draining => 6,
        RefusalKind::Denied => 7,
        RefusalKind::Ingress => 8,
        RefusalKind::Service => 9,
        RefusalKind::Internal => 10,
    }
}

/// Totals since start.
///
/// ```no_run
/// # #[cfg(feature = "http1")]
/// # fn main() -> Result<(), serve_net::ServeError> {
/// # let server = serve_net::http("127.0.0.1:0", |_req, reply| { reply.text(200, "ok"); })?;
/// let stats = server.stats();
/// println!("{} requests, {} replied, {} open", stats.requests, stats.replied, stats.transport.open);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "http1"))]
/// # fn main() {}
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Requests that reached `head` and finished.
    pub requests: u64,
    /// Requests answered by the service.
    pub replied: u64,
    /// Every refusal serve-net wrote (timeouts, limits, malformed, ingress).
    pub refused: u64,
    /// Busy refusals from admission and soft caps.
    pub shed: u64,
    /// Checkpoint denials and kills.
    pub denied: u64,
    /// Requests and connections ended by a serve-net deadline.
    pub timed_out: u64,
    /// Replies the service deferred.
    pub deferred: u64,
    /// Bytes the connection machine consumed.
    pub bytes_in: u64,
    /// Bytes handed to the transport.
    pub bytes_out: u64,
    /// net-io's counters: connections accepted, refused, open, closed.
    pub transport: net_io::Stats,
    refused_by: [u64; KINDS],
}

impl Stats {
    /// Refusals of this kind.
    #[must_use]
    pub fn refused_for(&self, kind: RefusalKind) -> u64 {
        self.refused_by[kind_index(kind)]
    }
}

/// One worker's counters. Only that worker writes them, so an increment is a
/// relaxed load and store, not a read-modify-write.
#[derive(Default)]
pub(crate) struct WorkerCounters {
    requests: AtomicU64,
    replied: AtomicU64,
    refused: AtomicU64,
    shed: AtomicU64,
    denied: AtomicU64,
    timed_out: AtomicU64,
    deferred: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    finished_draining: AtomicU64,
    refused_draining: AtomicU64,
    refused_by: [AtomicU64; KINDS],
    /// Moves on every event; `health` reads it to tell a stalled worker.
    progress: AtomicU64,
    /// Inside a service call.
    in_call: AtomicBool,
}

#[inline]
fn add(c: &AtomicU64, n: u64) {
    c.store(c.load(Ordering::Relaxed).wrapping_add(n), Ordering::Relaxed);
}

/// What one counter event is.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Count {
    Requests,
    Replied,
    Shed,
    Denied,
    TimedOut,
    Deferred,
    BytesIn(u64),
    BytesOut(u64),
    FinishedDraining,
    Refused { kind: RefusalKind, draining: bool },
}

/// Every worker's counters.
pub(crate) struct Counters {
    workers: Box<[WorkerCounters]>,
}

impl Counters {
    pub(crate) fn new(workers: u16) -> Counters {
        Counters {
            workers: (0..workers.max(1))
                .map(|_| WorkerCounters::default())
                .collect(),
        }
    }

    /// Records one event for `worker`; an unknown worker is ignored.
    #[inline]
    pub(crate) fn count(&self, worker: u16, what: Count) {
        let Some(w) = self.workers.get(usize::from(worker)) else {
            return;
        };
        add(&w.progress, 1);
        match what {
            Count::Requests => add(&w.requests, 1),
            Count::Replied => add(&w.replied, 1),
            Count::Shed => add(&w.shed, 1),
            Count::Denied => add(&w.denied, 1),
            Count::TimedOut => add(&w.timed_out, 1),
            Count::Deferred => add(&w.deferred, 1),
            Count::BytesIn(n) => add(&w.bytes_in, n),
            Count::BytesOut(n) => add(&w.bytes_out, n),
            Count::FinishedDraining => add(&w.finished_draining, 1),
            Count::Refused { kind, draining } => {
                add(&w.refused, 1);
                add(&w.refused_by[kind_index(kind)], 1);
                if draining {
                    add(&w.refused_draining, 1);
                }
            }
        }
    }

    /// The sum over workers (net-io's part left at its default).
    pub(crate) fn sum(&self) -> Stats {
        let mut s = Stats::default();
        let r = |c: &AtomicU64| c.load(Ordering::Relaxed);
        for w in self.workers.iter() {
            s.requests += r(&w.requests);
            s.replied += r(&w.replied);
            s.refused += r(&w.refused);
            s.shed += r(&w.shed);
            s.denied += r(&w.denied);
            s.timed_out += r(&w.timed_out);
            s.deferred += r(&w.deferred);
            s.bytes_in += r(&w.bytes_in);
            s.bytes_out += r(&w.bytes_out);
            for (k, c) in w.refused_by.iter().enumerate() {
                s.refused_by[k] += r(c);
            }
        }
        s
    }

    /// Marks `worker` inside or outside a service call.
    #[inline]
    pub(crate) fn in_call(&self, worker: u16, inside: bool) {
        if let Some(w) = self.workers.get(usize::from(worker)) {
            w.in_call.store(inside, Ordering::Relaxed);
            if !inside {
                add(&w.progress, 1);
            }
        }
    }

    /// Each worker's progress counter and whether it is inside a service call.
    pub(crate) fn workers(&self) -> impl Iterator<Item = (u64, bool)> + '_ {
        self.workers.iter().map(|w| {
            (
                w.progress.load(Ordering::Relaxed),
                w.in_call.load(Ordering::Relaxed),
            )
        })
    }

    /// Requests finished and refused while a drain ran.
    pub(crate) fn draining(&self) -> (u64, u64) {
        self.workers.iter().fold((0, 0), |(f, r), w| {
            (
                f + w.finished_draining.load(Ordering::Relaxed),
                r + w.refused_draining.load(Ordering::Relaxed),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counters_sum_over_workers_and_kinds() {
        let c = Counters::new(2);
        c.count(0, Count::Requests);
        c.count(1, Count::Requests);
        c.count(1, Count::BytesOut(10));
        c.count(
            0,
            Count::Refused {
                kind: RefusalKind::Busy,
                draining: true,
            },
        );
        c.count(9, Count::Requests); // unknown worker: ignored
        let s = c.sum();
        assert_eq!(s.requests, 2);
        assert_eq!(s.bytes_out, 10);
        assert_eq!(s.refused, 1);
        assert_eq!(s.refused_for(RefusalKind::Busy), 1);
        assert_eq!(s.refused_for(RefusalKind::Malformed), 0);
        assert_eq!(c.draining(), (0, 1));
    }
}
