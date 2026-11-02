//! Request admission: "can this worker take this request now?".

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::ProfileTable;
use crate::envelope::Envelope;
use crate::net::WorkerId;
use crate::sync::{AtomicU32, AtomicU64};

/// Request admission, after `head` and before any body byte.
///
/// `admit` and `release` run on the worker that owns the connection, and a
/// connection never moves between workers, so state indexed by `worker` is
/// written by one thread only: a per-worker counter needs no lock and no
/// read-modify-write. `release` runs once per `Admitted`, on every path.
///
/// A deployment may back admission by shared state (a cluster-wide budget);
/// it must then answer from its local share when the shared state is
/// unreachable, never block the worker waiting for the network.
pub trait Admit: Send + Sync + 'static {
    /// Runs once before any worker starts, to size per-worker state.
    fn prepare(&mut self, workers: u16, profiles: &ProfileTable) {
        let _ = (workers, profiles);
    }
    /// Admits the request, or refuses it with the busy refusal.
    fn admit(&self, worker: WorkerId, env: &Envelope) -> Result<Admitted, Shed>;
    /// Returns what `admit` took.
    fn release(&self, worker: WorkerId, env: &Envelope, admitted: Admitted);
}

/// What `admit` took; opaque to serve-net (a slot index, a permit id).
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The implementation's own value, handed back to `release`.
    pub token: u64,
}

/// A refusal from admission: the busy refusal (503) with `Retry-After`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shed {
    /// `Retry-After`; serve-net adds jitter when it is `None`.
    pub retry_after: Option<Duration>,
    /// End the connection after the refusal.
    pub close: bool,
}

/// One worker's counters, alone on its cache line.
#[repr(align(64))]
#[derive(Debug)]
struct WorkerShard {
    in_flight: AtomicU32,
    /// Per-profile counts for profiles with per-worker shares.
    profiles: Box<[AtomicU32]>,
    jitter: AtomicU64,
}

/// How one profile's cap is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileCap {
    /// No cap of its own.
    None,
    /// Per-worker shares: `share[worker]` requests on that worker.
    Shares,
    /// One shared counter (small caps, where shares would be unfair).
    Shared(u32),
}

/// The default admission control: a real cap on requests in flight per worker
/// and per profile.
///
/// Over the cap, the request gets the busy refusal with `Retry-After` = base
/// plus a jitter in `[0, base)`, so refused clients do not all return in the
/// same second.
///
/// ```
/// use serve_net::InFlightCap;
/// use std::time::Duration;
/// let cap = InFlightCap::new().per_worker(512).retry_after(Duration::from_secs(2));
/// # let _ = cap;
/// ```
#[derive(Debug)]
pub struct InFlightCap {
    per_worker: u32,
    base: Duration,
    shards: Box<[WorkerShard]>,
    caps: Box<[ProfileCap]>,
    /// `shares[profile * workers + worker]`.
    shares: Box<[u32]>,
    shared: Box<[AtomicU32]>,
    workers: u16,
}

impl Clone for InFlightCap {
    fn clone(&self) -> Self {
        // A clone is configuration only; `prepare` sizes the state again.
        InFlightCap::new()
            .per_worker(self.per_worker)
            .retry_after(self.base)
    }
}

impl InFlightCap {
    /// The defaults: 1,024 in flight per worker, `Retry-After` base 1 s.
    #[must_use]
    pub fn new() -> Self {
        InFlightCap {
            per_worker: 1024,
            base: Duration::from_secs(1),
            shards: Box::new([]),
            caps: Box::new([]),
            shares: Box::new([]),
            shared: Box::new([]),
            workers: 0,
        }
    }

    /// Requests in flight per worker.
    #[must_use]
    pub fn per_worker(mut self, n: u32) -> Self {
        self.per_worker = n.max(1);
        self
    }

    /// The `Retry-After` base (default 1 s).
    #[must_use]
    pub fn retry_after(mut self, base: Duration) -> Self {
        self.base = base.max(Duration::from_secs(1));
        self
    }

    fn retry(&self, shard: &WorkerShard) -> Duration {
        // xorshift64: not secret, it only spreads retries.
        let mut x = shard.jitter.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        shard.jitter.store(x, Ordering::Relaxed);
        let base_ms = u64::try_from(self.base.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let jitter_secs = (x % base_ms) / 1000;
        self.base + Duration::from_secs(jitter_secs)
    }

    fn shed(&self, shard: &WorkerShard) -> Shed {
        Shed {
            retry_after: Some(self.retry(shard)),
            close: false,
        }
    }
}

impl Default for InFlightCap {
    fn default() -> Self {
        InFlightCap::new()
    }
}

/// Bit set in `Admitted::token` when the profile was counted on its shared counter.
const COUNTED_SHARED: u64 = 1;
/// Bit set when it was counted on the worker's share.
const COUNTED_SHARE: u64 = 2;

impl Admit for InFlightCap {
    fn prepare(&mut self, workers: u16, profiles: &ProfileTable) {
        let workers = workers.max(1);
        let n = profiles.len();
        self.workers = workers;
        let w = usize::from(workers);
        let mut caps = Vec::with_capacity(n);
        let mut shares = vec![0u32; n * w];
        for (i, p) in profiles.iter().enumerate() {
            caps.push(match p.budget.max_in_flight {
                None => ProfileCap::None,
                Some(cap) if u64::from(cap) >= 4 * u64::from(workers) => {
                    // Exact shares: floor plus the remainder spread over the first workers.
                    let floor = cap / u32::from(workers);
                    let rest = cap % u32::from(workers);
                    for k in 0..w {
                        shares[i * w + k] = floor + u32::from((k as u32) < rest);
                    }
                    ProfileCap::Shares
                }
                Some(cap) => ProfileCap::Shared(cap),
            });
        }
        self.caps = caps.into_boxed_slice();
        self.shares = shares.into_boxed_slice();
        self.shared = (0..n).map(|_| AtomicU32::new(0)).collect();
        self.shards = (0..w)
            .map(|k| WorkerShard {
                in_flight: AtomicU32::new(0),
                profiles: (0..n).map(|_| AtomicU32::new(0)).collect(),
                jitter: AtomicU64::new(
                    0x9E37_79B9_7F4A_7C15 ^ (k as u64 + 1).wrapping_mul(0xBF58_476D_1CE4_E5B9),
                ),
            })
            .collect();
    }

    fn admit(&self, worker: WorkerId, env: &Envelope) -> Result<Admitted, Shed> {
        self.admit_at(worker.get(), env)
    }

    fn release(&self, worker: WorkerId, env: &Envelope, admitted: Admitted) {
        self.release_at(worker.get(), env, admitted);
    }
}

impl InFlightCap {
    /// `admit` for the worker with this index.
    pub(crate) fn admit_at(&self, worker: u16, env: &Envelope) -> Result<Admitted, Shed> {
        let Some(shard) = self.shards.get(usize::from(worker)) else {
            // Not prepared: fail closed.
            return Err(Shed {
                retry_after: Some(self.base),
                close: true,
            });
        };
        // Single writer: this worker only.
        let now = shard.in_flight.load(Ordering::Relaxed);
        if now >= self.per_worker {
            return Err(self.shed(shard));
        }
        let p = usize::from(env.profile().0);
        let mut token = 0;
        match self.caps.get(p).copied().unwrap_or(ProfileCap::None) {
            ProfileCap::None => {}
            ProfileCap::Shares => {
                let share = self.shares[p * usize::from(self.workers) + usize::from(worker)];
                let count = &shard.profiles[p];
                let c = count.load(Ordering::Relaxed);
                if c >= share {
                    return Err(self.shed(shard));
                }
                count.store(c + 1, Ordering::Relaxed);
                token |= COUNTED_SHARE;
            }
            ProfileCap::Shared(cap) => {
                let counter = &self.shared[p];
                let mut c = counter.load(Ordering::Relaxed);
                loop {
                    if c >= cap {
                        return Err(self.shed(shard));
                    }
                    match counter.compare_exchange_weak(
                        c,
                        c + 1,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => c = actual,
                    }
                }
                token |= COUNTED_SHARED;
            }
        }
        shard.in_flight.store(now + 1, Ordering::Relaxed);
        Ok(Admitted { token })
    }

    /// `release` for the worker with this index.
    pub(crate) fn release_at(&self, worker: u16, env: &Envelope, admitted: Admitted) {
        let Some(shard) = self.shards.get(usize::from(worker)) else {
            return;
        };
        let now = shard.in_flight.load(Ordering::Relaxed);
        shard
            .in_flight
            .store(now.saturating_sub(1), Ordering::Relaxed);
        let p = usize::from(env.profile().0);
        if admitted.token & COUNTED_SHARE != 0 {
            if let Some(count) = shard.profiles.get(p) {
                let c = count.load(Ordering::Relaxed);
                count.store(c.saturating_sub(1), Ordering::Relaxed);
            }
        }
        if admitted.token & COUNTED_SHARED != 0 {
            if let Some(counter) = self.shared.get(p) {
                // Never below zero, even if release ran twice for one admission.
                let mut c = counter.load(Ordering::Relaxed);
                while c > 0 {
                    match counter.compare_exchange_weak(
                        c,
                        c - 1,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => c = actual,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Budget, KeepAlive, Limits, Profile, ProfileId};

    fn table(caps: &[Option<u32>]) -> ProfileTable {
        let profiles: Vec<Profile> = caps
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let b = match c {
                    Some(n) => Budget::new().max_in_flight(*n),
                    None => Budget::new(),
                };
                Profile::new(ProfileId(i as u8)).budget(b)
            })
            .collect();
        ProfileTable::compile(&profiles, Limits::new(), KeepAlive::new())
    }

    fn env(profile: u8) -> Envelope {
        let mut e = crate::envelope::tests::sample();
        e.profile = ProfileId(profile);
        e
    }

    #[test]
    fn test_in_flight_cap_per_worker_boundary() {
        let mut cap = InFlightCap::new().per_worker(2);
        cap.prepare(1, &table(&[None]));
        let w = 0;
        let a = cap.admit_at(w, &env(0)).unwrap();
        let b = cap.admit_at(w, &env(0)).unwrap();
        let shed = cap.admit_at(w, &env(0)).unwrap_err();
        assert!(shed.retry_after.unwrap() >= Duration::from_secs(1));
        assert!(shed.retry_after.unwrap() < Duration::from_secs(2));
        cap.release_at(w, &env(0), a);
        assert!(cap.admit_at(w, &env(0)).is_ok());
        cap.release_at(w, &env(0), b);
    }

    #[test]
    fn test_in_flight_cap_small_profile_cap_is_shared_and_exact() {
        let mut cap = InFlightCap::new();
        cap.prepare(8, &table(&[Some(3)]));
        let mut held = Vec::new();
        for k in 0..3u16 {
            held.push((k, cap.admit_at(k, &env(0)).unwrap()));
        }
        // Any worker is refused once the profile is full.
        assert!(cap.admit_at(7, &env(0)).is_err());
        let (k, a) = held.pop().unwrap();
        cap.release_at(k, &env(0), a);
        assert!(cap.admit_at(7, &env(0)).is_ok());
    }

    #[test]
    fn test_in_flight_cap_large_profile_cap_exact_shares() {
        let mut cap = InFlightCap::new();
        cap.prepare(4, &table(&[Some(18)]));
        let mut total = 0;
        for k in 0..4u16 {
            while cap.admit_at(k, &env(0)).is_ok() {
                total += 1;
            }
        }
        assert_eq!(total, 18);
    }

    #[test]
    fn test_in_flight_cap_unprepared_fails_closed() {
        let cap = InFlightCap::new();
        assert!(cap.admit_at(0, &env(0)).is_err());
    }

    #[test]
    fn test_in_flight_cap_counters_return_to_zero() {
        let mut cap = InFlightCap::new().per_worker(10);
        cap.prepare(2, &table(&[Some(1), None]));
        let w = 1;
        let a = cap.admit_at(w, &env(0)).unwrap();
        let b = cap.admit_at(w, &env(1)).unwrap();
        cap.release_at(w, &env(0), a);
        cap.release_at(w, &env(1), b);
        assert_eq!(cap.shards[1].in_flight.load(Ordering::Relaxed), 0);
        assert_eq!(cap.shared[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_jitter_bounds_hold() {
        let mut cap = InFlightCap::new()
            .per_worker(1)
            .retry_after(Duration::from_secs(5));
        cap.prepare(1, &table(&[None]));
        let w = 0;
        let _held = cap.admit_at(w, &env(0)).unwrap();
        for _ in 0..1000 {
            let r = cap.admit_at(w, &env(0)).unwrap_err().retry_after.unwrap();
            assert!(
                r >= Duration::from_secs(5) && r < Duration::from_secs(10),
                "{r:?}"
            );
        }
    }
}
