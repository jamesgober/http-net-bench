//! Tables that can be swapped live.

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};

use crate::sync::{AtomicU64, Mutex};

/// A value that can be replaced while readers use it: a reader sees a whole
/// old value or a whole new one, never a mix.
///
/// A writer that panics cannot leave the value half-written (the value is a
/// whole `Arc`), so a poisoned lock is recovered, never unwrapped.
///
/// ```
/// use serve_net::Snapshot;
///
/// let table = Snapshot::new(vec!["a", "b"]);
/// let mut reader = table.reader();
/// assert_eq!(reader.get(&table).len(), 2);
/// table.publish(vec!["a", "b", "c"]);
/// assert_eq!(reader.get(&table).len(), 3);
/// ```
#[derive(Debug)]
pub struct Snapshot<T> {
    version: AtomicU64,
    current: Mutex<Arc<T>>,
}

impl<T: Send + Sync> Snapshot<T> {
    /// A snapshot holding `value`, at version 1.
    pub fn new(value: T) -> Self {
        Snapshot {
            version: AtomicU64::new(1),
            current: Mutex::new(Arc::new(value)),
        }
    }

    /// Replaces the value; readers see it at their next `get`.
    pub fn publish(&self, value: T) {
        let next = Arc::new(value);
        let mut guard = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = next;
        // Bumped while the lock is held, so a reader that sees the new
        // version and takes the lock always finds the new value.
        self.version.fetch_add(1, Ordering::AcqRel);
        drop(guard);
    }

    /// The current value (takes the lock; not for hot paths).
    pub fn load(&self) -> Arc<T> {
        Arc::clone(&self.current.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// A reader that caches the current value.
    pub fn reader(&self) -> SnapshotReader<T> {
        let guard = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        let version = self.version.load(Ordering::Acquire);
        SnapshotReader {
            cached: Arc::clone(&guard),
            version,
        }
    }

    /// The version: 1 at creation, plus one per `publish`.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

/// A per-worker cache of a [`Snapshot`]'s value.
#[derive(Debug)]
pub struct SnapshotReader<T> {
    cached: Arc<T>,
    version: u64,
}

impl<T: Send + Sync> SnapshotReader<T> {
    /// The value; one acquire load when nothing changed.
    #[inline]
    pub fn get(&mut self, source: &Snapshot<T>) -> &T {
        let v = source.version.load(Ordering::Acquire);
        if v != self.version {
            let guard = source
                .current
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.cached = Arc::clone(&guard);
            self.version = source.version.load(Ordering::Acquire);
        }
        &self.cached
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_reader_sees_whole_values() {
        let s = Snapshot::new((1u32, 1u32));
        let mut r = s.reader();
        assert_eq!(*r.get(&s), (1, 1));
        s.publish((2, 2));
        s.publish((3, 3));
        assert_eq!(*r.get(&s), (3, 3));
        assert_eq!(s.version(), 3);
        assert_eq!(*s.load(), (3, 3));
    }

    #[test]
    fn test_snapshot_concurrent_publish_never_mixes() {
        let s = Arc::new(Snapshot::new([0u64; 4]));
        let writer = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for i in 1..2000u64 {
                    s.publish([i; 4]);
                }
            })
        };
        let mut r = s.reader();
        for _ in 0..20_000 {
            let v = r.get(&s);
            assert!(v.iter().all(|&x| x == v[0]));
        }
        writer.join().unwrap();
        assert_eq!(*r.get(&s), [1999; 4]);
    }

    #[test]
    fn test_snapshot_is_send_sync() {
        fn check<T: Send + Sync>() {}
        check::<Snapshot<Vec<u8>>>();
        check::<SnapshotReader<Vec<u8>>>();
    }
}
