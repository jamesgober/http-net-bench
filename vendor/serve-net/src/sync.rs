//! The synchronization primitives serve-net's shared state uses: `std`'s in
//! normal builds, loom's under `cfg(serve_net_loom)` so the models in `loom_tests` can
//! explore every interleaving.

#[cfg(serve_net_loom)]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64};
#[cfg(serve_net_loom)]
pub(crate) use loom::sync::{Mutex, MutexGuard};
#[cfg(not(serve_net_loom))]
pub(crate) use std::sync::atomic::{AtomicU32, AtomicU64};
#[cfg(not(serve_net_loom))]
pub(crate) use std::sync::{Mutex, MutexGuard};
