//! Shared harness for the http-net competitor benchmarks.
//!
//! Everything a bench measures is defined here once, so that the benches in
//! `benches/` and the checks in `tests/equivalence.rs` run exactly the same
//! code on exactly the same bytes:
//!
//! - [`inputs`]: the wire inputs (the same ones http-net's own benches use).
//! - [`net`]: the http-net side of each workload.
//! - [`framing`]: the framing pass run after `httparse`, with the rules
//!   http-net applies, so both sides answer the same questions.
//! - [`chunked`]: the chunked-body loops for both sides.
//! - [`rt`]: hyper and the bare transport baseline over an in-memory
//!   `tokio::io::duplex` stream on a current-thread runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chunked;
pub mod framing;
pub mod inputs;
pub mod net;
pub mod rt;

/// How this build's `httparse` was compiled: `"simd"` (the default, runtime
/// SIMD detection) or `"nosimd"` (built with
/// `RUSTFLAGS='--cfg httparse_disable_simd="1"'`). Bench groups that run
/// `httparse` (directly or inside hyper) carry it in their name so the two
/// modes never overwrite each other's results.
pub const HTTPARSE_MODE: &str = if cfg!(httparse_disable_simd = "1") {
    "nosimd"
} else {
    "simd"
};
