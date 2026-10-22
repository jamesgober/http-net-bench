//! The criterion method of spec section 11.3, shared by every bench.

use std::time::Duration;

use criterion::Criterion;

/// 3 s measurement, 1 s warm-up, 100 samples. Command-line flags
/// (`--measurement-time`, `--warm-up-time`, `--sample-size`) override
/// these; `scripts/run.sh --smoke` uses that for a short run.
pub fn config() -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(3))
        .warm_up_time(Duration::from_secs(1))
        .sample_size(100)
}
