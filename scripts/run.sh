#!/usr/bin/env bash
# Runs every competitor benchmark (H1-H5) pinned to one core and writes a
# results file under results/, named by date and commit.
#
# Usage:
#   scripts/run.sh            full run: the method of spec section 11.3
#                             (3 s measurement, 1 s warm-up, 100 samples)
#   scripts/run.sh --smoke    short run (1 s measurement, 1 s warm-up) to
#                             check that everything works; the results file
#                             is labelled as a smoke run, not a measurement
#
# Environment:
#   CORE=3                    the core to pin to (taskset -c)
#   CARGO_TARGET_DIR          honoured; the SIMD-off build goes in
#                             $CARGO_TARGET_DIR/nosimd so the two builds
#                             never invalidate each other
#
# H1 and H3 run twice: with httparse's default runtime SIMD detection, and
# with SIMD compiled out. httparse 1.10's build script disables SIMD only
# when CARGO_CFG_HTTPARSE_DISABLE_SIMD is exactly "1", so the flag must be
# --cfg httparse_disable_simd="1"; the bare --cfg httparse_disable_simd
# does nothing. The script checks the build script's output to prove the
# switch took effect.
#
# Linux only (taskset, /proc/cpuinfo); in WSL run it from the Linux side.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

MODE="measurement"
CRITERION_ARGS=()
if [[ "${1:-}" == "--smoke" ]]; then
    MODE="smoke"
    CRITERION_ARGS=(--measurement-time 1 --warm-up-time 1)
    shift
fi
if [[ $# -gt 0 ]]; then
    echo "usage: $0 [--smoke]" >&2
    exit 2
fi

CORE="${CORE:-3}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
NOSIMD_TARGET="$TARGET/nosimd"
NOSIMD_FLAGS='--cfg httparse_disable_simd="1"'

command -v taskset >/dev/null || { echo "taskset not found (util-linux)" >&2; exit 1; }

COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
DIRTY=""
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    DIRTY="-dirty"
fi
STAMP="$(date -u +%Y-%m-%d)"
NAME="${STAMP}-${COMMIT}${DIRTY}"
if [[ "$MODE" == "smoke" ]]; then
    NAME="${NAME}-smoke"
fi
mkdir -p results
OUT="results/${NAME}.md"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

# A fresh criterion directory per run, so the summary holds only this run.
CRITERION_DIR="$TARGET/criterion-runs/$NAME-$(date -u +%H%M%S)"
mkdir -p "$CRITERION_DIR"

lock_version() {
    # The version of a package in Cargo.lock.
    awk -v pkg="$1" '
        $0 == "name = \"" pkg "\"" { found = 1; next }
        found && /^version = / { gsub(/"/, "", $3); print $3; exit }
    ' Cargo.lock
}

echo "== build (httparse SIMD on)"
cargo bench --locked --no-run

echo "== build (httparse SIMD off)"
CARGO_TARGET_DIR="$NOSIMD_TARGET" RUSTFLAGS="$NOSIMD_FLAGS" \
    cargo bench --locked --no-run --bench h1_head --bench h3_response
if ! grep -qs "disabling SIMD" "$NOSIMD_TARGET"/release/build/httparse-*/output; then
    echo "httparse SIMD was not disabled in $NOSIMD_TARGET; refusing to label it nosimd" >&2
    exit 1
fi
if grep -qs "disabling SIMD" "$TARGET"/release/build/httparse-*/output; then
    echo "httparse SIMD is disabled in the default build ($TARGET); clean it first" >&2
    exit 1
fi

run_bench() {
    # run_bench <target dir> <rustflags> <bench>
    local dir="$1" flags="$2" bench="$3"
    echo "== $bench (httparse ${flags:+SIMD off: }${flags:-SIMD on}), pinned to core $CORE" | tee -a "$LOG"
    if [[ -n "$flags" ]]; then
        CARGO_TARGET_DIR="$dir" RUSTFLAGS="$flags" CRITERION_HOME="$CRITERION_DIR" \
            taskset -c "$CORE" cargo bench --locked --bench "$bench" -- "${CRITERION_ARGS[@]}" \
            2>&1 | tee -a "$LOG"
    else
        # The caller's RUSTFLAGS (if any) as in the build step above.
        CARGO_TARGET_DIR="$dir" CRITERION_HOME="$CRITERION_DIR" \
            taskset -c "$CORE" cargo bench --locked --bench "$bench" -- "${CRITERION_ARGS[@]}" \
            2>&1 | tee -a "$LOG"
    fi
}

# The two httparse modes of a workload run back to back, so slow drift in
# machine load or clock speed falls on both. The http-net rows, which do
# not use httparse, are measured in both runs and act as the control: if
# they move between `_simd` and `_nosimd`, the machine moved.
run_bench "$TARGET" "" h1_head
run_bench "$NOSIMD_TARGET" "$NOSIMD_FLAGS" h1_head
run_bench "$TARGET" "" h3_response
run_bench "$NOSIMD_TARGET" "$NOSIMD_FLAGS" h3_response
for bench in h2_exchange h4_chunked h5_pipelined; do
    run_bench "$TARGET" "" "$bench"
done

# ---------------------------------------------------------------- report

median_table() {
    # One row per benchmark: id, median, throughput from the median.
    find "$CRITERION_DIR" -path '*/new/estimates.json' | sort | while read -r est; do
        local dir id median elements bytes
        dir="$(dirname "$est")"
        id="$(sed -E 's/.*"full_id":"([^"]*)".*/\1/' "$dir/benchmark.json")"
        median="$(sed -E 's/.*"median":\{"confidence_interval":\{[^}]*\},"point_estimate":([0-9.eE+-]+).*/\1/' "$est")"
        elements="$(grep -o '"Elements":[0-9]*' "$dir/benchmark.json" | cut -d: -f2 || true)"
        bytes="$(grep -o '"Bytes":[0-9]*' "$dir/benchmark.json" | cut -d: -f2 || true)"
        awk -v id="$id" -v ns="$median" -v el="${elements:-0}" -v by="${bytes:-0}" 'BEGIN {
            if (ns >= 1e6) t = sprintf("%.3f ms", ns / 1e6);
            else if (ns >= 1e3) t = sprintf("%.3f us", ns / 1e3);
            else t = sprintf("%.1f ns", ns);
            rate = "";
            if (el > 1) rate = sprintf("%.2f M elem/s", el / ns * 1e3);
            else if (by > 0) {
                mib = by / ns * 1e9 / 1048576;
                if (mib >= 1024) rate = sprintf("%.2f GiB/s", mib / 1024);
                else rate = sprintf("%.1f MiB/s", mib);
            }
            printf("| `%s` | %s | %s |\n", id, t, rate);
        }'
    done
}

{
    if [[ "$MODE" == "smoke" ]]; then
        echo "# SMOKE RUN, NOT A MEASUREMENT"
        echo
        echo "This file comes from \`scripts/run.sh --smoke\`: 1 s measurement and 1 s"
        echo "warm-up instead of the 3 s / 1 s / 100 samples of spec section 11.3,"
        echo "with no control of CPU frequency or machine load. It shows that every"
        echo "bench builds and runs. Do not quote these numbers."
    else
        echo "# Competitor benchmark results"
        echo
        echo "Method: criterion 0.5, 3 s measurement, 1 s warm-up, 100 samples"
        echo "(spec section 11.3), pinned with \`taskset -c $CORE\`."
    fi
    echo
    echo "## Machine and build"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Date (UTC) | $(date -u '+%Y-%m-%d %H:%M') |"
    echo "| Commit | \`${COMMIT}${DIRTY}\` |"
    echo "| http-net | $(lock_version http-net) (crates.io) |"
    echo "| httparse | $(lock_version httparse) |"
    echo "| hyper | $(lock_version hyper) |"
    echo "| tokio | $(lock_version tokio) |"
    echo "| CPU | $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//') |"
    echo "| Pinned core | $CORE |"
    echo "| Governor | $(cat "/sys/devices/system/cpu/cpu$CORE/cpufreq/scaling_governor" 2>/dev/null || echo 'not exposed') |"
    echo "| Criterion args | ${CRITERION_ARGS[*]:-none (defaults of the benches)} |"
    echo "| RUSTFLAGS (SIMD-on build) | ${RUSTFLAGS:-unset} |"
    echo "| RUSTFLAGS (SIMD-off build) | \`$NOSIMD_FLAGS\` |"
    echo
    echo '```text'
    uname -a
    echo
    rustc -vV
    echo '```'
    echo
    echo "## Medians"
    echo
    echo "Group names end in the httparse build mode (\`_simd\`: default runtime"
    echo "detection; \`_nosimd\`: SIMD compiled out). hyper parses with httparse,"
    echo "so its groups carry the mode too. \`baseline/executor_duplex\` is the"
    echo "runtime and duplex transport alone, with no HTTP: subtract it from the"
    echo "\`hyper/...\` row of the same group to estimate hyper's own cost."
    echo
    echo "| Benchmark | Median | Throughput at the median |"
    echo "|---|---:|---:|"
    median_table
    echo
    echo "## Criterion output"
    echo
    echo '```text'
    grep -E '^== |^[a-z0-9_]+/|time:|thrpt:' "$LOG" || true
    echo '```'
} > "$OUT"

echo
echo "wrote $OUT"
