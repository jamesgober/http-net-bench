#!/usr/bin/env bash
# Runs every competitor benchmark (H1-H6), each pinned, and writes a results
# file under results/, named by date and commit.
#
# Usage:
#   scripts/run.sh            full run: the method of spec section 11.3
#                             (3 s measurement, 1 s warm-up, 100 samples)
#   scripts/run.sh --smoke    short run (1 s measurement, 1 s warm-up) to
#                             check that everything works; the results file
#                             is labelled as a smoke run, not a measurement
#
# Environment:
#   CORE=3                    the core to pin to (taskset -c); for H6, the
#                             core of the server
#   CLIENT_CORES=4,6,8,10     H6: the cores of the load generator; never the
#                             server core or its SMT sibling (lscpu -e)
#   ROUNDS=5                  H6: rounds of the interleaved server loop
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
# H6 is not a criterion bench: a server and a load generator run in two
# processes. Every server serves one shape at a time, on a fresh process, in
# interleaved rounds so that drift falls on all of them; the table has the
# median round.
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
CLIENT_CORES="${CLIENT_CORES:-4,6,8,10}"
ROUNDS="${ROUNDS:-5}"
H6_WARM_UP=1
H6_MEASURE=3
if [[ "$MODE" == "smoke" ]]; then
    ROUNDS=1
    H6_MEASURE=1
fi
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
H6_DATA="$(mktemp)"
trap 'rm -f "$LOG" "$H6_DATA"' EXIT
LOAD_START="$(cut -d' ' -f1-3 /proc/loadavg)"

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

echo "== build (H6 server and load generator)"
cargo build --release --locked --features h6 --bin h6_server --bin h6_load

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

# -------------------------------------------------------------------- H6

H6_SERVERS=(serve-net serve-net-blocking hyper actix-web may-minihttp)
H6_SHAPES=("1 1" "1 16" "16 16")
H6_PORT=18080

h6_round() {
    # h6_round <server> <connections> <pipeline>
    local server="$1" connections="$2" pipeline="$3" pid
    taskset -c "$CORE" "$TARGET/release/h6_server" "$server" "127.0.0.1:$H6_PORT" &
    pid=$!
    local line
    line="$(taskset -c "$CLIENT_CORES" "$TARGET/release/h6_load" "127.0.0.1:$H6_PORT" \
        "$connections" "$pipeline" "$H6_WARM_UP" "$H6_MEASURE" "$pid")" || {
        kill "$pid" 2>/dev/null
        return 1
    }
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null || true
    # A new port each time: no waiting on the old sockets in TIME_WAIT.
    H6_PORT=$((H6_PORT + 1))
    printf '%s\t%s\t%s\t%s\n' "$server" "$connections" "$pipeline" "$line" >> "$H6_DATA"
}

echo "== h6 (server on core $CORE, load on $CLIENT_CORES, $ROUNDS rounds)" | tee -a "$LOG"
for ((round = 1; round <= ROUNDS; round++)); do
    for shape in "${H6_SHAPES[@]}"; do
        read -r connections pipeline <<< "$shape"
        for server in "${H6_SERVERS[@]}"; do
            h6_round "$server" "$connections" "$pipeline"
        done
    done
done

h6_table() {
    # One row per server and shape: the median, lowest, and highest round.
    local shape server connections pipeline
    for shape in "${H6_SHAPES[@]}"; do
        read -r connections pipeline <<< "$shape"
        for server in "${H6_SERVERS[@]}"; do
            awk -F'\t' -v s="$server" -v c="$connections" -v p="$pipeline" '
                $1 == s && $2 == c && $3 == p { print $6, $7 }
            ' "$H6_DATA" | sort -n | awk -v s="$server" -v c="$connections" -v p="$pipeline" '
                { rate[NR] = $1; cpu[NR] = $2 }
                END {
                    mid = int((NR + 1) / 2)
                    printf("| %s | %d | %d | %.3f M/s | %.3f to %.3f | %s%% |\n",
                        s, c, p, rate[mid] / 1e6, rate[1] / 1e6, rate[NR] / 1e6, cpu[mid]);
                }
            '
        done
    done
}

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
    echo "| picohttpparser | \`dd573d8\` (vendored) |"
    echo "| llhttp | $(awk '/define LLHTTP_VERSION_(MAJOR|MINOR)/ { printf "%s.", $3 } /define LLHTTP_VERSION_PATCH/ { print $3 }' vendor/llhttp/llhttp.h) (vendored) |"
    echo "| serve-net | $(lock_version serve-net) |"
    echo "| net-io | $(lock_version net-io) |"
    echo "| actix-web | $(lock_version actix-web) |"
    echo "| may-minihttp | $(lock_version may_minihttp) |"
    echo "| C compiler | $(cc --version | head -1), \`-O3\`, \`-msse4.2\` except the scalar copy |"
    echo "| CPU | $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//') |"
    echo "| Pinned core | $CORE |"
    echo "| H6 load generator cores | $CLIENT_CORES |"
    echo "| Load average (first minute, five, fifteen) at start | $LOAD_START |"
    echo "| Load average at end | $(cut -d' ' -f1-3 /proc/loadavg) |"
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
    echo "## H6, plaintext over sockets"
    echo
    echo "Report only. Requests per second, closed loop, over 127.0.0.1, $ROUNDS"
    echo "rounds of ${H6_WARM_UP} s warm-up and ${H6_MEASURE} s measurement, each server a fresh process"
    echo "pinned to core $CORE. CPU is the server process in the median round,"
    echo "in percent of one core: at 100% the server set the rate."
    echo
    echo "| Server | Connections | Pipeline | Median | Rounds, lowest to highest | Server CPU |"
    echo "|---|---:|---:|---:|---:|---:|"
    h6_table
    echo
    echo "## Criterion output"
    echo
    echo '```text'
    grep -E '^== |^[a-z0-9_]+/|time:|thrpt:' "$LOG" || true
    echo '```'
} > "$OUT"

echo
echo "wrote $OUT"
