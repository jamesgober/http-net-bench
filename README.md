<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>http-net-bench</b>
    <br>
    <sub><sup>COMPETITOR BENCHMARKS FOR HTTP-NET</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/http-net"><img alt="http-net on crates.io" src="https://img.shields.io/crates/v/http-net?label=http-net"></a>
    <a href="https://github.com/jamesgober/http-net-bench/actions"><img alt="CI" src="https://github.com/jamesgober/http-net-bench/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>http-net-bench</strong> measures <a href="https://github.com/jamesgober/http-net">http-net</a>, a sans-IO HTTP/1.1 engine, against <a href="https://crates.io/crates/httparse">httparse</a> and <a href="https://crates.io/crates/hyper">hyper</a> on identical input bytes, and reports it next to <a href="https://github.com/h2o/picohttpparser">picohttpparser</a>, <a href="https://github.com/nodejs/llhttp">llhttp</a>, and real socket servers. Each comparison is independent of http-net's own benches and reproducible from this repository alone: the competitor versions are pinned by the committed <code>Cargo.lock</code> and <a href="./vendor/README.md"><code>vendor/</code></a>, http-net comes from crates.io, and one script builds, pins, runs, and records the machine.
    </p>
    <p>
        It is a separate, unpublished repository because http-net must never depend on tokio, hyper, or httparse, not even as a dev-dependency of its benches. Those crates, and the C parsers, are allowed here and only here.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). Not published (<code>publish = false</code>). Benchmarks are never run in CI: CI builds the harness, lints it, and runs the equivalence tests.
    </p>
</div>

<hr>
<br>

## Workloads

The workloads of http-net's specification, section 11.3. Every input is defined once in [`src/inputs.rs`](./src/inputs.rs). H1 to H5 use http-net's own bench inputs (`benches/bench.rs` in http-net) byte for byte; H6 uses the request of TechEmpower's plaintext test.

| Id | Workload | http-net side | Competitor | Bench |
|---|---|---|---|---|
| H1 | Parse a request head and decide its framing (12-field, ~500-byte browser GET) | `parse_request_head` (stateless, caller field array of 16 or 32), facts read from the view; `ServerConn` head-only as a reference | `httparse::Request::parse` (default, strict configuration) into 16 or 32 headers, then the [framing pass](./src/framing.rs); parse-only as a reference. Report only: `phr_parse_request` ([picohttpparser](./src/pico.rs)) with the same pass, compiled with and without SSE4.2 | [`h1_head`](./benches/h1_head.rs) |
| H2 | Full server exchange in memory, keep-alive: browser GET in, `200` with five fields and a 1 KiB body out | `ServerConn` fed the request, `respond` with a prebuilt `Response`; and with the `Response` built per request | hyper 1.x `server::conn::http1` over `tokio::io::duplex` on a current-thread runtime | [`h2_exchange`](./benches/h2_exchange.rs) |
| H3 | Response parse, client side (`200`, three fields, 1 KiB body) | `parse_response_head` plus facts; full `ClientConn` exchange | `httparse::Response::parse` plus the response framing pass; hyper 1.x `client::conn::http1` over a duplex stream | [`h3_response`](./benches/h3_response.rs) |
| H4 | Chunked decode, 1 MiB in 4 KiB chunks | `ChunkedDecoder` | a loop over `httparse::parse_chunk_size` with the same checks ([`src/chunked.rs`](./src/chunked.rs)). Report only: `phr_decode_chunked` | [`h4_chunked`](./benches/h4_chunked.rs) |
| H5 | 100,000 pipelined `GET /item/42` (with `Host` and `Accept`) in 16 KiB reads, each answered `204` | `ServerConn` | hyper 1.x server with `pipeline_flush(true)` over a 16 KiB duplex stream. Report only: [llhttp](./src/llhttp.rs) with callbacks that do a server's reading and answer each request, and with one that only counts | [`h5_pipelined`](./benches/h5_pipelined.rs) |
| H6 | Plaintext over 127.0.0.1 sockets, report only: `GET /plaintext` answered with `Hello, World!`, on 1 connection and 16, one request or 16 pipelined at a time | serve-net 0.3 over `ServerConn`: http-net through a whole server, on net-io's blocking driver | hyper 1.x on a current-thread tokio runtime, actix-web 4 with one worker, may-minihttp on one `may` worker | [`h6_server`](./src/bin/h6_server.rs), [`h6_load`](./src/bin/h6_load.rs) |

"Report only" is the specification's term: those rows are there to read, and no http-net target depends on them.

<br>

## Fairness rules

- **Same bytes.** Both sides of a comparison read the same input from [`src/inputs.rs`](./src/inputs.rs); a bench never generates its own.
- **Same work, checked.** [`tests/equivalence.rs`](./tests/equivalence.rs) runs the exact functions the benches time and asserts that they agree: the same method, target, field count, head length, framing, keep-alive, and `Host` answer (H1); the framing pass accepting and refusing the same 39 request heads and 14 response heads as http-net, with the same error; the same status, fields, and body for every response hyper and http-net produce (H2, H3, H5, all 100,000 responses of H5 compared); the same decoded body (H4). picohttpparser with the pass answers the same on the same 39 heads; llhttp sees the same method, target, field count, `host`, and keep-alive on all 100,000 requests of H5 and refuses what http-net refuses on the cases it is given; with the `h6` feature, every H6 server answers the same status, `content-type`, `content-length`, and body, and stays open past 1,000 requests a connection. CI runs it on every push.
- **httparse is only a parser, so it gets the framing pass.** http-net's parser also decides how the body is framed, whether the connection stays open, and whether the head is acceptable. Timing httparse alone would compare unequal work. The pass in [`src/framing.rs`](./src/framing.rs) is shaped like hyper's role code (one walk over the fields, a match on the name) but applies http-net's rules, no more and no less: `Content-Length` with duplicate and list rejection, `Transfer-Encoding` that must end in `chunked`, the CL and TE conflict, TE in HTTP/1.0, the body budget, `Connection` keep-alive and close, `Host` count and value, upgrade and `Expect`, and the percent escapes of the target. Its header comment lists each check and where hyper's own rules differ. A parse-only bench shows what the pass costs.
- **picohttpparser is only a parser too, so it gets the same pass.** The pass is generic over the parser ([`FieldLine`](./src/framing.rs)), so both Rust and C heads run the same code after the parse.
- **httparse with and without SIMD.** httparse picks SIMD at run time; `scripts/run.sh` also builds it with SIMD compiled out and runs H1 and H3 both ways. httparse 1.10.1's build script disables SIMD only when the cfg value is exactly `"1"`, so the flag is `RUSTFLAGS='--cfg httparse_disable_simd="1"'`; the bare `--cfg httparse_disable_simd` builds with SIMD on. The script checks the build output to prove the switch took effect, and bench groups carry the mode in their name (`h1_head_simd`, `h1_head_nosimd`).
- **picohttpparser with and without SSE4.2.** It chooses SSE4.2 at compile time, not at run time, so `build.rs` compiles it twice, the second copy under renamed symbols, and H1 has both in one binary (`picohttpparser/...`, `picohttpparser_scalar/...`). The bench group's `_simd` or `_nosimd` suffix is httparse's mode and does not touch these rows.
- **hyper's executor overhead is reported separately.** Every hyper bench has a `baseline/executor_duplex` twin in the same group: the same runtime, duplex stream, and client loop, moving the same bytes each way, with the HTTP side replaced by a task that reads a fixed number of bytes and writes canned response bytes. Subtracting it from the hyper row estimates hyper's own cost.
- **hyper set up the cheap way.** `date` off (http-net's sans-IO core writes none either), no header-read timer, header names and values from compile-time constants, static bodies, the request URI parsed once and cloned. hyper must build an `http::Response` per request, so H2 also times http-net building its `Response` per request.
- **In-place chunked decoding for both.** H4 hands each run of data to the sink as a slice of the input; neither side copies. Those variants touch only the 256 chunk lines, so their bytes-per-second figure is framing cost, not memory bandwidth; the `*_copy_out` variants deliver the body into one reused contiguous buffer on both sides.
- **`phr_decode_chunked` belongs next to the copy-out rows.** It decodes in place by moving each chunk's data down over the chunk lines before it, one move of every data byte, so its row compares with the `*_copy_out` rows of H4. It rewrites its input, so each iteration restores the wire bytes outside the timed part.
- **llhttp is answered the way http-net is fed.** Both get the same 16 KiB reads. `llhttp/parse_and_answer` copies each span into a reused head buffer (a span can cross a read, and `ServerConn` copies its input too), indexes the fields, counts `host`, reads keep-alive, and writes the bytes http-net wrote. `llhttp/count_only` is the shape of llhttp's own benchmark table: one callback, no field read.
- **H6 pins the server, not the pair.** Each server is a fresh process pinned to one core with `taskset`, set up for one worker, with `TCP_NODELAY` on, and the load generator runs on other cores, never the server core's SMT sibling. may-minihttp does not set `TCP_NODELAY` itself, and without it batches of about 1 KiB and up stall, so `h6_server` sets it through the factory form of its server. The generator is closed-loop and the same for all, with one blocking thread per connection; it checks every batch and fails the run if a server closes a connection. The results file gives the CPU the server used: at 100% the server set the rate, and below it the generator did, which is expected on one connection, where the server idles while the client turns around.
- **A control for machine drift.** The two httparse modes of H1 and H3 run back to back, and the http-net rows (which do not use httparse) are measured in both. If the http-net rows move between `_simd` and `_nosimd`, the machine moved, and the httparse difference cannot be read from that run.
- **Same code generation.** `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`: http-net's release profile, applied to every crate in the bench build, the H6 servers included. The C sources get `-O3` and `-msse4.2` from `build.rs`, in every profile.

What could not be made identical, and how it is handled:

- hyper owns its I/O: it reads from and writes to the duplex stream, so its numbers include moving the bytes through a runtime. The baseline twin measures that part.
- http-net's `ServerConn` copies input into its own buffer, while `parse_request_head` and httparse parse in place; `http_net/server_conn_head` is in H1 as a reference for that difference, not as the comparison.
- The framing pass validates non-origin targets (absolute and authority form) by their first byte only. No bench input uses them.
- The C parsers sit across an FFI boundary, with no inlining into the bench or from it. That costs about a nanosecond per call: one call per head in H1, one per body in H4, about seven callbacks per request in `llhttp/parse_and_answer`.
- picohttpparser accepts bare LF line ends, which http-net refuses, and has no body budget, so H4 checks the total at the end of the body. Neither is reachable on the bench inputs.
- llhttp's answer is a canned byte string, where http-net formats a prebuilt `Response`. That favours llhttp slightly. llhttp also does not check a `host` value; the driver only counts the field.
- H6 is a whole server each time. serve-net 0.3 has a blocking driver only (net-io 0.3): each connection holds a thread, and on one core the 16-connection shape switches threads on every batch, where hyper, actix-web, and may-minihttp multiplex connections on one thread. serve-net also does its own admission and reply accounting on each request, on top of http-net. The H6 table reads as what these servers do on one core, not as a parser comparison, and http-net's own cost is what H1, H2, and H5 show.
- The H6 servers write different field orders and spellings, and may-minihttp adds `Server: M` and writes the reason `Ok`. All send `date`, the only response field a per-request cost hangs on, and each caches it by the second. Response lengths differ by at most a few bytes.
- serve-net in H6 is a [vendored copy](./vendor/README.md) of the published 0.3.0 with one requirement changed, because 0.3.0 asks for http-net 0.6. http-net itself is 0.9 from crates.io, as everywhere here: `h6_server` proves it at compile time.

<br>

## Running

Linux or WSL (the script needs `taskset`, `/proc/cpuinfo`, and a C compiler as `cc`):

```bash
scripts/run.sh            # the method of spec section 11.3
scripts/run.sh --smoke    # 1 s per bench: checks that everything runs
CORE=5 scripts/run.sh     # pin to another core (default 3)
CLIENT_CORES=4,6,8,10 ROUNDS=5 scripts/run.sh    # H6: the load generator's cores, and the rounds
```

The script builds both httparse modes, runs H1 and H3 in both modes back to back and H2, H4, and H5 with SIMD on, each pinned with `taskset -c $CORE`, then H6 in interleaved rounds, and writes `results/<date>-<commit>.md` (`-smoke` for a smoke run, `-dirty` for uncommitted changes) with the machine (`uname -a`, CPU model, governor, load average at start and end), the compilers (`rustc -vV`, `cc --version`), the commit, every competitor's version, a table of medians, the H6 table, and the criterion output.

Method (spec section 11.3): criterion 0.5, 3 s measurement, 1 s warm-up, 100 samples. H5 uses flat sampling, since one iteration takes milliseconds. H6 is two processes, so it is timed by the generator: 1 s warm-up, 3 s measurement, five rounds, the median round reported. Fix the CPU governor to `performance` and disable turbo where the machine allows it; the results file records the governor.

One workload by hand:

```bash
cargo bench --bench h1_head
RUSTFLAGS='--cfg httparse_disable_simd="1"' CARGO_TARGET_DIR=target/nosimd cargo bench --bench h1_head
```

```bash
cargo build --release --features h6 --bin h6_server --bin h6_load
taskset -c 3 target/release/h6_server hyper 127.0.0.1:8080 &
taskset -c 4,6,8,10 target/release/h6_load 127.0.0.1:8080 16 16 1 3
```

Before a change to the harness: `cargo fmt --all`, `cargo clippy --all-targets --features h6 -- -D warnings`, `cargo test --features h6`, and `cargo bench --no-run` must be clean. The H6 servers sit behind the `h6` feature so that they never enter an H1 to H5 build.

<br>

## Results

Results files live in [`results/`](./results/). A file whose name ends in `-smoke` comes from a short run that only proves the benches work; its numbers are not measurements.

| File | http-net | Note |
|---|---|---|
| [`2026-10-29-c1255d143e57`](./results/2026-10-29-c1255d143e57.md) | 0.9.0 | The machine was shared with fuzzers (load average 6 to 12): absolute times are about half higher than on a quiet machine for both sides, so read the ratios within a group. A quiet-machine H1 run replaces it before http-net 1.0. |

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
