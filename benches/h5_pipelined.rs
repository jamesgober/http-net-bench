//! H5: 100,000 pipelined requests on one connection.
//!
//! Input: `GET /item/42` with `Host` and `Accept`, 100,000 times (the
//! request mix of http-net's `pipelined_100k` bench), sent in 16 KiB
//! pieces; every request answered `204 No Content`. Each iteration is a
//! fresh connection; its setup is not timed.
//!
//! - `http_net/server_conn`: a new `ServerConn` fed 16 KiB at a time,
//!   `respond` for each request (http-net's own driver).
//! - `hyper/server_duplex_pipeline_flush`: hyper 1.x
//!   `server::conn::http1` with `pipeline_flush(true)` (and `date` off)
//!   over a `tokio::io::duplex` stream of 16 KiB, on a current-thread
//!   runtime; the client end writes 16 KiB pieces while reading responses
//!   until all 100,000 have arrived, then closes, and the server task is
//!   awaited.
//! - `baseline/executor_duplex`: the same runtime, duplex stream, and client
//!   loop, moving the same bytes each way, with a task that counts request
//!   bytes and writes one canned response per request: the executor and
//!   transport overhead inside `hyper/...`.
//!
//! One iteration takes milliseconds, so the group uses flat sampling (each
//! of the 100 samples runs the same number of iterations).

use std::hint::black_box;

use criterion::{BatchSize, Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use http_net::{Response, ServerConn};
use http_net_bench::{
    HTTPARSE_MODE,
    inputs::{PIPELINED_COUNT, PIPELINED_ONE, READ_SIZE, limits, pipelined_input},
    net, rt,
};

mod common;

fn bench_h5(c: &mut Criterion) {
    let input = pipelined_input();
    let mut group = c.benchmark_group(format!("h5_pipelined_{HTTPARSE_MODE}"));
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Elements(PIPELINED_COUNT as u64));

    let response = Response::new(204);
    group.bench_function("http_net/server_conn", |b| {
        b.iter_batched(
            || (ServerConn::with_limits(limits()), Vec::with_capacity(256)),
            |(mut conn, mut out)| {
                let n = net::serve_all(&mut conn, &input, READ_SIZE, &response, &mut out);
                assert_eq!(n, PIPELINED_COUNT);
            },
            BatchSize::LargeInput,
        )
    });

    let runtime = rt::runtime();
    // One request first, to learn the exact response bytes hyper writes.
    let one = {
        let (mut client, _server) = rt::spawn_hyper_server(
            &runtime,
            rt::PIPELINED_CAPACITY,
            true,
            rt::no_content_response,
        );
        rt::probe_response(&runtime, &mut client, PIPELINED_ONE)
    };
    let expected = one.len() * PIPELINED_COUNT;
    let mut buf = vec![0u8; 64 * 1024];

    group.bench_function("hyper/server_duplex_pipeline_flush", |b| {
        b.iter_batched(
            || {
                rt::spawn_hyper_server(
                    &runtime,
                    rt::PIPELINED_CAPACITY,
                    true,
                    rt::no_content_response,
                )
            },
            |(client, server)| {
                let got = runtime
                    .block_on(rt::drive_pipelined(
                        client, server, &input, READ_SIZE, expected, &mut buf,
                    ))
                    .expect("hyper pipelined");
                assert_eq!(got, expected);
            },
            BatchSize::PerIteration,
        )
    });

    group.bench_function("baseline/executor_duplex", |b| {
        b.iter_batched(
            || {
                rt::spawn_canned_pipelined_server(
                    &runtime,
                    rt::PIPELINED_CAPACITY,
                    PIPELINED_ONE.len(),
                    one.clone(),
                )
            },
            |(client, server)| {
                let got = runtime
                    .block_on(rt::drive_pipelined(
                        client, server, &input, READ_SIZE, expected, &mut buf,
                    ))
                    .expect("baseline pipelined");
                assert_eq!(got, expected);
                black_box(got)
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::config();
    targets = bench_h5
}
criterion_main!(benches);
