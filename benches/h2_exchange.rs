//! H2: a full server exchange in memory, keep-alive.
//!
//! Request bytes in (the 12-field browser GET), response bytes out (status
//! 200, the five fields of http-net's `response_write` bench, a 1 KiB body,
//! `content-length`), on one connection reused across iterations.
//!
//! - `http_net/respond_prebuilt`: a reused `ServerConn`: feed, poll to the
//!   end of the request, `respond` with a `Response` built once.
//! - `http_net/build_and_respond`: the same, with the `Response` built for
//!   each request, as a hyper service must build its `http::Response`.
//! - `hyper/server_duplex`: hyper 1.x `server::conn::http1` serving a
//!   `tokio::io::duplex` stream on a current-thread runtime; the client end
//!   writes the request and reads the whole response. `date` off (the
//!   sans-IO core adds none), header-read timeout off, everything else
//!   default. The service builds the response from compile-time header
//!   constants and a static body.
//! - `baseline/executor_duplex`: the same runtime, duplex stream, and client
//!   loop, moving the same bytes each way, with no HTTP: a task reads the
//!   request's length in bytes and writes hyper's response bytes back. This
//!   is the executor and transport overhead included in `hyper/...`.
//!
//! hyper parses with httparse, so the group name carries the httparse build
//! mode.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http_net::ServerConn;
use http_net_bench::{
    HTTPARSE_MODE,
    inputs::{BODY_1K, BROWSER_GET, FIVE_FIELDS, READ_SIZE, five_field_response, limits},
    net, rt,
};

mod common;

fn bench_h2(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("h2_exchange_{HTTPARSE_MODE}"));
    group.throughput(Throughput::Elements(1));

    let response = five_field_response();
    let mut conn = ServerConn::with_limits(limits());
    let mut out = Vec::with_capacity(4096);
    group.bench_function("http_net/respond_prebuilt", |b| {
        b.iter(|| {
            let n = net::serve_all(
                &mut conn,
                black_box(BROWSER_GET),
                READ_SIZE,
                &response,
                &mut out,
            );
            black_box((n, out.len()))
        })
    });

    let mut conn = ServerConn::with_limits(limits());
    group.bench_function("http_net/build_and_respond", |b| {
        b.iter(|| {
            let n = net::serve_one_building(
                &mut conn,
                black_box(BROWSER_GET),
                &FIVE_FIELDS,
                &BODY_1K,
                &mut out,
            );
            black_box((n, out.len()))
        })
    });

    let runtime = rt::runtime();
    let (mut client, _server) = rt::spawn_hyper_server(
        &runtime,
        rt::EXCHANGE_CAPACITY,
        false,
        rt::five_field_response,
    );
    // One exchange first, to learn the exact response bytes hyper writes.
    let hyper_bytes = rt::probe_response(&runtime, &mut client, BROWSER_GET);
    let mut buf = vec![0u8; hyper_bytes.len()];
    group.bench_function("hyper/server_duplex", |b| {
        b.iter(|| {
            runtime
                .block_on(rt::round_trip(
                    &mut client,
                    black_box(BROWSER_GET),
                    &mut buf,
                ))
                .expect("hyper exchange");
            black_box(buf[0])
        })
    });

    let (mut client, _server) = rt::spawn_canned_server(
        &runtime,
        rt::EXCHANGE_CAPACITY,
        BROWSER_GET.len(),
        hyper_bytes.clone(),
    );
    group.bench_function("baseline/executor_duplex", |b| {
        b.iter(|| {
            runtime
                .block_on(rt::round_trip(
                    &mut client,
                    black_box(BROWSER_GET),
                    &mut buf,
                ))
                .expect("baseline exchange");
            black_box(buf[0])
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::config();
    targets = bench_h2
}
criterion_main!(benches);
