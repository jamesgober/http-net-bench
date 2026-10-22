//! H3: response parse, client side.
//!
//! Input: the response of http-net's `response_parse` bench, `200 OK` with
//! `content-type`, `date`, `content-length: 1024`, and a 1 KiB JSON-like
//! body.
//!
//! Head only (status, field count, head length, framing, keep-alive):
//!
//! - `http_net/parse_response_head`: the stateless Tier-3 parser into 16
//!   field records, facts read from the view.
//! - `httparse/parse_and_framing`: `httparse::Response::parse` into 16
//!   headers, then the response framing pass of `src/framing.rs`
//!   (http-net's rules: status range, 1xx/204/304, transfer-encoding and
//!   content-length, keep-alive).
//!
//! Whole exchange (request out, response in, body delivered):
//!
//! - `http_net/client_conn_exchange`: a reused `ClientConn`, as http-net's
//!   own bench: `send_request`, feed the response, poll to its end.
//! - `hyper/client_duplex`: hyper 1.x `client::conn::http1` over a
//!   `tokio::io::duplex` stream on a current-thread runtime; a task on the
//!   other end reads the request and writes the response bytes; the body is
//!   collected.
//! - `baseline/executor_duplex`: the same runtime, duplex stream, and
//!   server task, moving the same bytes each way, with no HTTP on the
//!   client end: the executor and transport overhead inside `hyper/...`.
//!
//! The group name carries the httparse build mode (hyper parses with
//! httparse too); `scripts/run.sh` runs both.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http_net::{ClientConn, FieldSpan, Request};
use http_net_bench::{
    HTTPARSE_MODE, framing,
    inputs::{CLIENT_HOST, CLIENT_PATH, MAX_BODY, json_response_wire, limits},
    net, rt,
};

mod common;

fn bench_h3(c: &mut Criterion) {
    let limits = limits();
    let wire = json_response_wire();
    let mut group = c.benchmark_group(format!("h3_response_{HTTPARSE_MODE}"));
    group.throughput(Throughput::Bytes(wire.len() as u64));

    group.bench_function("http_net/parse_response_head", |b| {
        b.iter(|| {
            let mut fields = [FieldSpan::default(); 16];
            black_box(net::parse_response(black_box(&wire), &limits, &mut fields))
        })
    });
    group.bench_function("httparse/parse_and_framing", |b| {
        b.iter(|| {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            black_box(framing::httparse_response(
                black_box(&wire),
                &mut headers,
                MAX_BODY,
            ))
        })
    });

    let request = Request::get(CLIENT_PATH).header("host", CLIENT_HOST);
    let mut conn = ClientConn::with_limits(limits);
    let mut out = Vec::with_capacity(256);
    group.bench_function("http_net/client_conn_exchange", |b| {
        b.iter(|| {
            let status =
                net::client_exchange(&mut conn, &request, black_box(&wire), &mut out, |b| {
                    black_box(b);
                });
            black_box(status)
        })
    });

    let runtime = rt::runtime();
    let request_wire = rt::hyper_client_request_wire();
    let uri = rt::client_uri();
    let mut sender = rt::hyper_client(&runtime, request_wire.len(), wire.clone());
    group.bench_function("hyper/client_duplex", |b| {
        b.iter(|| {
            let got = runtime
                .block_on(rt::hyper_get(&mut sender, &uri))
                .expect("hyper exchange");
            black_box(got)
        })
    });

    let (mut client, _server) = rt::spawn_canned_server(
        &runtime,
        rt::EXCHANGE_CAPACITY,
        request_wire.len(),
        wire.clone(),
    );
    let mut buf = vec![0u8; wire.len()];
    group.bench_function("baseline/executor_duplex", |b| {
        b.iter(|| {
            runtime
                .block_on(rt::round_trip(
                    &mut client,
                    black_box(&request_wire),
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
    targets = bench_h3
}
criterion_main!(benches);
