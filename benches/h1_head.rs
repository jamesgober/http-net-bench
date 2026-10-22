//! H1: parse a request head and determine its framing.
//!
//! Input: the 12-field, ~500-byte browser GET of http-net's own benches.
//! Every function answers the same questions about it: method, target,
//! field count, head length, body framing, keep-alive, `host` present.
//!
//! - `http_net/parse_request_head/{16,32}`: the stateless Tier-3 parser
//!   into a caller array of 16 or 32 field records; framing, keep-alive,
//!   and `host` read from the view.
//! - `httparse/parse_and_framing/{16,32}`: `httparse::Request::parse`
//!   (default, strict configuration) into 16 or 32 headers, then the
//!   framing pass of `src/framing.rs` (http-net's rules; see that file for
//!   exactly what it checks).
//! - `httparse/parse_only/16`: reference, the parse without the framing
//!   pass, to show what the pass costs.
//! - `http_net/server_conn_head`: reference, the same head through a reused
//!   `ServerConn` (copy into its buffer, resumable scan), up to the head
//!   event, then `reset`.
//!
//! The group name carries the httparse build mode (`h1_head_simd` or
//! `h1_head_nosimd`); `scripts/run.sh` runs both.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http_net::{FieldSpan, ServerConn};
use http_net_bench::{
    HTTPARSE_MODE, framing,
    inputs::{BROWSER_GET, MAX_BODY, limits},
    net,
};

mod common;

fn bench_h1(c: &mut Criterion) {
    let limits = limits();
    let mut group = c.benchmark_group(format!("h1_head_{HTTPARSE_MODE}"));
    group.throughput(Throughput::Bytes(BROWSER_GET.len() as u64));

    group.bench_function("http_net/parse_request_head/16", |b| {
        b.iter(|| {
            let mut fields = [FieldSpan::default(); 16];
            let summary = net::parse_head(black_box(BROWSER_GET), &limits, &mut fields);
            black_box(&summary);
        })
    });
    group.bench_function("httparse/parse_and_framing/16", |b| {
        b.iter(|| {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let summary = framing::httparse_head(black_box(BROWSER_GET), &mut headers, MAX_BODY);
            black_box(&summary);
        })
    });
    group.bench_function("http_net/parse_request_head/32", |b| {
        b.iter(|| {
            let mut fields = [FieldSpan::default(); 32];
            let summary = net::parse_head(black_box(BROWSER_GET), &limits, &mut fields);
            black_box(&summary);
        })
    });
    group.bench_function("httparse/parse_and_framing/32", |b| {
        b.iter(|| {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let summary = framing::httparse_head(black_box(BROWSER_GET), &mut headers, MAX_BODY);
            black_box(&summary);
        })
    });
    group.bench_function("httparse/parse_only/16", |b| {
        b.iter(|| {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            let status = req.parse(black_box(BROWSER_GET));
            black_box((&status, &req));
        })
    });
    let mut conn = ServerConn::with_limits(limits);
    group.bench_function("http_net/server_conn_head", |b| {
        b.iter(|| black_box(net::server_conn_head(&mut conn, black_box(BROWSER_GET))))
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::config();
    targets = bench_h1
}
criterion_main!(benches);
