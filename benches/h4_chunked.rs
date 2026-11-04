//! H4: chunked decode of 1 MiB in 4 KiB chunks.
//!
//! Input: the body part of http-net's `body_1mib/chunked_4k` bench (256
//! chunks of 4096 bytes, the last chunk, an empty trailer section), whole
//! in memory. Both sides decode in place: each run of data is handed to the
//! sink as a slice of the input, nothing is copied.
//!
//! - `http_net/chunked_decoder`: `http_net::ChunkedDecoder` (the
//!   connections' decoder), stepped over the input.
//! - `httparse/parse_chunk_size_loop`: a loop over
//!   `httparse::parse_chunk_size` with the checks http-net's decoder makes
//!   on this input: body budget before each chunk, data present, CRLF after
//!   the data, empty trailer section (see `src/chunked.rs`).
//! - `*_copy_out`: both again, each delivering the body into one reused
//!   contiguous buffer. The slice-only variants touch only the 256 chunk
//!   lines, never the data, so their bytes-per-second figure is not a
//!   memory-bandwidth number; the copy-out variants are.
//! - `picohttpparser/phr_decode_chunked`: report only. It decodes in place
//!   by moving each chunk's data down over the chunk lines, so it is one
//!   move of every data byte and belongs next to the `*_copy_out` rows. It
//!   rewrites its input, so each iteration starts from a copy of the wire
//!   bytes, made outside the timed part.

use std::{hint::black_box, time::Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http_net_bench::{
    chunked,
    inputs::{CHUNKED_BODY_LEN, MAX_BODY, chunked_wire, limits},
    pico,
};

mod common;

fn bench_h4(c: &mut Criterion) {
    let limits = limits();
    let wire = chunked_wire();
    let mut group = c.benchmark_group("h4_chunked");
    group.throughput(Throughput::Bytes(CHUNKED_BODY_LEN as u64));

    group.bench_function("http_net/chunked_decoder", |b| {
        b.iter(|| {
            black_box(chunked::http_net_decode(black_box(&wire), &limits, |d| {
                black_box(d);
            }))
        })
    });
    group.bench_function("httparse/parse_chunk_size_loop", |b| {
        b.iter(|| {
            black_box(chunked::httparse_decode(black_box(&wire), MAX_BODY, |d| {
                black_box(d);
            }))
        })
    });

    // The same decoders delivering the body into one contiguous buffer
    // (one copy of every data byte, the buffer reused): what a caller that
    // needs the body in one piece pays, and the part of the work the
    // slice-only variants above leave out.
    let mut body = Vec::with_capacity(CHUNKED_BODY_LEN);
    group.bench_function("http_net/chunked_decoder_copy_out", |b| {
        b.iter(|| {
            body.clear();
            let done = chunked::http_net_decode(black_box(&wire), &limits, |d| {
                body.extend_from_slice(d);
            });
            black_box((done, body.len()))
        })
    });
    group.bench_function("httparse/parse_chunk_size_loop_copy_out", |b| {
        b.iter(|| {
            body.clear();
            let done = chunked::httparse_decode(black_box(&wire), MAX_BODY, |d| {
                body.extend_from_slice(d);
            });
            black_box((done, body.len()))
        })
    });

    let mut scratch = wire.clone();
    group.bench_function("picohttpparser/phr_decode_chunked", |b| {
        b.iter_custom(|iters| {
            let mut timed = std::time::Duration::ZERO;
            for _ in 0..iters {
                scratch.copy_from_slice(&wire);
                let start = Instant::now();
                let done = pico::decode_chunked(black_box(&mut scratch), MAX_BODY);
                timed += start.elapsed();
                black_box(done).expect("the bench input decodes");
            }
            timed
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::config();
    targets = bench_h4
}
criterion_main!(benches);
