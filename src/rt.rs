//! hyper, and a bare transport baseline, over an in-memory
//! `tokio::io::duplex` stream on a current-thread runtime (workloads H2, H3,
//! and H5).
//!
//! Every hyper measurement has a twin with no HTTP in it: the same runtime,
//! the same duplex stream, the same client loop, the same number of bytes
//! each way, but the HTTP side replaced by a task that reads a fixed number
//! of request bytes and writes canned response bytes. That twin is the
//! executor and transport overhead the spec asks to report separately;
//! subtracting it from the hyper number estimates hyper's own HTTP cost.

use std::{convert::Infallible, hint::black_box, io};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    client::conn::http1 as client_http1,
    header::{self, HeaderName, HeaderValue},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    runtime::Runtime,
    task::JoinHandle,
};

use crate::inputs::{BODY_1K, CLIENT_HOST, CLIENT_PATH, FIVE_FIELDS, READ_SIZE};

/// The duplex capacity of the one-exchange workloads (H2, H3): large enough
/// that one request or response never waits for the other side.
pub const EXCHANGE_CAPACITY: usize = 64 * 1024;

/// The duplex capacity of the pipelined workload (H5): the 16 KiB read size,
/// so hyper reads at most 16 KiB at a time, as http-net is fed.
pub const PIPELINED_CAPACITY: usize = READ_SIZE;

/// A current-thread runtime with no I/O or time driver (the duplex stream
/// needs neither, and no hyper timer is configured).
///
/// # Panics
///
/// If the runtime cannot be built.
#[must_use]
pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}

// The H2 response fields as hyper constants: names and values are built at
// compile time from static strings, the cheapest way hyper offers.
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");
const HYPER_FIELDS: [(HeaderName, HeaderValue); 5] = [
    (
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript"),
    ),
    (
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=31536000, immutable"),
    ),
    (
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ),
    (
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    ),
    (CORP, HeaderValue::from_static("same-origin")),
];

/// The H2 response for hyper: status 200, the five fields of
/// [`FIVE_FIELDS`] (same names and values), and the 1 KiB body (hyper adds
/// `content-length`).
#[must_use]
pub fn five_field_response() -> Response<Full<Bytes>> {
    debug_assert_eq!(HYPER_FIELDS.len(), FIVE_FIELDS.len());
    let mut response = Response::new(Full::new(Bytes::from_static(&BODY_1K)));
    let headers = response.headers_mut();
    for (name, value) in HYPER_FIELDS {
        headers.insert(name, value);
    }
    response
}

/// Spawns a hyper HTTP/1.1 server connection on `rt` over a new duplex
/// stream of `capacity`, answering every request with `respond`, and
/// returns the client end and the connection task. `auto_date_header` is
/// off (http-net's sans-IO core adds no `date` either); `pipeline_flush`
/// as given; everything else is hyper's default (keep-alive on).
pub fn spawn_hyper_server<B, F>(
    rt: &Runtime,
    capacity: usize,
    pipeline_flush: bool,
    respond: F,
) -> (DuplexStream, JoinHandle<()>)
where
    F: Fn() -> Response<B> + Send + Sync + Copy + 'static,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (client, server) = duplex(capacity);
    let task = rt.spawn(async move {
        let service = service_fn(move |req: Request<Incoming>| async move {
            black_box(req.uri().path());
            Ok::<_, Infallible>(respond())
        });
        let _ = server_http1::Builder::new()
            .auto_date_header(false)
            .header_read_timeout(None)
            .pipeline_flush(pipeline_flush)
            .serve_connection(TokioIo::new(server), service)
            .await;
    });
    (client, task)
}

/// The H5 response for hyper: `204 No Content`, no fields, no body.
#[must_use]
pub fn no_content_response() -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

/// Spawns the transport baseline: a task on `rt` that, over a new duplex
/// stream of `capacity`, reads exactly `request_len` bytes and writes
/// `response`, until the client end closes. No HTTP is involved.
pub fn spawn_canned_server(
    rt: &Runtime,
    capacity: usize,
    request_len: usize,
    response: Vec<u8>,
) -> (DuplexStream, JoinHandle<()>) {
    let (client, mut server) = duplex(capacity);
    let task = rt.spawn(async move {
        let mut request = vec![0u8; request_len];
        loop {
            if server.read_exact(&mut request).await.is_err() {
                return;
            }
            if server.write_all(&response).await.is_err() {
                return;
            }
        }
    });
    (client, task)
}

/// The pipelined transport baseline (H5): reads whatever arrives (at most
/// `capacity` bytes at a time), and for every complete `request_len` bytes
/// writes one copy of `response`, batched per read (as `pipeline_flush`
/// batches hyper's writes). No HTTP is involved.
pub fn spawn_canned_pipelined_server(
    rt: &Runtime,
    capacity: usize,
    request_len: usize,
    response: Vec<u8>,
) -> (DuplexStream, JoinHandle<()>) {
    let (client, mut server) = duplex(capacity);
    let task = rt.spawn(async move {
        let mut buf = vec![0u8; capacity];
        let mut out = Vec::with_capacity(capacity);
        let mut carry = 0usize;
        loop {
            let n = match server.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let total = carry + n;
            carry = total % request_len;
            out.clear();
            for _ in 0..total / request_len {
                out.extend_from_slice(&response);
            }
            if server.write_all(&out).await.is_err() {
                return;
            }
        }
    });
    (client, task)
}

/// One exchange from the client end (H2): write `request`, read exactly
/// `response.len()` bytes back.
///
/// # Errors
///
/// An I/O error of the duplex stream (the server end closed).
#[inline]
pub async fn round_trip(
    client: &mut DuplexStream,
    request: &[u8],
    response: &mut [u8],
) -> io::Result<()> {
    client.write_all(request).await?;
    client.read_exact(response).await?;
    Ok(())
}

/// Reads one whole response from `client` (head by `httparse`, body by its
/// `content-length`). Used once per setup to learn how many bytes an
/// exchange returns, and by the equivalence test; never timed.
///
/// # Errors
///
/// An I/O error, or `InvalidData` if the bytes are not a response.
pub async fn read_one_response(client: &mut DuplexStream) -> io::Result<Vec<u8>> {
    let mut got = Vec::new();
    let mut buf = vec![0u8; EXCHANGE_CAPACITY];
    loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        got.extend_from_slice(&buf[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&got) {
            Ok(httparse::Status::Complete(head)) => {
                let length = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok()?.parse::<usize>().ok())
                    .unwrap_or(0);
                if got.len() >= head + length {
                    got.truncate(head + length);
                    return Ok(got);
                }
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

/// Sends `request` once on a fresh hyper server made by `spawn` and returns
/// the whole response it writes: how a bench learns the exact response
/// bytes (and their length) before timing.
///
/// # Panics
///
/// If the exchange fails.
pub fn probe_response(rt: &Runtime, client: &mut DuplexStream, request: &[u8]) -> Vec<u8> {
    rt.block_on(async {
        client.write_all(request).await.expect("probe write");
        read_one_response(client).await.expect("probe read")
    })
}

/// The bytes hyper's client writes for the H3 request, captured by a server
/// task that reads up to the blank line. Used to size the canned server.
///
/// # Panics
///
/// If the handshake or the capture fails.
#[must_use]
pub fn hyper_client_request_wire() -> Vec<u8> {
    let rt = runtime();
    let (client, mut server) = duplex(EXCHANGE_CAPACITY);
    let capture = rt.spawn(async move {
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.ends_with(b"\r\n\r\n") {
            let n = server.read(&mut buf).await.expect("capture read");
            assert_ne!(n, 0, "the client closed before the end of its head");
            got.extend_from_slice(&buf[..n]);
        }
        got
    });
    rt.block_on(async move {
        let (mut sender, conn) = client_http1::handshake(TokioIo::new(client))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        tokio::spawn(async move {
            if sender.ready().await.is_ok() {
                let _ = sender.send_request(client_request(&client_uri())).await;
            }
        });
        capture.await.expect("capture task")
    })
}

/// The H3 request target, parsed once.
#[must_use]
pub fn client_uri() -> Uri {
    Uri::from_static(CLIENT_PATH)
}

/// The H3 request for hyper: `GET /api` with `host: a` and no body. The URI
/// is cloned from one parsed in setup (static bytes, no allocation), the
/// cheapest way to make a request per call, as `send_request` takes it by
/// value.
#[inline]
#[must_use]
pub fn client_request(uri: &Uri) -> Request<Empty<Bytes>> {
    let mut request = Request::new(Empty::new());
    *request.uri_mut() = uri.clone();
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(CLIENT_HOST));
    request
}

/// A hyper client connection on `rt` to a canned server that answers every
/// `request_len`-byte request with `wire` (H3). Returns the sender.
///
/// # Panics
///
/// If the handshake fails.
#[must_use]
pub fn hyper_client(
    rt: &Runtime,
    request_len: usize,
    wire: Vec<u8>,
) -> client_http1::SendRequest<Empty<Bytes>> {
    let (io, _server) = spawn_canned_server(rt, EXCHANGE_CAPACITY, request_len, wire);
    let (sender, conn) = rt
        .block_on(client_http1::handshake(TokioIo::new(io)))
        .expect("handshake");
    rt.spawn(async move {
        let _ = conn.await;
    });
    sender
}

/// One H3 exchange on a hyper client: wait until the connection is ready,
/// send the request, read the head, collect the body. Returns the status,
/// the field count, and the body.
///
/// # Errors
///
/// A hyper error.
#[inline]
pub async fn hyper_get(
    sender: &mut client_http1::SendRequest<Empty<Bytes>>,
    uri: &Uri,
) -> hyper::Result<(u16, usize, Bytes)> {
    sender.ready().await?;
    let response = sender.send_request(client_request(uri)).await?;
    let status = response.status().as_u16();
    let fields = response.headers().len();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, fields, body))
}

/// The H5 client loop: writes `input` in `chunk`-byte writes while reading
/// responses, until `expected` response bytes have arrived, then closes its
/// end and waits for the server task to finish (the whole connection's
/// life is timed). Returns the response bytes read.
///
/// # Errors
///
/// An I/O error of the duplex stream.
pub async fn drive_pipelined(
    client: DuplexStream,
    server: JoinHandle<()>,
    input: &[u8],
    chunk: usize,
    expected: usize,
    buf: &mut [u8],
) -> io::Result<usize> {
    let (mut rd, mut wr) = tokio::io::split(client);
    let writer = async {
        for piece in input.chunks(chunk) {
            wr.write_all(piece).await?;
        }
        Ok::<_, io::Error>(())
    };
    let reader = async {
        let mut got = 0;
        while got < expected {
            let n = rd.read(buf).await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        Ok::<_, io::Error>(got)
    };
    let (written, got) = tokio::join!(writer, reader);
    written?;
    let got = got?;
    drop(rd.unsplit(wr));
    let _ = server.await;
    Ok(got)
}

/// Like [`drive_pipelined`], but keeps every response byte (for the
/// equivalence test).
///
/// # Errors
///
/// An I/O error of the duplex stream.
pub async fn collect_pipelined(
    client: DuplexStream,
    server: JoinHandle<()>,
    input: &[u8],
    chunk: usize,
    expected: usize,
) -> io::Result<Vec<u8>> {
    let (mut rd, mut wr) = tokio::io::split(client);
    let writer = async {
        for piece in input.chunks(chunk) {
            wr.write_all(piece).await?;
        }
        Ok::<_, io::Error>(())
    };
    let reader = async {
        let mut got = Vec::with_capacity(expected);
        let mut buf = vec![0u8; READ_SIZE];
        while got.len() < expected {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        Ok::<_, io::Error>(got)
    };
    let (written, got) = tokio::join!(writer, reader);
    written?;
    let got = got?;
    drop(rd.unsplit(wr));
    let _ = server.await;
    Ok(got)
}
