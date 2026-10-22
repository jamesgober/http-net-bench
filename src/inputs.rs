//! The wire inputs, byte for byte the ones in http-net's `benches/bench.rs`.

use http_net::{Limits, Response};

/// A browser-like GET: 12 fields, about 500 bytes (workloads H1 and H2).
pub const BROWSER_GET: &[u8] = b"GET /assets/app.3f9a1c.js?v=2 HTTP/1.1\r\n\
Host: 127.0.0.1:53817\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\n\
Accept: */*\r\n\
Accept-Encoding: gzip, deflate, br, zstd\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Cache-Control: no-cache\r\n\
Connection: keep-alive\r\n\
Pragma: no-cache\r\n\
Referer: http://127.0.0.1:53817/\r\n\
Sec-Fetch-Dest: script\r\n\
Sec-Fetch-Mode: no-cors\r\n\
Sec-Fetch-Site: same-origin\r\n\r\n";

/// The number of fields in [`BROWSER_GET`].
pub const BROWSER_GET_FIELDS: usize = 12;

/// The read size every streaming workload feeds in: 16 KiB.
pub const READ_SIZE: usize = 16 * 1024;

/// One request of the pipelined workload (H5).
pub const PIPELINED_ONE: &[u8] = b"GET /item/42 HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n";

/// How many requests the pipelined workload sends on one connection.
pub const PIPELINED_COUNT: usize = 100_000;

/// [`PIPELINED_ONE`] repeated [`PIPELINED_COUNT`] times.
#[must_use]
pub fn pipelined_input() -> Vec<u8> {
    PIPELINED_ONE.repeat(PIPELINED_COUNT)
}

/// The five response fields of the H2 exchange (http-net's
/// `response_write` bench), names as http-net's bench spells them.
pub const FIVE_FIELDS: [(&str, &str); 5] = [
    ("content-type", "application/javascript"),
    ("cache-control", "max-age=31536000, immutable"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// The 1 KiB response body of the H2 exchange.
pub static BODY_1K: [u8; 1024] = [b'x'; 1024];

/// The H2 response for http-net: status 200, [`FIVE_FIELDS`], and
/// [`BODY_1K`] (http-net adds `content-length`, as hyper does).
#[must_use]
pub fn five_field_response() -> Response {
    let mut response = Response::new(200);
    for (name, value) in FIVE_FIELDS {
        response = response.header(name, value);
    }
    response.body(&BODY_1K[..])
}

/// The length of the JSON body in [`json_response_wire`].
pub const JSON_BODY_LEN: usize = 1024;

/// The client workload's response (H3): four fields and a 1 KiB body.
#[must_use]
pub fn json_response_wire() -> Vec<u8> {
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: Sun, 04 Oct 2026 00:00:00 GMT\r\nContent-Length: 1024\r\n\r\n".to_vec();
    wire.extend(std::iter::repeat_n(b'{', JSON_BODY_LEN));
    wire
}

/// The fields of [`json_response_wire`].
pub const JSON_RESPONSE_FIELDS: usize = 3;

/// The H3 request: `GET /api` with a `host` field.
pub const CLIENT_PATH: &str = "/api";

/// The `host` of the H3 request.
pub const CLIENT_HOST: &str = "a";

/// The decoded size of the chunked workload (H4): 1 MiB.
pub const CHUNKED_BODY_LEN: usize = 1024 * 1024;

/// The chunk size of the chunked workload: 4 KiB.
pub const CHUNK_SIZE: usize = 4096;

/// The 1 MiB body of H4 (the byte http-net's bench uses).
#[must_use]
pub fn chunked_body() -> Vec<u8> {
    vec![0x5au8; CHUNKED_BODY_LEN]
}

/// [`chunked_body`] chunk-encoded in [`CHUNK_SIZE`] chunks, with the last
/// chunk and an empty trailer section: the body part of http-net's
/// `body_1mib/chunked_4k` input, without the request head.
#[must_use]
pub fn chunked_wire() -> Vec<u8> {
    let body = chunked_body();
    let mut wire = Vec::with_capacity(body.len() + body.len() / CHUNK_SIZE * 10 + 5);
    for piece in body.chunks(CHUNK_SIZE) {
        wire.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        wire.extend_from_slice(piece);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

/// The limits of every workload: http-net's defaults, with the body budget
/// raised to 2 MiB (as http-net's `body_1mib` bench does) so the 1 MiB body
/// fits. The framing pass and the chunked loop on the httparse side enforce
/// the same body budget.
#[must_use]
pub fn limits() -> Limits {
    Limits::new().with_max_body(MAX_BODY)
}

/// The body budget of [`limits`], in bytes.
pub const MAX_BODY: u64 = 2 << 20;
