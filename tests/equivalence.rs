//! Correctness first: every competitor setup in `benches/` does the same
//! work as the http-net side it is compared with, on the same bytes.
//!
//! A bench that compared unequal work would be meaningless, so each
//! workload is checked here with the exact functions the benches time:
//! same method, target, field count, head length, and framing for H1; the
//! framing pass agreeing with http-net on accepted and refused heads; the
//! same response semantics (status, fields, body) for H2, H3, and H5; the
//! same decoded body for H4; and the transport baselines moving the same
//! bytes as hyper.
//!
//! The report-only comparisons are held to the same rule: picohttpparser
//! with the framing pass answers as http-net does on H1 and decodes the same
//! body on H4, llhttp sees the same 100,000 requests on H5, and with the
//! `h6` feature every socket server answers the same request alike.

use http_net::{ClientConn, FieldSpan, HttpError, Request, Response, ServerConn};
use http_net_bench::{
    chunked,
    framing::{self, Framing, HeadError},
    inputs::{
        BROWSER_GET, BROWSER_GET_FIELDS, CLIENT_HOST, CLIENT_PATH, JSON_BODY_LEN,
        JSON_RESPONSE_FIELDS, MAX_BODY, PIPELINED_COUNT, PIPELINED_ONE, READ_SIZE, chunked_body,
        chunked_wire, five_field_response, json_response_wire, limits, pipelined_input,
    },
    llhttp, net,
    pico::{self, Build, PhrHeader, PicoError},
    rt,
};

/// A response, parsed by httparse into what a client can observe: status,
/// fields (names lowercased, sorted), body.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    status: u16,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

/// Parses one whole response from the start of `bytes` (body by
/// `content-length`) and returns it with the bytes it took.
fn observe(bytes: &[u8]) -> (Observed, usize) {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(head) = resp.parse(bytes).expect("a valid response") else {
        panic!("an incomplete response");
    };
    let mut fields: Vec<(String, Vec<u8>)> = resp
        .headers
        .iter()
        .map(|h| (h.name.to_ascii_lowercase(), h.value.to_vec()))
        .collect();
    fields.sort();
    let length = fields
        .iter()
        .find(|(n, _)| n == "content-length")
        .map_or(0, |(_, v)| {
            std::str::from_utf8(v).unwrap().parse::<usize>().unwrap()
        });
    let observed = Observed {
        status: resp.code.unwrap(),
        fields,
        body: bytes[head..head + length].to_vec(),
    };
    (observed, head + length)
}

// ---------------------------------------------------------------- H1 ----

#[test]
fn h1_both_parsers_answer_the_same_on_the_browser_get() {
    let limits = limits();
    let mut fields16 = [FieldSpan::default(); 16];
    let mut fields32 = [FieldSpan::default(); 32];
    let mut headers16 = [httparse::EMPTY_HEADER; 16];
    let mut headers32 = [httparse::EMPTY_HEADER; 32];
    let a = net::parse_head(BROWSER_GET, &limits, &mut fields16).unwrap();
    let b = net::parse_head(BROWSER_GET, &limits, &mut fields32).unwrap();
    let c = framing::httparse_head(BROWSER_GET, &mut headers16, MAX_BODY).unwrap();
    let d = framing::httparse_head(BROWSER_GET, &mut headers32, MAX_BODY).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a, d);
    assert_eq!(a.method(BROWSER_GET), b"GET");
    assert_eq!(a.target(BROWSER_GET), b"/assets/app.3f9a1c.js?v=2");
    assert_eq!(a.fields, BROWSER_GET_FIELDS);
    assert_eq!(a.len, BROWSER_GET.len());
    assert_eq!(a.framing, Framing::None);
    assert!(a.keep_alive);
    assert!(a.host_present);

    // The ServerConn reference sees the same facts, iteration after
    // iteration on the reused connection.
    let mut conn = ServerConn::with_limits(limits);
    for _ in 0..3 {
        let got = net::server_conn_head(&mut conn, BROWSER_GET).unwrap();
        assert_eq!(got, (BROWSER_GET_FIELDS, Framing::None, true, true));
    }

    // The parse-only reference parses the same head.
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    assert_eq!(
        req.parse(BROWSER_GET).unwrap(),
        httparse::Status::Complete(BROWSER_GET.len())
    );
    assert_eq!(req.headers.len(), BROWSER_GET_FIELDS);
}

/// Heads that exercise every rule of the framing pass. For each, the pass
/// after httparse and http-net's parser must accept with the same facts or
/// refuse with the same error.
const FRAMING_CASES: &[&[u8]] = &[
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: CHUNKED\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 4194304\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;q=1\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \"chunked\"\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: ,\r\n\r\n",
    b"POST /up HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"GET / HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: :80\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: \r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a%2\r\n\r\n",
    b"GET / HTTP/1.0\r\n\r\n",
    b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    b"GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nConnection: \"close\", x\r\n\r\n",
    b"GET /chat HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    b"GET /chat HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
    b"POST /up HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nExpect: something\r\n\r\n",
    b"GET /a%zz HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET /a%2F HTTP/1.1\r\nHost: a\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET * HTTP/1.1\r\nHost: a\r\n\r\n",
];

#[test]
fn h1_framing_pass_agrees_with_http_net_on_every_rule() {
    let limits = limits();
    for &input in FRAMING_CASES {
        let shown = String::from_utf8_lossy(input);
        let mut fields = [FieldSpan::default(); 16];
        let ours = net::parse_head(input, &limits, &mut fields);
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let theirs = framing::httparse_head(input, &mut headers, MAX_BODY);
        match (ours, theirs) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "{shown}");
                // The facts the summary does not carry agree too.
                let mut fields = [FieldSpan::default(); 16];
                let http_net::Parsed::Complete { head, .. } =
                    http_net::parse_request_head(input, &limits, &mut fields).unwrap()
                else {
                    panic!("{shown}")
                };
                let view = head.view();
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);
                req.parse(input).unwrap();
                let facts = framing::request_framing(&req, MAX_BODY).unwrap();
                assert_eq!(facts.upgrade, view.is_upgrade(), "{shown}");
                assert_eq!(facts.expect_continue, view.expects_continue(), "{shown}");
                assert_eq!(
                    facts.unknown_expectation,
                    view.has_unknown_expectation(),
                    "{shown}"
                );
                assert_eq!(
                    facts.http11,
                    view.version() == http_net::Version::Http11,
                    "{shown}"
                );
            }
            (Err(a), Err(HeadError::Framing(b))) => {
                assert_eq!(format!("{a:?}"), format!("{b:?}"), "{shown}");
            }
            // Every case is valid syntax, so a refusal by httparse itself
            // would mean the case does not reach the framing pass at all.
            (a, b) => panic!("disagree on {shown}: http-net {a:?}, httparse {b:?}"),
        }
    }
}

#[test]
fn h1_picohttpparser_answers_the_same_on_the_browser_get() {
    let limits = limits();
    let mut fields = [FieldSpan::default(); 16];
    let ours = net::parse_head(BROWSER_GET, &limits, &mut fields).unwrap();
    for build in [Build::Sse42, Build::Scalar] {
        let mut headers16 = [PhrHeader::EMPTY; 16];
        let mut headers32 = [PhrHeader::EMPTY; 32];
        assert_eq!(
            pico::head(build, BROWSER_GET, &mut headers16, MAX_BODY),
            Ok(ours)
        );
        assert_eq!(
            pico::head(build, BROWSER_GET, &mut headers32, MAX_BODY),
            Ok(ours)
        );

        // The parse-only reference parses the same head.
        let parsed = pico::parse(build, BROWSER_GET, &mut headers16).unwrap();
        assert_eq!(parsed.fields, BROWSER_GET_FIELDS);
        assert_eq!(parsed.len, BROWSER_GET.len());
    }
}

#[test]
fn h1_picohttpparser_with_the_pass_agrees_with_http_net_on_every_rule() {
    let limits = limits();
    for &input in FRAMING_CASES {
        let shown = String::from_utf8_lossy(input);
        let mut fields = [FieldSpan::default(); 16];
        let ours = net::parse_head(input, &limits, &mut fields);
        for build in [Build::Sse42, Build::Scalar] {
            let mut headers = [PhrHeader::EMPTY; 16];
            match (&ours, pico::head(build, input, &mut headers, MAX_BODY)) {
                (Ok(a), Ok(b)) => assert_eq!(*a, b, "{shown}"),
                (Err(a), Err(PicoError::Framing(b))) => {
                    assert_eq!(format!("{a:?}"), format!("{b:?}"), "{shown}");
                }
                (a, b) => panic!("disagree on {shown}: http-net {a:?}, pico {b:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------- H2 ----

#[test]
fn h2_hyper_and_http_net_send_the_same_response() {
    let response = five_field_response();
    let mut conn = ServerConn::with_limits(limits());
    let mut out = Vec::new();
    assert_eq!(
        net::serve_all(&mut conn, BROWSER_GET, READ_SIZE, &response, &mut out),
        1
    );
    let (ours, used) = observe(&out);
    assert_eq!(used, out.len());

    // The per-request builder writes the same bytes.
    let mut conn = ServerConn::with_limits(limits());
    let mut built = Vec::new();
    for _ in 0..3 {
        assert_eq!(
            net::serve_one_building(
                &mut conn,
                BROWSER_GET,
                &http_net_bench::inputs::FIVE_FIELDS,
                &http_net_bench::inputs::BODY_1K,
                &mut built,
            ),
            1
        );
        assert_eq!(built, out);
    }

    let runtime = rt::runtime();
    let (mut client, _server) = rt::spawn_hyper_server(
        &runtime,
        rt::EXCHANGE_CAPACITY,
        false,
        rt::five_field_response,
    );
    let hyper_bytes = rt::probe_response(&runtime, &mut client, BROWSER_GET);
    let (theirs, used) = observe(&hyper_bytes);
    assert_eq!(used, hyper_bytes.len());
    assert_eq!(ours, theirs);
    assert_eq!(ours.status, 200);
    assert_eq!(ours.fields.len(), 6, "five fields and content-length");
    assert_eq!(ours.body.len(), 1024);

    // Keep-alive: the bench's round trip on the same connection reads
    // exactly the same bytes again, every time.
    let mut buf = vec![0u8; hyper_bytes.len()];
    for _ in 0..3 {
        runtime
            .block_on(rt::round_trip(&mut client, BROWSER_GET, &mut buf))
            .unwrap();
        assert_eq!(buf, hyper_bytes);
    }

    // The transport baseline moves the same bytes each way.
    let (mut client, _server) = rt::spawn_canned_server(
        &runtime,
        rt::EXCHANGE_CAPACITY,
        BROWSER_GET.len(),
        hyper_bytes.clone(),
    );
    for _ in 0..3 {
        runtime
            .block_on(rt::round_trip(&mut client, BROWSER_GET, &mut buf))
            .unwrap();
        assert_eq!(buf, hyper_bytes);
    }
}

// ---------------------------------------------------------------- H3 ----

#[test]
fn h3_response_head_facts_agree() {
    let wire = json_response_wire();
    let mut fields = [FieldSpan::default(); 16];
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let ours = net::parse_response(&wire, &limits(), &mut fields).unwrap();
    let theirs = framing::httparse_response(&wire, &mut headers, MAX_BODY).unwrap();
    assert_eq!(ours, theirs);
    assert_eq!(
        ours,
        (
            200,
            JSON_RESPONSE_FIELDS,
            wire.len() - JSON_BODY_LEN,
            Framing::Length(JSON_BODY_LEN as u64),
            true
        )
    );
}

/// Response heads for every rule of the response framing pass.
const RESPONSE_CASES: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.1 200 OK\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 600 Nope\r\n\r\n",
    b"HTTP/1.1 099 Nope\r\n\r\n",
];

#[test]
fn h3_response_framing_pass_agrees_with_http_net_on_every_rule() {
    let limits = limits();
    for &input in RESPONSE_CASES {
        let shown = String::from_utf8_lossy(input);
        let mut fields = [FieldSpan::default(); 16];
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let ours = net::parse_response(input, &limits, &mut fields);
        let theirs = framing::httparse_response(input, &mut headers, MAX_BODY);
        match (ours, theirs) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{shown}"),
            (Err(a), Err(HeadError::Framing(b))) => {
                assert_eq!(format!("{a:?}"), format!("{b:?}"), "{shown}");
            }
            (a, b) => panic!("disagree on {shown}: http-net {a:?}, httparse {b:?}"),
        }
    }
}

#[test]
fn h3_hyper_client_and_client_conn_receive_the_same_response() {
    let wire = json_response_wire();
    let request = Request::get(CLIENT_PATH).header("host", CLIENT_HOST);
    let mut conn = ClientConn::with_limits(limits());
    let mut out = Vec::new();
    let mut ours = Vec::new();
    for _ in 0..3 {
        ours.clear();
        let status = net::client_exchange(&mut conn, &request, &wire, &mut out, |b| {
            ours.extend_from_slice(b);
        });
        assert_eq!(status, 200);
        assert_eq!(ours, vec![b'{'; JSON_BODY_LEN]);
    }

    // hyper's request is the same request http-net's client writes.
    let request_wire = rt::hyper_client_request_wire();
    let mut ours_req = Vec::new();
    ClientConn::new()
        .send_request(&request, &mut ours_req)
        .unwrap();
    let parse = |bytes: &[u8]| {
        let mut headers = [httparse::EMPTY_HEADER; 8];
        let mut req = httparse::Request::new(&mut headers);
        assert!(req.parse(bytes).unwrap().is_complete());
        let mut fields: Vec<(String, Vec<u8>)> = req
            .headers
            .iter()
            .map(|h| (h.name.to_ascii_lowercase(), h.value.to_vec()))
            .collect();
        fields.sort();
        (
            req.method.unwrap().to_owned(),
            req.path.unwrap().to_owned(),
            fields,
        )
    };
    assert_eq!(parse(&request_wire), parse(&ours_req));

    let runtime = rt::runtime();
    let uri = rt::client_uri();
    let mut sender = rt::hyper_client(&runtime, request_wire.len(), wire.clone());
    for _ in 0..3 {
        let (status, fields, body) = runtime.block_on(rt::hyper_get(&mut sender, &uri)).unwrap();
        assert_eq!(status, 200);
        assert_eq!(fields, JSON_RESPONSE_FIELDS);
        assert_eq!(&body[..], &ours[..]);
    }

    // The transport baseline moves the same bytes each way.
    let (mut client, _server) = rt::spawn_canned_server(
        &runtime,
        rt::EXCHANGE_CAPACITY,
        request_wire.len(),
        wire.clone(),
    );
    let mut buf = vec![0u8; wire.len()];
    for _ in 0..3 {
        runtime
            .block_on(rt::round_trip(&mut client, &request_wire, &mut buf))
            .unwrap();
        assert_eq!(buf, wire);
    }
}

// ---------------------------------------------------------------- H4 ----

#[test]
fn h4_both_decoders_deliver_the_same_body() {
    let wire = chunked_wire();
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    let a = chunked::http_net_decode(&wire, &limits(), |d| ours.extend_from_slice(d)).unwrap();
    let b = chunked::httparse_decode(&wire, MAX_BODY, |d| theirs.extend_from_slice(d)).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.consumed, wire.len());
    assert_eq!(a.total, chunked_body().len() as u64);
    assert_eq!(ours, chunked_body());
    assert_eq!(theirs, ours);
}

#[test]
fn h4_both_decoders_refuse_the_same_broken_bodies() {
    let cases: &[&[u8]] = &[
        b"4\r\nWikiXX5\r\npedia\r\n0\r\n\r\n",
        b"g\r\nabc\r\n0\r\n\r\n",
        b"4\r\nWik",
        b"ffffffffffffffff\r\n",
        b"300001\r\n",
    ];
    for &wire in cases {
        let a = chunked::http_net_decode(wire, &limits(), |_| {});
        let b = chunked::httparse_decode(wire, MAX_BODY, |_| {});
        assert!(a.is_err() && b.is_err(), "{a:?} {b:?}");
    }
    // A body over the budget is refused by both before its data.
    let a = chunked::http_net_decode(b"300001\r\n", &limits(), |_| {});
    assert_eq!(a, Err(HttpError::BodyTooLarge));
    let b = chunked::httparse_decode(b"300001\r\n", MAX_BODY, |_| {});
    assert_eq!(b, Err(chunked::ChunkError::BodyTooLarge));
}

#[test]
fn h4_picohttpparser_delivers_the_same_body() {
    let wire = chunked_wire();
    let ours = chunked::http_net_decode(&wire, &limits(), |_| {}).unwrap();
    let mut buf = wire.clone();
    let theirs = pico::decode_chunked(&mut buf, MAX_BODY).unwrap();
    assert_eq!(ours, theirs);
    assert_eq!(&buf[..chunked_body().len()], &chunked_body()[..]);

    // Refused alike, except that it has no budget to stop a body early: a
    // size over the budget waits for more input, and the check comes at the
    // end of the body.
    for wire in [
        &b"4\r\nWikiXX5\r\npedia\r\n0\r\n\r\n"[..],
        b"g\r\nabc\r\n0\r\n\r\n",
    ] {
        assert_eq!(
            pico::decode_chunked(&mut wire.to_vec(), MAX_BODY),
            Err(PicoError::Parse)
        );
    }
    assert_eq!(
        pico::decode_chunked(&mut b"4\r\nWik".to_vec(), MAX_BODY),
        Err(PicoError::Partial)
    );
    assert_eq!(
        pico::decode_chunked(&mut wire_of(5), 4),
        Err(PicoError::BodyTooLarge)
    );
}

/// A one-chunk body of `n` bytes.
fn wire_of(n: usize) -> Vec<u8> {
    let mut wire = format!("{n:x}\r\n").into_bytes();
    wire.resize(wire.len() + n, b'x');
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    wire
}

// ---------------------------------------------------------------- H5 ----

#[test]
fn h5_hyper_and_http_net_answer_every_pipelined_request_alike() {
    let input = pipelined_input();
    let response = Response::new(204);
    let mut conn = ServerConn::with_limits(limits());
    let mut out = Vec::new();
    assert_eq!(
        net::serve_all(&mut conn, &input, READ_SIZE, &response, &mut out),
        PIPELINED_COUNT
    );
    let (ours, _) = observe(&out);
    assert_eq!(ours.status, 204);

    let runtime = rt::runtime();
    let one = {
        let (mut client, _server) = rt::spawn_hyper_server(
            &runtime,
            rt::PIPELINED_CAPACITY,
            true,
            rt::no_content_response,
        );
        rt::probe_response(&runtime, &mut client, PIPELINED_ONE)
    };
    let (theirs, used) = observe(&one);
    assert_eq!(used, one.len());
    assert_eq!(ours, theirs);

    // All 100,000 responses arrive, each one the same bytes.
    let expected = one.len() * PIPELINED_COUNT;
    let (client, server) = rt::spawn_hyper_server(
        &runtime,
        rt::PIPELINED_CAPACITY,
        true,
        rt::no_content_response,
    );
    let got = runtime
        .block_on(rt::collect_pipelined(
            client, server, &input, READ_SIZE, expected,
        ))
        .unwrap();
    assert_eq!(got, one.repeat(PIPELINED_COUNT));

    // The bench's own loop reads the same count, for hyper and for the
    // transport baseline.
    let mut buf = vec![0u8; 64 * 1024];
    let (client, server) = rt::spawn_hyper_server(
        &runtime,
        rt::PIPELINED_CAPACITY,
        true,
        rt::no_content_response,
    );
    let n = runtime
        .block_on(rt::drive_pipelined(
            client, server, &input, READ_SIZE, expected, &mut buf,
        ))
        .unwrap();
    assert_eq!(n, expected);
    let (client, server) = rt::spawn_canned_pipelined_server(
        &runtime,
        rt::PIPELINED_CAPACITY,
        PIPELINED_ONE.len(),
        one.clone(),
    );
    let got = runtime
        .block_on(rt::collect_pipelined(
            client, server, &input, READ_SIZE, expected,
        ))
        .unwrap();
    assert_eq!(got, one.repeat(PIPELINED_COUNT));
}

#[test]
fn h5_llhttp_sees_every_pipelined_request_as_http_net_does() {
    let input = pipelined_input();
    let response = Response::new(204);
    let mut conn = ServerConn::with_limits(limits());
    let mut ours = Vec::new();
    assert_eq!(
        net::serve_all(&mut conn, &input, READ_SIZE, &response, &mut ours),
        PIPELINED_COUNT
    );

    // The bench's own driver: every request parsed the same, whichever read
    // it fell across, and every one answered with http-net's bytes.
    let mut seen = 0usize;
    let mut out = Vec::new();
    let watch = |m: &llhttp::Message<'_>| {
        assert_eq!(m.method, 1, "GET");
        assert_eq!(m.target, b"/item/42");
        assert_eq!(m.fields, 2);
        assert_eq!(m.host, b"a");
        assert!(m.keep_alive);
        seen += 1;
    };
    let n = llhttp::Conn::new().serve_all(&input, READ_SIZE, &ours, &mut out, watch);
    assert_eq!(n, Ok(PIPELINED_COUNT));
    assert_eq!(seen, PIPELINED_COUNT);
    assert_eq!(out, ours);

    assert_eq!(
        llhttp::Conn::new().count_only(&input, READ_SIZE),
        Ok(PIPELINED_COUNT)
    );

    // A request http-net refuses for its `host` stops this driver too, and
    // the byte stream of a broken request stops llhttp itself.
    let mut out = Vec::new();
    for bad in [
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n",
        b"GET / HTTP/1.1\r\nBad Name: a\r\n\r\n",
    ] {
        let mut conn = ServerConn::with_limits(limits());
        assert_eq!(
            net::serve_all(&mut conn, bad, READ_SIZE, &response, &mut out),
            0
        );
        assert!(
            llhttp::Conn::new()
                .serve_all(bad, READ_SIZE, &ours, &mut out, ())
                .is_err()
        );
    }
}

// ---------------------------------------------------------------- H6 ----

#[cfg(feature = "h6")]
mod h6 {
    use std::{
        io::Write,
        net::{SocketAddr, TcpListener},
        process::{Child, Command},
        time::Duration,
    };

    use http_net_bench::{
        h6::{self, Shape},
        inputs::{PLAINTEXT_BODY, PLAINTEXT_GET, PLAINTEXT_TYPE},
    };

    use super::{Observed, observe};

    /// One `h6_server` process, killed at the end of the test.
    struct Server {
        child: Child,
        addr: SocketAddr,
    }

    impl Server {
        fn start(name: &str) -> Self {
            // Ask the kernel for a free port, then hand it to the server.
            let addr = TcpListener::bind("127.0.0.1:0")
                .and_then(|l| l.local_addr())
                .unwrap();
            let child = Command::new(env!("CARGO_BIN_EXE_h6_server"))
                .arg(name)
                .arg(addr.to_string())
                .spawn()
                .unwrap();
            Self { child, addr }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Writes `pipeline` copies of `request` in one go and reads every
    /// response, with `server` and `date` taken out: `date` differs by the
    /// second, and may-minihttp always writes its own `server`.
    fn exchange(addr: SocketAddr, request: &[u8], pipeline: usize) -> Vec<Observed> {
        let mut stream = h6::connect(addr, Duration::from_secs(5)).unwrap();
        stream.write_all(&request.repeat(pipeline)).unwrap();
        let mut rest = Vec::new();
        (0..pipeline)
            .map(|_| {
                let one = h6::read_response(&mut stream, &mut rest).unwrap();
                let (mut seen, used) = observe(&one);
                assert_eq!(used, one.len());
                assert!(seen.fields.iter().any(|(n, _)| n == "date"), "no date");
                seen.fields.retain(|(n, _)| n != "date" && n != "server");
                seen
            })
            .collect()
    }

    #[test]
    fn h6_every_server_answers_the_same_request_alike() {
        for name in ["serve-net", "hyper", "actix-web", "may-minihttp"] {
            let server = Server::start(name);
            for seen in exchange(server.addr, PLAINTEXT_GET, 16) {
                assert_eq!(seen.status, 200, "{name}");
                assert_eq!(seen.body, PLAINTEXT_BODY, "{name}");
                assert_eq!(
                    seen.fields,
                    [
                        ("content-length".to_owned(), b"13".to_vec()),
                        (
                            "content-type".to_owned(),
                            PLAINTEXT_TYPE.as_bytes().to_vec()
                        ),
                    ],
                    "{name}"
                );
            }

            // Every server routes: another path is not a canned answer.
            let other = String::from_utf8_lossy(PLAINTEXT_GET).replace("/plaintext", "/other");
            let seen = exchange(server.addr, other.as_bytes(), 1);
            assert_eq!(seen[0].status, 404, "{name}");
        }
    }

    #[test]
    fn h6_the_generator_outlasts_every_connection_limit() {
        // More requests per connection than any server's defaults allow
        // (serve-net closes at 1,000 unless told otherwise): a server that
        // closes a connection fails the run.
        for name in ["serve-net", "hyper", "actix-web", "may-minihttp"] {
            let server = Server::start(name);
            let shape = Shape {
                connections: 16,
                pipeline: 16,
            };
            let run = h6::run(
                server.addr,
                shape,
                Duration::ZERO,
                Duration::from_secs(1),
                Some(server.child.id()),
            )
            .unwrap();
            assert!(run.requests > 16 * 1000, "{name}: {run:?}");
            assert!(run.server_cpu.is_some(), "{name}: {run:?}");
        }
    }
}
