//! Compiles the vendored C parsers: picohttpparser twice (with SSE4.2 and
//! scalar) and llhttp once. See `vendor/README.md` for where they come from.
//!
//! Every C object is built with `-O3` whatever the Cargo profile, so the test
//! build runs the same C as the bench build. A C compiler is required; the
//! results file records which one.

fn build() -> cc::Build {
    let mut build = cc::Build::new();
    build.opt_level(3).debug(false).warnings(false);
    build.define("NDEBUG", None);
    build
}

fn main() {
    println!("cargo:rerun-if-changed=vendor/picohttpparser");
    println!("cargo:rerun-if-changed=vendor/llhttp");
    println!("cargo:rerun-if-changed=build.rs");
    let x86_64 = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64");

    // Both parsers pick SSE4.2 at compile time, not at run time as httparse
    // does, so it has to be asked for.
    let mut pico = build();
    pico.file("vendor/picohttpparser/picohttpparser.c");
    if x86_64 {
        pico.flag("-msse4.2");
    }
    pico.compile("picohttpparser");

    // The same source without SSE4.2, its public names changed so that both
    // copies link into one binary.
    let mut scalar = build();
    scalar.file("vendor/picohttpparser/picohttpparser.c");
    for name in [
        "phr_parse_request",
        "phr_parse_response",
        "phr_parse_headers",
        "phr_decode_chunked",
        "phr_decode_chunked_is_in_data",
    ] {
        scalar.define(name, format!("{name}_scalar").as_str());
    }
    scalar.compile("picohttpparser_scalar");

    let mut llhttp = build();
    llhttp
        .include("vendor/llhttp")
        .file("vendor/llhttp/api.c")
        .file("vendor/llhttp/http.c")
        .file("vendor/llhttp/llhttp.c");
    if x86_64 {
        llhttp.flag("-msse4.2");
    }
    llhttp.compile("llhttp");
}
