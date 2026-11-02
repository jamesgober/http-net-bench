//! picohttpparser, report only (workloads H1 and H4).
//!
//! The vendored C source, compiled by `build.rs` twice: with SSE4.2 (its
//! only SIMD path, chosen at compile time) and scalar. picohttpparser stops
//! at syntax as `httparse` does, so H1 runs the same framing pass after it
//! ([`crate::framing`]). `tests/equivalence.rs` checks that the pair answers
//! as http-net does.
//!
//! The calls cross a C boundary with no inlining, a cost of about a
//! nanosecond per call that the Rust parsers do not pay. H1 makes one call
//! and H4 one, so it does not move a row.

use std::{
    ffi::{c_char, c_int},
    ptr, slice,
};

use crate::{
    chunked::Decoded,
    framing::{self, FieldLine, FramingError},
    net::{HeadSummary, offset_in},
};

/// `struct phr_header`: one field line, pointing into the parsed input.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PhrHeader {
    name: *const c_char,
    name_len: usize,
    value: *const c_char,
    value_len: usize,
}

impl PhrHeader {
    /// An unfilled header, as `httparse::EMPTY_HEADER`.
    pub const EMPTY: Self = Self {
        name: ptr::null(),
        name_len: 0,
        value: ptr::null(),
        value_len: 0,
    };
}

impl FieldLine for PhrHeader {
    #[inline]
    fn name(&self) -> &[u8] {
        // SAFETY: only a successful parse hands these to the framing pass;
        // it filled the pointer and length with a span of the input, which
        // outlives the pass.
        unsafe { slice::from_raw_parts(self.name.cast(), self.name_len) }
    }

    #[inline]
    fn value(&self) -> &[u8] {
        // SAFETY: as in `name`.
        unsafe { slice::from_raw_parts(self.value.cast(), self.value_len) }
    }
}

/// `struct phr_chunked_decoder`, to be zero-filled before use.
#[repr(C)]
struct PhrChunkedDecoder {
    bytes_left_in_chunk: usize,
    consume_trailer: c_char,
    hex_count: c_char,
    state: c_char,
    total_read: u64,
    total_overhead: u64,
}

type ParseRequest = unsafe extern "C" fn(
    buf: *const c_char,
    len: usize,
    method: *mut *const c_char,
    method_len: *mut usize,
    path: *mut *const c_char,
    path_len: *mut usize,
    minor_version: *mut c_int,
    headers: *mut PhrHeader,
    num_headers: *mut usize,
    last_len: usize,
) -> c_int;

unsafe extern "C" {
    fn phr_parse_request(
        buf: *const c_char,
        len: usize,
        method: *mut *const c_char,
        method_len: *mut usize,
        path: *mut *const c_char,
        path_len: *mut usize,
        minor_version: *mut c_int,
        headers: *mut PhrHeader,
        num_headers: *mut usize,
        last_len: usize,
    ) -> c_int;
    fn phr_parse_request_scalar(
        buf: *const c_char,
        len: usize,
        method: *mut *const c_char,
        method_len: *mut usize,
        path: *mut *const c_char,
        path_len: *mut usize,
        minor_version: *mut c_int,
        headers: *mut PhrHeader,
        num_headers: *mut usize,
        last_len: usize,
    ) -> c_int;
    fn phr_decode_chunked(
        decoder: *mut PhrChunkedDecoder,
        buf: *mut c_char,
        bufsz: *mut usize,
    ) -> isize;
}

/// Which compiled copy of picohttpparser to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Build {
    /// Compiled with `-msse4.2`.
    Sse42,
    /// Compiled without it.
    Scalar,
}

impl Build {
    #[inline]
    fn parse_request(self) -> ParseRequest {
        match self {
            Self::Sse42 => phr_parse_request,
            Self::Scalar => phr_parse_request_scalar,
        }
    }
}

/// Why picohttpparser refused its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PicoError {
    /// The C function returned -1.
    Parse,
    /// The C function returned -2: the input ends early.
    Partial,
    /// The framing pass refused the head.
    Framing(FramingError),
    /// The decoded body is over the budget.
    BodyTooLarge,
}

/// A request head as picohttpparser split it.
#[derive(Clone, Copy, Debug)]
pub struct Parsed<'b> {
    /// The method.
    pub method: &'b [u8],
    /// The request target.
    pub target: &'b [u8],
    /// The digit of `HTTP/1.x`.
    pub minor: u8,
    /// Fields filled in the caller's array.
    pub fields: usize,
    /// Bytes of input the head took.
    pub len: usize,
}

/// H1 reference, picohttpparser: `phr_parse_request` with nothing after it.
///
/// # Errors
///
/// [`PicoError::Parse`] or [`PicoError::Partial`].
#[inline]
pub fn parse<'b>(
    build: Build,
    input: &'b [u8],
    headers: &mut [PhrHeader],
) -> Result<Parsed<'b>, PicoError> {
    let (mut method, mut method_len) = (ptr::null(), 0);
    let (mut path, mut path_len) = (ptr::null(), 0);
    let mut minor: c_int = -1;
    let mut fields = headers.len();
    // SAFETY: every pointer is valid for the call, `input` for `input.len()`
    // bytes and `headers` for `fields` entries. A last length of 0 means the
    // input is new.
    let ret = unsafe {
        (build.parse_request())(
            input.as_ptr().cast(),
            input.len(),
            &raw mut method,
            &raw mut method_len,
            &raw mut path,
            &raw mut path_len,
            &raw mut minor,
            headers.as_mut_ptr(),
            &raw mut fields,
            0,
        )
    };
    match ret {
        -2 => return Err(PicoError::Partial),
        ..0 => return Err(PicoError::Parse),
        _ => {}
    }
    // SAFETY: on success `method` and `path` are spans of `input`.
    let (method, target) = unsafe {
        (
            slice::from_raw_parts(method.cast(), method_len),
            slice::from_raw_parts(path.cast(), path_len),
        )
    };
    Ok(Parsed {
        method,
        target,
        minor: u8::try_from(minor).map_err(|_| PicoError::Parse)?,
        fields,
        len: ret.unsigned_abs() as usize,
    })
}

/// H1, picohttpparser: [`parse`], then the framing pass.
///
/// # Errors
///
/// The [`PicoError`] for the parse or the framing pass.
#[inline]
pub fn head(
    build: Build,
    input: &[u8],
    headers: &mut [PhrHeader],
    max_body: u64,
) -> Result<HeadSummary, PicoError> {
    let parsed = parse(build, input, headers)?;
    let facts = framing::request_parts_framing(
        parsed.method,
        parsed.target,
        parsed.minor,
        &headers[..parsed.fields],
        max_body,
    )
    .map_err(PicoError::Framing)?;
    Ok(HeadSummary {
        method_at: offset_in(input, parsed.method),
        target_at: offset_in(input, parsed.target),
        fields: parsed.fields,
        len: parsed.len,
        framing: facts.framing,
        keep_alive: facts.keep_alive,
        host_present: facts.host_present,
    })
}

/// H4, picohttpparser: `phr_decode_chunked` over a whole chunked body. It
/// decodes in place by moving each chunk's data down over the chunk lines
/// before it, so `buf` is rewritten, the body ends up in
/// `buf[..total]`, and the work includes one move of every data byte: the
/// row to compare is `*_copy_out`, not the slice-only one.
///
/// The body budget is checked once at the end: the function has no budget of
/// its own and reports nothing between chunks.
///
/// # Errors
///
/// [`PicoError::Parse`], [`PicoError::Partial`], or
/// [`PicoError::BodyTooLarge`].
#[inline]
pub fn decode_chunked(buf: &mut [u8], max_body: u64) -> Result<Decoded, PicoError> {
    let mut decoder = PhrChunkedDecoder {
        bytes_left_in_chunk: 0,
        consume_trailer: 1,
        hex_count: 0,
        state: 0,
        total_read: 0,
        total_overhead: 0,
    };
    let mut size = buf.len();
    // SAFETY: `buf` is valid for reads and writes of `size` bytes.
    let left =
        unsafe { phr_decode_chunked(&raw mut decoder, buf.as_mut_ptr().cast(), &raw mut size) };
    let left = match left {
        -2 => return Err(PicoError::Partial),
        ..0 => return Err(PicoError::Parse),
        _ => left.unsigned_abs(),
    };
    let total = size as u64;
    if total > max_body {
        return Err(PicoError::BodyTooLarge);
    }
    Ok(Decoded {
        total,
        consumed: buf.len() - left,
    })
}
