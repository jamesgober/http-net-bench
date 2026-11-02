//! llhttp, report only (workload H5).
//!
//! The vendored release C sources, compiled by `build.rs`. Two drivers over
//! the same input, in the same 16 KiB reads as http-net's:
//!
//! - [`Conn::count_only`]: llhttp with one callback, counting messages: what
//!   llhttp's own benchmark table measures. llhttp validates and frames but
//!   nothing reads a field, so this is a floor, not a server.
//! - [`Conn::serve_all`]: the same answers a server gets from http-net's
//!   `ServerConn`. Each span is copied into a reused head buffer (a span can
//!   cross a read, and `ServerConn` copies its input too), the fields are
//!   indexed, `host` is counted, keep-alive is read, and every request is
//!   answered by writing a response into `out`.
//!
//! What stays unequal: the response is a canned byte string here, where
//! http-net formats its prebuilt `Response`, and the C boundary is crossed
//! per callback, about seven times per request of this input.

use std::{
    ffi::{c_char, c_int, c_void},
    hint::black_box,
    mem::MaybeUninit,
    ptr, slice,
};

/// `llhttp_t`, field for field from the vendored `llhttp.h`.
#[repr(C)]
struct Parser {
    index: i32,
    span_pos0: *mut c_void,
    span_cb0: *mut c_void,
    error: i32,
    reason: *const c_char,
    error_pos: *const c_char,
    data: *mut c_void,
    current: *mut c_void,
    content_length: u64,
    kind: u8,
    method: u8,
    http_major: u8,
    http_minor: u8,
    header_state: u8,
    lenient_flags: u16,
    upgrade: u8,
    finish: u8,
    flags: u16,
    status_code: u16,
    initial_message_completed: u8,
    settings: *mut c_void,
}

type Cb = Option<unsafe extern "C" fn(*mut Parser) -> c_int>;
type DataCb = Option<unsafe extern "C" fn(*mut Parser, *const c_char, usize) -> c_int>;

/// `llhttp_settings_t`, field for field from the vendored `llhttp.h`.
#[repr(C)]
struct Settings {
    on_message_begin: Cb,
    on_protocol: DataCb,
    on_url: DataCb,
    on_status: DataCb,
    on_method: DataCb,
    on_version: DataCb,
    on_header_field: DataCb,
    on_header_value: DataCb,
    on_chunk_extension_name: DataCb,
    on_chunk_extension_value: DataCb,
    on_headers_complete: Cb,
    on_body: DataCb,
    on_message_complete: Cb,
    on_protocol_complete: Cb,
    on_url_complete: Cb,
    on_status_complete: Cb,
    on_method_complete: Cb,
    on_version_complete: Cb,
    on_header_field_complete: Cb,
    on_header_value_complete: Cb,
    on_chunk_extension_name_complete: Cb,
    on_chunk_extension_value_complete: Cb,
    on_chunk_header: Cb,
    on_chunk_complete: Cb,
    on_reset: Cb,
}

/// `HTTP_REQUEST` of `enum llhttp_type`.
const HTTP_REQUEST: c_int = 1;

/// `HPE_USER` of `enum llhttp_errno`: a callback refused the message.
const HPE_USER: c_int = 24;

unsafe extern "C" {
    fn llhttp_init(parser: *mut Parser, kind: c_int, settings: *const Settings);
    fn llhttp_settings_init(settings: *mut Settings);
    fn llhttp_execute(parser: *mut Parser, data: *const c_char, len: usize) -> c_int;
    fn llhttp_finish(parser: *mut Parser) -> c_int;
    fn llhttp_should_keep_alive(parser: *const Parser) -> c_int;
    fn llhttp_get_method(parser: *mut Parser) -> u8;
}

/// The most fields one request may carry here, as http-net's default limit.
const MAX_FIELDS: usize = 128;

/// Where one field line sits in the head buffer.
#[derive(Clone, Copy, Debug, Default)]
struct FieldAt {
    name: (u32, u32),
    value_end: u32,
}

/// One request as [`Conn::serve_all`] saw it.
#[derive(Debug)]
pub struct Message<'a> {
    /// `llhttp_get_method`: 1 is `GET`.
    pub method: u8,
    /// The request target.
    pub target: &'a [u8],
    /// Field count.
    pub fields: usize,
    /// The value of the one `host` field.
    pub host: &'a [u8],
    /// `llhttp_should_keep_alive`.
    pub keep_alive: bool,
}

/// What to do with each request besides answering it: nothing in the bench,
/// recording it in the equivalence test.
pub trait Watch {
    /// Called once per request, after its response is written.
    fn request(&mut self, message: &Message<'_>);
}

impl Watch for () {
    #[inline]
    fn request(&mut self, _message: &Message<'_>) {}
}

impl<F: FnMut(&Message<'_>)> Watch for F {
    fn request(&mut self, message: &Message<'_>) {
        self(message);
    }
}

struct State<'a, W> {
    head: Vec<u8>,
    target_end: u32,
    fields: [FieldAt; MAX_FIELDS],
    count: usize,
    host: Option<usize>,
    keep_alive: bool,
    requests: usize,
    response: &'a [u8],
    out: &'a mut Vec<u8>,
    watch: W,
}

impl<W> State<'_, W> {
    #[inline]
    fn value_range(&self, field: usize) -> std::ops::Range<usize> {
        let at = self.fields[field];
        at.name.1 as usize..at.value_end as usize
    }
}

/// The driver state behind `parser`.
///
/// # Safety
///
/// `parser.data` must point at the live `State<W>` of the running
/// [`Conn::serve_all`], and no other reference to it may be in use.
#[inline]
unsafe fn state<'p, 'a, W>(parser: *mut Parser) -> &'p mut State<'a, W> {
    // SAFETY: as the caller promises. `serve_all` touches its state only
    // around `llhttp_execute`, never during a callback.
    unsafe { &mut *(*parser).data.cast::<State<'a, W>>() }
}

/// # Safety
///
/// As [`state`]; llhttp passes a span of the input it was given.
unsafe extern "C" fn on_begin<W>(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract.
    let s = unsafe { state::<W>(parser) };
    s.head.clear();
    s.target_end = 0;
    s.count = 0;
    s.host = None;
    0
}

/// # Safety
///
/// As [`state`]; `at` is a span of `len` bytes of the input.
unsafe extern "C" fn on_span<W>(parser: *mut Parser, at: *const c_char, len: usize) -> c_int {
    // SAFETY: as this function's contract.
    let (s, span) = unsafe {
        (
            state::<W>(parser),
            slice::from_raw_parts(at.cast::<u8>(), len),
        )
    };
    s.head.extend_from_slice(span);
    0
}

/// # Safety
///
/// As [`state`].
unsafe extern "C" fn on_target_end<W>(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract.
    let s = unsafe { state::<W>(parser) };
    s.target_end = s.head.len() as u32;
    0
}

/// # Safety
///
/// As [`state`].
unsafe extern "C" fn on_name_end<W>(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract.
    let s = unsafe { state::<W>(parser) };
    if s.count == MAX_FIELDS {
        return HPE_USER;
    }
    let start = if s.count == 0 {
        s.target_end
    } else {
        s.fields[s.count - 1].value_end
    };
    s.fields[s.count].name = (start, s.head.len() as u32);
    0
}

/// # Safety
///
/// As [`state`].
unsafe extern "C" fn on_value_end<W>(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract.
    let s = unsafe { state::<W>(parser) };
    let end = s.head.len() as u32;
    let at = &mut s.fields[s.count];
    at.value_end = end;
    let name = &s.head[at.name.0 as usize..at.name.1 as usize];
    if name.eq_ignore_ascii_case(b"host") {
        if s.host.is_some() {
            return HPE_USER;
        }
        s.host = Some(s.count);
    }
    s.count += 1;
    0
}

/// # Safety
///
/// As [`state`].
unsafe extern "C" fn on_headers_end<W>(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract; `parser` is the running parser.
    let (s, keep_alive) = unsafe { (state::<W>(parser), llhttp_should_keep_alive(parser)) };
    s.keep_alive = keep_alive != 0;
    if s.host.is_none() { HPE_USER } else { 0 }
}

/// # Safety
///
/// As [`state`].
unsafe extern "C" fn on_end<W: Watch>(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract; `parser` is the running parser.
    let (s, method) = unsafe { (state::<W>(parser), llhttp_get_method(parser)) };
    s.requests += 1;
    let target = &s.head[..s.target_end as usize];
    black_box(target);
    s.out.clear();
    s.out.extend_from_slice(s.response);
    let host = s.host.map_or(0..0, |at| s.value_range(at));
    let message = Message {
        method,
        target,
        fields: s.count,
        host: &s.head[host],
        keep_alive: s.keep_alive,
    };
    s.watch.request(&message);
    0
}

/// # Safety
///
/// `parser.data` must point at a live `usize`.
unsafe extern "C" fn on_end_count(parser: *mut Parser) -> c_int {
    // SAFETY: as this function's contract.
    unsafe { *(*parser).data.cast::<usize>() += 1 };
    0
}

fn empty_settings() -> Settings {
    let mut settings = MaybeUninit::<Settings>::uninit();
    // SAFETY: `llhttp_settings_init` zero-fills the whole struct, which is
    // `None` for every field.
    unsafe {
        llhttp_settings_init(settings.as_mut_ptr());
        settings.assume_init()
    }
}

/// A fresh llhttp request parser: the setup of one H5 iteration, which is
/// not timed.
pub struct Conn {
    parser: Box<MaybeUninit<Parser>>,
    head: Vec<u8>,
}

impl Conn {
    /// A new connection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parser: Box::new(MaybeUninit::uninit()),
            head: Vec::with_capacity(4096),
        }
    }

    /// Feeds `input` in `read`-sized pieces to a parser with `settings` and
    /// `data` behind it, then ends the stream.
    fn run(
        &mut self,
        settings: &Settings,
        data: *mut c_void,
        input: &[u8],
        read: usize,
    ) -> Result<(), c_int> {
        let parser = self.parser.as_mut_ptr();
        // SAFETY: `llhttp_init` fills the parser. `settings` outlives it: it
        // is only used by the execute and finish calls below. The caller's
        // `data` is what the callbacks in `settings` expect. Every piece is
        // valid for its length.
        unsafe {
            llhttp_init(parser, HTTP_REQUEST, settings);
            (*parser).data = data;
            for piece in input.chunks(read) {
                let code = llhttp_execute(parser, piece.as_ptr().cast(), piece.len());
                if code != 0 {
                    return Err(code);
                }
            }
            match llhttp_finish(parser) {
                0 => Ok(()),
                code => Err(code),
            }
        }
    }

    /// Parses `input`, counting messages and reading nothing. Returns the
    /// count.
    ///
    /// # Errors
    ///
    /// The `llhttp_errno` that stopped the parse.
    pub fn count_only(&mut self, input: &[u8], read: usize) -> Result<usize, c_int> {
        let mut settings = empty_settings();
        settings.on_message_complete = Some(on_end_count);
        let mut count = 0usize;
        self.run(&settings, (&raw mut count).cast(), input, read)?;
        Ok(count)
    }

    /// Serves `input`, writing `response` into `out` for every request
    /// (cleared per response, so it holds the last one, as
    /// [`crate::net::serve_all`]). Returns the request count.
    ///
    /// # Errors
    ///
    /// The `llhttp_errno` that stopped the parse; `HPE_USER` for a request
    /// without exactly one `host`.
    pub fn serve_all<W: Watch>(
        &mut self,
        input: &[u8],
        read: usize,
        response: &[u8],
        out: &mut Vec<u8>,
        watch: W,
    ) -> Result<usize, c_int> {
        let mut settings = empty_settings();
        settings.on_message_begin = Some(on_begin::<W>);
        settings.on_url = Some(on_span::<W>);
        settings.on_url_complete = Some(on_target_end::<W>);
        settings.on_header_field = Some(on_span::<W>);
        settings.on_header_field_complete = Some(on_name_end::<W>);
        settings.on_header_value = Some(on_span::<W>);
        settings.on_header_value_complete = Some(on_value_end::<W>);
        settings.on_headers_complete = Some(on_headers_end::<W>);
        settings.on_message_complete = Some(on_end::<W>);
        let mut state = State {
            head: std::mem::take(&mut self.head),
            target_end: 0,
            fields: [FieldAt::default(); MAX_FIELDS],
            count: 0,
            host: None,
            keep_alive: false,
            requests: 0,
            response,
            out,
            watch,
        };
        let done = self.run(&settings, ptr::from_mut(&mut state).cast(), input, read);
        self.head = state.head;
        done.map(|()| state.requests)
    }
}

impl Default for Conn {
    fn default() -> Self {
        Self::new()
    }
}
