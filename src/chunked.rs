//! The chunked-body loops of workload H4.
//!
//! Both sides decode in place: they report each run of body data as a slice
//! of the input to a sink and copy nothing (the spec's fairness rule for H4
//! allows in-place decoding for all). Both check the body budget before
//! accepting a chunk's data.

use http_net::{ChunkStep, ChunkedDecoder, HttpError, Limits};

/// What a decode loop reports at the end of a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// Body bytes delivered.
    pub total: u64,
    /// Input bytes consumed, the last chunk and trailer section included.
    pub consumed: usize,
}

/// Decodes a whole chunked body with http-net's [`ChunkedDecoder`] (the
/// connections' decoder: chunk-size grammar, extension budget, body budget,
/// CRLF after the data, trailer validation).
///
/// # Errors
///
/// Any decoder error, or [`HttpError::UnexpectedEof`] if `wire` ends early.
#[inline]
pub fn http_net_decode(
    wire: &[u8],
    limits: &Limits,
    mut sink: impl FnMut(&[u8]),
) -> Result<Decoded, HttpError> {
    let mut decoder = ChunkedDecoder::new(limits);
    let mut pos = 0;
    loop {
        // The whole body is in `wire`, so `eof` never matters; `NeedMore`
        // would mean it is truncated.
        match decoder.decode(&wire[pos..], false)? {
            ChunkStep::Data { skip, len } => {
                sink(&wire[pos + skip..pos + skip + len]);
                pos += skip + len;
            }
            ChunkStep::Trailers { skip, len } => pos += skip + len,
            ChunkStep::Done { consumed } => {
                pos += consumed;
                return Ok(Decoded {
                    total: decoder.total(),
                    consumed: pos,
                });
            }
            ChunkStep::NeedMore { .. } => return Err(HttpError::UnexpectedEof),
            // `ChunkStep` is non-exhaustive; 0.5 has exactly the four.
            _ => return Err(HttpError::UnexpectedEof),
        }
    }
}

/// Why the httparse loop refused a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// `httparse::parse_chunk_size` refused a chunk-size line.
    InvalidChunkSize,
    /// The data of a chunk is not followed by CRLF.
    InvalidChunkTerminator,
    /// The decoded body would exceed the budget.
    BodyTooLarge,
    /// A trailer section with fields: this loop, like the bench input, has
    /// none (http-net validates and skips them).
    Trailers,
    /// The input ends before the body does.
    UnexpectedEof,
}

/// Decodes a whole chunked body with a loop over
/// [`httparse::parse_chunk_size`], doing the checks http-net's decoder does
/// on this input:
///
/// - each chunk-size line through `parse_chunk_size` (hex digits, at most 16,
///   an extension after `;`, CRLF);
/// - the body budget, before the chunk's data is accepted;
/// - the chunk's data present in full, then CRLF after it;
/// - after the last chunk (size 0), an empty trailer section: CRLF.
///
/// It reports data slices to `sink` and copies nothing.
///
/// # Errors
///
/// The [`ChunkError`] for the first rule the body breaks.
#[inline]
pub fn httparse_decode(
    wire: &[u8],
    max_body: u64,
    mut sink: impl FnMut(&[u8]),
) -> Result<Decoded, ChunkError> {
    let mut pos = 0usize;
    let mut total = 0u64;
    loop {
        let (line, size) = match httparse::parse_chunk_size(&wire[pos..]) {
            Ok(httparse::Status::Complete(found)) => found,
            Ok(httparse::Status::Partial) => return Err(ChunkError::UnexpectedEof),
            Err(_) => return Err(ChunkError::InvalidChunkSize),
        };
        pos += line;
        if size == 0 {
            return match wire.get(pos..pos + 2) {
                Some(b"\r\n") => Ok(Decoded {
                    total,
                    consumed: pos + 2,
                }),
                Some(_) => Err(ChunkError::Trailers),
                None => Err(ChunkError::UnexpectedEof),
            };
        }
        if size > max_body - total {
            return Err(ChunkError::BodyTooLarge);
        }
        let len = usize::try_from(size).map_err(|_| ChunkError::BodyTooLarge)?;
        let Some(data) = wire.get(pos..pos + len) else {
            return Err(ChunkError::UnexpectedEof);
        };
        sink(data);
        total += size;
        pos += len;
        match wire.get(pos..pos + 2) {
            Some(b"\r\n") => pos += 2,
            Some(_) => return Err(ChunkError::InvalidChunkTerminator),
            None => return Err(ChunkError::UnexpectedEof),
        }
    }
}
