//! The load generator of workload H6, plaintext over sockets.
//!
//! The same generator drives every server (`h6_server`), with the same
//! request bytes from [`crate::inputs::PLAINTEXT_GET`]. It is closed-loop:
//! each connection writes a batch of pipelined requests, reads every
//! response, checks the batch, and writes the next. One thread per
//! connection, plain blocking sockets, `TCP_NODELAY`.
//!
//! The number that matters is requests per second with the server's one core
//! saturated, so a run also reports the CPU the server process used: well
//! under 100% means the generator, not the server, set the rate.

use std::{
    fs, io,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::inputs::{PLAINTEXT_BODY, PLAINTEXT_GET};

/// One load shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// Open connections.
    pub connections: usize,
    /// Requests written per batch on each connection.
    pub pipeline: usize,
}

/// The shapes of a run: TechEmpower's pipeline depth on one connection and
/// on 16, and plain keep-alive as a reference.
pub const SHAPES: [Shape; 3] = [
    Shape {
        connections: 1,
        pipeline: 1,
    },
    Shape {
        connections: 1,
        pipeline: 16,
    },
    Shape {
        connections: 16,
        pipeline: 16,
    },
];

/// What one measured run produced.
#[derive(Clone, Copy, Debug)]
pub struct Run {
    /// Requests answered inside the measured window.
    pub requests: u64,
    /// The length of the measured window, in seconds.
    pub seconds: f64,
    /// CPU the server used in the window, in percent of one core; `None`
    /// without a pid or a `/proc`.
    pub server_cpu: Option<f64>,
}

impl Run {
    /// Requests per second.
    #[must_use]
    pub fn rate(&self) -> f64 {
        self.requests as f64 / self.seconds
    }
}

/// Connects to `addr`, retrying until `wait` runs out (a server needs a
/// moment to bind).
///
/// # Errors
///
/// The last connect error.
pub fn connect(addr: SocketAddr, wait: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + wait;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Reads one whole response (head by `httparse`, body by `content-length`)
/// from `stream`, starting with what is already in `got`.
///
/// # Errors
///
/// An I/O error, or `InvalidData` if the bytes are not a response.
pub fn read_response(stream: &mut TcpStream, got: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 4096];
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(got) {
            Ok(httparse::Status::Complete(head)) => {
                let length = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok()?.parse::<usize>().ok())
                    .ok_or(io::ErrorKind::InvalidData)?;
                if got.len() >= head + length {
                    return Ok(got.drain(..head + length).collect());
                }
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(io::ErrorKind::InvalidData.into()),
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        got.extend_from_slice(&buf[..n]);
    }
}

/// The length of one response from the server at `addr`, which must be the
/// same for every request (`date` has a fixed width).
fn response_len(addr: SocketAddr) -> io::Result<usize> {
    let mut stream = connect(addr, Duration::from_secs(5))?;
    stream.write_all(PLAINTEXT_GET)?;
    Ok(read_response(&mut stream, &mut Vec::new())?.len())
}

fn valid(batch: &[u8]) -> bool {
    // Only the code: may-minihttp's reason phrase is `Ok`.
    batch.starts_with(b"HTTP/1.1 200 ") && batch.ends_with(PLAINTEXT_BODY)
}

#[repr(align(64))]
struct Counter(AtomicU64);

fn connection_loop(
    mut stream: TcpStream,
    pipeline: usize,
    one: usize,
    done: &AtomicBool,
    count: &Counter,
) -> io::Result<()> {
    let batch = PLAINTEXT_GET.repeat(pipeline);
    let want = one * pipeline;
    let mut buf = vec![0u8; want];
    let mut requests = 0u64;
    while !done.load(Ordering::Relaxed) {
        stream.write_all(&batch)?;
        stream.read_exact(&mut buf)?;
        if !valid(&buf) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        requests += pipeline as u64;
        count.0.store(requests, Ordering::Relaxed);
    }
    Ok(())
}

/// The CPU time `pid` has used so far, in seconds (user and system, every
/// thread).
fn cpu_seconds(pid: u32) -> Option<f64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesized name; utime and stime are 14 and 15 of
    // proc(5), in clock ticks (100 per second on Linux).
    let mut after = stat.rsplit_once(')')?.1.split_whitespace();
    let utime: u64 = after.nth(11)?.parse().ok()?;
    let stime: u64 = after.next()?.parse().ok()?;
    Some((utime + stime) as f64 / 100.0)
}

fn total(counts: &[Arc<Counter>]) -> u64 {
    counts.iter().map(|c| c.0.load(Ordering::Relaxed)).sum()
}

/// Runs `shape` against the server at `addr`: `warm_up`, then `measure`, in
/// which requests and the CPU of `server_pid` are counted.
///
/// # Errors
///
/// The first error of the probe or of any connection: a server that closes
/// a connection or sends a wrong response fails the run.
///
/// # Panics
///
/// If a connection thread panics.
pub fn run(
    addr: SocketAddr,
    shape: Shape,
    warm_up: Duration,
    measure: Duration,
    server_pid: Option<u32>,
) -> io::Result<Run> {
    let one = response_len(addr)?;
    let done = Arc::new(AtomicBool::new(false));
    let mut counts = Vec::with_capacity(shape.connections);
    let mut threads = Vec::with_capacity(shape.connections);
    for _ in 0..shape.connections {
        let stream = connect(addr, Duration::from_secs(5))?;
        let count = Arc::new(Counter(AtomicU64::new(0)));
        counts.push(Arc::clone(&count));
        let done = Arc::clone(&done);
        threads.push(thread::spawn(move || {
            connection_loop(stream, shape.pipeline, one, &done, &count)
        }));
    }

    thread::sleep(warm_up);
    let (start, first) = (Instant::now(), total(&counts));
    let cpu_start = server_pid.and_then(cpu_seconds);
    thread::sleep(measure);
    let (seconds, last) = (start.elapsed().as_secs_f64(), total(&counts));
    let cpu_end = server_pid.and_then(cpu_seconds);
    done.store(true, Ordering::Relaxed);

    for thread in threads {
        thread.join().expect("a connection thread panicked")?;
    }
    Ok(Run {
        requests: last - first,
        seconds,
        server_cpu: cpu_start
            .zip(cpu_end)
            .map(|(a, b)| (b - a) / seconds * 100.0),
    })
}
