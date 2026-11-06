//! The H6 servers: one plaintext server per process, all answering
//! `GET /plaintext` with the same status, `content-type`, and body, and 404
//! for any other path.
//!
//! ```text
//! h6_server <serve-net|serve-net-blocking|hyper|actix-web|may-minihttp> <addr>
//! ```
//!
//! Each is set up for one core, the way its own documentation gives for one
//! worker; `scripts/run.sh` pins the process with `taskset`. Every one keeps
//! connections open indefinitely and sends a `date` field. The differences
//! that remain are in the README.

use std::{convert::Infallible, env, error::Error, io, net::SocketAddr, process::ExitCode};

use bytes::Bytes;
use http_body_util::Full;
use http_net_bench::inputs::{PLAINTEXT_BODY, PLAINTEXT_PATH, PLAINTEXT_TYPE};
use hyper::{Request, Response, StatusCode, body::Incoming, header, service::service_fn};
use hyper_util::rt::TokioIo;

/// serve-net through its Tier 2 builder, over http-net's `ServerConn`.
///
/// `workers` picks net-io's driver: the reactor with one event loop, which
/// is how every other server here runs, or the blocking pool, where every
/// connection holds a thread (sized for the 16 connections of the largest
/// shape, all sharing the pinned core).
fn serve_net_server(addr: SocketAddr, workers: serve_net::Workers) -> Result<(), Box<dyn Error>> {
    use serve_net::{KeepAlive, ListenerSpec, Server};
    const FOREVER: std::time::Duration = std::time::Duration::from_secs(u32::MAX as u64);

    // Proof that the http-net behind serve-net is this crate's, 0.9.
    let _: serve_net::http_net::Limits = http_net_bench::inputs::limits();

    let service = serve_net::handler(|req, reply| {
        if req.path() == PLAINTEXT_PATH {
            reply
                .status(200)
                .header("content-type", PLAINTEXT_TYPE)
                .body_static(PLAINTEXT_BODY);
        } else {
            reply.text(404, "not found");
        }
    });
    let running = Server::builder()
        .listener(ListenerSpec::tcp("h6", addr))
        .keep_alive(
            KeepAlive::new()
                .max_requests(u32::MAX)
                .max_age(FOREVER)
                .idle(FOREVER),
        )
        .workers(workers)
        .serve(service)?;
    running.wait();
    Ok(())
}

async fn hyper_plaintext(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut response = if req.uri().path() == PLAINTEXT_PATH {
        Response::new(Full::new(Bytes::from_static(PLAINTEXT_BODY)))
    } else {
        let mut response = Response::new(Full::new(Bytes::from_static(b"not found")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        response
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(PLAINTEXT_TYPE),
    );
    Ok(response)
}

/// hyper 1.x on a current-thread tokio runtime, `pipeline_flush` on, as in
/// H5, `date` on (hyper's default), no header-read timer.
fn hyper_server(addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .header_read_timeout(None)
                    .pipeline_flush(true)
                    .serve_connection(TokioIo::new(stream), service_fn(hyper_plaintext))
                    .await;
            });
        }
    })
}

/// actix-web 4 with one worker.
fn actix_server(addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    use actix_web::{App, HttpResponse, HttpServer, http::header::ContentType, rt::System, web};

    System::new().block_on(async move {
        HttpServer::new(|| {
            App::new().route(
                PLAINTEXT_PATH,
                web::get().to(|| async {
                    HttpResponse::Ok()
                        .insert_header(ContentType(PLAINTEXT_TYPE.parse().expect("a media type")))
                        .body(PLAINTEXT_BODY)
                }),
            )
        })
        .workers(1)
        .disable_signals()
        .bind(addr)?
        .run()
        .await
    })?;
    Ok(())
}

/// may-minihttp on one `may` worker. It writes `server` and `date` itself.
struct MayPlaintext;

/// The factory form of may-minihttp's server, for the one thing the plain
/// form cannot do: may-minihttp never sets `TCP_NODELAY` (the call is
/// commented out upstream), and every other server here does, so without it
/// pipelined batches of about 1 KiB and up stall. The factory is told each
/// connection's descriptor.
struct MayFactory;

impl may_minihttp::HttpServiceFactory for MayFactory {
    type Service = MayPlaintext;

    fn new_service(&self, id: usize) -> MayPlaintext {
        use std::{mem::ManuallyDrop, net::TcpStream, os::fd::FromRawFd};

        // SAFETY: on Unix `id` is the descriptor of the accepted connection,
        // open for as long as the connection is. `ManuallyDrop` keeps this
        // borrowed view from closing it.
        let stream = ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(id as i32) });
        stream.set_nodelay(true).expect("TCP_NODELAY");
        MayPlaintext
    }
}

impl may_minihttp::HttpService for MayPlaintext {
    fn call(
        &mut self,
        req: may_minihttp::Request,
        res: &mut may_minihttp::Response,
    ) -> io::Result<()> {
        if req.path() == PLAINTEXT_PATH {
            res.header("content-type: text/plain");
            res.body("Hello, World!");
        } else {
            res.status_code(404, "Not Found");
            res.body("not found");
        }
        Ok(())
    }
}

fn may_server(addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    may::config().set_workers(1);
    let server = may_minihttp::HttpServiceFactory::start(MayFactory, addr)?;
    server.join().map_err(|_| "the may server panicked")?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(addr) = args.get(1).and_then(|a| a.parse().ok()) else {
        eprintln!(
            "usage: h6_server <serve-net|serve-net-blocking|hyper|actix-web|may-minihttp> <addr>"
        );
        return ExitCode::from(2);
    };
    let served = match args[0].as_str() {
        "serve-net" => serve_net_server(addr, serve_net::Workers::reactor(1)),
        "serve-net-blocking" => serve_net_server(addr, serve_net::Workers::blocking(32)),
        "hyper" => hyper_server(addr),
        "actix-web" => actix_server(addr),
        "may-minihttp" => may_server(addr),
        other => {
            eprintln!("unknown server {other}");
            return ExitCode::from(2);
        }
    };
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("h6_server: {e}");
            ExitCode::FAILURE
        }
    }
}
