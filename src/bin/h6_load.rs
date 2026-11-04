//! The H6 load generator: one run against a server already listening.
//!
//! ```text
//! h6_load <addr> <connections> <pipeline> <warm-up s> <measure s> [server pid]
//! ```
//!
//! Prints `requests seconds rate server_cpu`, tab separated, for
//! `scripts/run.sh` to collect.

use std::{env, process::ExitCode, time::Duration};

use http_net_bench::h6::{self, Shape};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (Some(addr), Some(connections), Some(pipeline), Some(warm_up), Some(measure)) = (
        args.first().and_then(|a| a.parse().ok()),
        args.get(1).and_then(|a| a.parse().ok()),
        args.get(2).and_then(|a| a.parse().ok()),
        args.get(3).and_then(|a| a.parse().ok()),
        args.get(4).and_then(|a| a.parse().ok()),
    ) else {
        eprintln!("usage: h6_load <addr> <connections> <pipeline> <warm-up s> <measure s> [pid]");
        return ExitCode::from(2);
    };
    let shape = Shape {
        connections,
        pipeline,
    };
    let pid = args.get(5).and_then(|a| a.parse().ok());
    let run = h6::run(
        addr,
        shape,
        Duration::from_secs(warm_up),
        Duration::from_secs(measure),
        pid,
    );
    match run {
        Ok(run) => {
            let cpu = run.server_cpu.map_or("-".to_owned(), |c| format!("{c:.1}"));
            println!(
                "{}\t{:.3}\t{:.0}\t{cpu}",
                run.requests,
                run.seconds,
                run.rate()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("h6_load: {e}");
            ExitCode::FAILURE
        }
    }
}
