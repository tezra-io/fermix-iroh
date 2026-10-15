//! Entry point. NDJSON ops on stdin, NDJSON events on stdout.
//!
//! stdout carries the protocol and nothing else. stderr is not part of the
//! channel; the daemon does not read it.
//!
//! Exit status: 0 after `shutdown` or end of stdin, 1 after an `error` event,
//! 101 on any panic in any thread (so a panicking task is never swallowed by
//! the runtime), 2 for a usage error, 3 if the async runtime cannot start.

use std::process::ExitCode;

use fermix_iroh::endpoint::{Network, PROXY_VARIABLES};
use fermix_iroh::{IROH_VERSION, VERSION, session};

/// Exit status for unexpected arguments. The daemon passes none.
const EXIT_USAGE: u8 = 2;
/// Exit status when the runtime cannot be built; no `hello` was sent.
const EXIT_RUNTIME: u8 = 3;
/// Exit status for a panic, Rust's own.
const EXIT_PANIC: i32 = 101;

fn main() -> ExitCode {
    drop_proxy_variables();
    exit_on_any_panic();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => serve(),
        [flag] if flag == "--version" || flag == "-V" => {
            println!("fermix-iroh {VERSION} (iroh {IROH_VERSION})");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("fermix-iroh: unexpected arguments: {}", args.join(" "));
            eprintln!("usage: fermix-iroh [--version]  (speaks NDJSON on stdin/stdout)");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Remove the proxy variables iroh's HTTPS probes would otherwise honour (see
/// `PROXY_VARIABLES`). Runs first in `main`, before any thread exists.
fn drop_proxy_variables() {
    for name in PROXY_VARIABLES {
        // SAFETY: `main` calls this before it starts the runtime or any other
        // thread, so nothing can be reading the environment concurrently.
        unsafe { std::env::remove_var(name) };
    }
}

/// A panic anywhere, including inside a spawned task, ends the process with
/// 101 after the default report on stderr.
fn exit_on_any_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        std::process::exit(EXIT_PANIC);
    }));
}

fn serve() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("fermix-iroh: cannot start the async runtime: {e}");
            return ExitCode::from(EXIT_RUNTIME);
        }
    };
    let exit = runtime.block_on(session::run(
        tokio::io::stdin(),
        tokio::io::stdout(),
        Network::production(),
    ));
    // stdin's blocking reader may still be parked in read(2); do not wait for it.
    runtime.shutdown_background();
    ExitCode::from(exit.code())
}
