use clap::Parser;
use tracing_subscriber::EnvFilter;

use umsh_bridge::cli::ToolArgs;

fn main() {
    restore_sigpipe();
    let args = ToolArgs::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(args.log_filter()))
        .with_target(false)
        .init();

    if let Err(error) = umsh_bridge::run(args) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

/// Die quietly when a reader goes away, the way every other command-line
/// tool does.
///
/// Rust ignores `SIGPIPE` so that a write to a closed pipe surfaces as an
/// error — which `println!` then turns into a panic. `umsh-bridge check |
/// head` is an ordinary thing to type, and it should not produce a
/// backtrace.
#[cfg(unix)]
fn restore_sigpipe() {
    // SAFETY: setting a signal disposition to the default before any
    // other thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_sigpipe() {}
