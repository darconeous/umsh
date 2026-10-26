//! Line I/O for the CLI.
//!
//! Split into two halves—[`CliInput`] for line-by-line reading, and
//! [`CliOutput`] for writing + flushing. Splitting the halves lets the
//! [`CliSession::run`](crate::CliSession::run) loop hold a long-lived
//! read future across `select!` iterations while the session simultaneously
//! uses the output half to service inbound events. A unified trait would
//! force the read future to borrow the whole transport, blocking concurrent
//! writes.

use std::future::Future;
use std::io;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};

/// Line-reading half of the CLI transport.
///
/// Read futures returned by [`CliInput::read_line`] are NOT required to be
/// cancellation-safe. The driver keeps each read future alive across multiple
/// wake events and only drops it when it completes, so implementations may
/// safely park partial-line state inside the returned future.
pub trait CliInput {
    type Error: std::fmt::Debug;

    /// Read one line, terminator stripped. `Ok(None)` on EOF.
    fn read_line(&mut self) -> impl Future<Output = Result<Option<String>, Self::Error>> + '_;
}

/// Line-writing half of the CLI transport.
pub trait CliOutput {
    type Error: std::fmt::Debug;

    fn write_line(&mut self, line: &str) -> impl Future<Output = Result<(), Self::Error>>;

    fn flush(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Tokio-based stdin reader.
pub struct StdioInput {
    reader: BufReader<Stdin>,
}

/// Tokio-based stdout writer.
pub struct StdioOutput {
    writer: Stdout,
}

/// Construct the stdin/stdout halves for the CLI.
pub fn stdio_split() -> (StdioInput, StdioOutput) {
    (
        StdioInput {
            reader: BufReader::new(tokio::io::stdin()),
        },
        StdioOutput {
            writer: tokio::io::stdout(),
        },
    )
}

impl CliInput for StdioInput {
    type Error = io::Error;

    async fn read_line(&mut self) -> Result<Option<String>, Self::Error> {
        // The driver keeps this future alive across wake events, so we
        // don't need an external partial-line accumulator—tokio's
        // internal `Vec<u8>` inside `ReadLine` retains consumed bytes
        // until the line is complete.
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 && line.is_empty() {
            return Ok(None);
        }
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(Some(line))
    }
}

impl CliOutput for StdioOutput {
    type Error = io::Error;

    async fn write_line(&mut self, line: &str) -> Result<(), Self::Error> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.writer.flush().await
    }
}
