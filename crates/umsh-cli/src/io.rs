//! Transport-agnostic line I/O for the CLI.
//!
//! Split into two halves — [`CliInput`] for line-by-line reading, and
//! [`CliOutput`] for writing + flushing. Splitting the halves lets the
//! [`CliSession::run`](crate::CliSession::run) loop hold a long-lived
//! read future across `select!` iterations while the session simultaneously
//! uses the output half to service inbound events. A unified trait would
//! force the read future to borrow the whole transport, blocking concurrent
//! writes.

use core::future::Future;

/// Line-reading half of the CLI transport.
///
/// Read futures returned by [`CliInput::read_line`] are NOT required to be
/// cancellation-safe. The driver keeps each read future alive across multiple
/// wake events and only drops it when it completes, so implementations may
/// safely park partial-line state inside the returned future.
pub trait CliInput {
    type Error: core::fmt::Debug;

    /// Read one line (terminator stripped) into `buf`. `Ok(None)` on EOF.
    /// `Err` on overflow (line > buf.len()) or invalid UTF-8.
    ///
    /// The returned `&'buf str` borrows from `buf` only, not from `self`.
    fn read_line<'io, 'buf>(
        &'io mut self,
        buf: &'buf mut [u8],
    ) -> impl Future<Output = Result<Option<&'buf str>, Self::Error>> + 'io
    where
        'buf: 'io;
}

/// Line-writing half of the CLI transport.
pub trait CliOutput {
    type Error: core::fmt::Debug;

    fn write_line(&mut self, line: &str) -> impl Future<Output = Result<(), Self::Error>>;

    fn flush(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
}

#[cfg(feature = "tokio-stdio")]
pub use stdio::{StdioInput, StdioOutput, stdio_split};

#[cfg(feature = "tokio-stdio")]
mod stdio {
    use super::{CliInput, CliOutput};
    use std::io;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};

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

        async fn read_line<'io, 'buf>(
            &'io mut self,
            buf: &'buf mut [u8],
        ) -> Result<Option<&'buf str>, Self::Error>
        where
            'buf: 'io,
        {
            // The driver keeps this future alive across wake events, so we
            // don't need an external partial-line accumulator — tokio's
            // internal `Vec<u8>` inside `ReadLine` retains consumed bytes
            // until the line is complete.
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 && line.is_empty() {
                return Ok(None);
            }
            let trimmed_len = {
                let s = line.as_str();
                let mut end = s.len();
                if s.ends_with('\n') {
                    end -= 1;
                    if s[..end].ends_with('\r') {
                        end -= 1;
                    }
                }
                end
            };
            let bytes = &line.as_bytes()[..trimmed_len];
            if bytes.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input line exceeds buffer size",
                ));
            }
            buf[..bytes.len()].copy_from_slice(bytes);
            let line_len = bytes.len();
            let out = core::str::from_utf8(&buf[..line_len]).expect("utf8 in = utf8 out");
            Ok(Some(out))
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
}
