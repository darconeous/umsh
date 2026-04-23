//! Transport-agnostic line I/O for the CLI.

use core::future::Future;

/// Transport trait for the CLI. Implementations shuttle bytes between the CLI
/// and some user-facing transport (stdio, USB serial, Bluetooth RFCOMM, TCP).
///
/// **Cancellation safety:** `read_line` implementations MUST be cancel-safe.
/// The CLI's inner `select!` drops the `read_line` future every time a
/// callback-driven wake fires, so any bytes consumed from the underlying
/// transport must be preserved across such drops — usually by owning an
/// internal partial-line buffer and only returning a completed line atomically.
pub trait CliIo {
    type Error: core::fmt::Debug;

    /// Read one line (terminator stripped) into `buf`. `Ok(None)` on EOF.
    /// `Err` on overflow (line > buf.len()) or invalid UTF-8.
    ///
    /// The returned `&'buf str` borrows from `buf` only, not from `self`.
    /// This lets the caller hold the line reference while `&mut self` is
    /// available for other methods.
    fn read_line<'io, 'buf>(
        &'io mut self,
        buf: &'buf mut [u8],
    ) -> impl Future<Output = Result<Option<&'buf str>, Self::Error>> + 'io
    where
        'buf: 'io;

    fn write_line(&mut self, line: &str) -> impl Future<Output = Result<(), Self::Error>>;

    fn flush(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
}

#[cfg(feature = "tokio-stdio")]
pub use stdio::StdioCliIo;

#[cfg(feature = "tokio-stdio")]
mod stdio {
    use super::CliIo;
    use std::io;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};

    /// Tokio-based stdio adapter for the CLI. Internally-buffered `BufReader`
    /// makes `read_line` cancel-safe: if a pending `read_line` is dropped,
    /// any bytes already consumed from stdin remain in the buffer.
    pub struct StdioCliIo {
        reader: BufReader<Stdin>,
        writer: Stdout,
        partial: String,
    }

    impl StdioCliIo {
        pub fn new() -> Self {
            StdioCliIo {
                reader: BufReader::new(tokio::io::stdin()),
                writer: tokio::io::stdout(),
                partial: String::new(),
            }
        }
    }

    impl Default for StdioCliIo {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CliIo for StdioCliIo {
        type Error = io::Error;

        async fn read_line<'io, 'buf>(
            &'io mut self,
            buf: &'buf mut [u8],
        ) -> Result<Option<&'buf str>, Self::Error>
        where
            'buf: 'io,
        {
            // Cancel-safety: accumulate into `self.partial` across cancellations.
            // `BufReader::read_line` appends until the first '\n' or EOF. If the
            // caller drops us mid-read, the bytes we already consumed stay in
            // `self.partial`; the next call picks up where we left off.
            //
            // We only clear `self.partial` after a complete line has been
            // delivered to the caller's buffer.
            let n = self.reader.read_line(&mut self.partial).await?;
            if n == 0 && self.partial.is_empty() {
                return Ok(None);
            }
            // Strip one trailing '\n' and, if present, a preceding '\r'.
            let trimmed_len = {
                let s = self.partial.as_str();
                let mut end = s.len();
                if s.ends_with('\n') {
                    end -= 1;
                    if s[..end].ends_with('\r') {
                        end -= 1;
                    }
                }
                end
            };
            let bytes = &self.partial.as_bytes()[..trimmed_len];
            if bytes.len() > buf.len() {
                self.partial.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input line exceeds buffer size",
                ));
            }
            buf[..bytes.len()].copy_from_slice(bytes);
            let line_len = bytes.len();
            self.partial.clear();
            let out = core::str::from_utf8(&buf[..line_len]).expect("utf8 in = utf8 out");
            Ok(Some(out))
        }

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
