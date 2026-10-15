//! NDJSON framing over stdio.
//!
//! One compact JSON object per line, UTF-8, `\n`-terminated, in both
//! directions, at most [`MAX_LINE_BYTES`] per line. The reader never holds more
//! than that: an over-long line is refused as soon as it crosses the bound,
//! before the rest of it is read. Every framing error is fatal to the helper
//! (the contract's "the side that sees it ends the helper"), so the reader does
//! not resynchronize after one.
//!
//! Events are written by one task that owns stdout; every other task hands it
//! events through a bounded channel ([`EventSink`]), so lines never interleave
//! and a daemon that stops reading applies backpressure instead of growing a
//! queue.

use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::protocol::{Event, MAX_LINE_BYTES};

/// Events queued for stdout before senders wait.
const EVENT_QUEUE: usize = 256;

/// A framing failure on the control channel. Each one ends the helper.
#[derive(Debug, thiserror::Error)]
pub enum LineError {
    /// The line crossed [`MAX_LINE_BYTES`].
    #[error("line exceeds {MAX_LINE_BYTES} bytes")]
    Oversize,
    /// The line was not valid UTF-8.
    #[error("line is not UTF-8")]
    NotUtf8,
    /// Input ended in the middle of a line.
    #[error("input ended inside an unterminated line")]
    Unterminated,
    /// stdin failed.
    #[error("reading stdin failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads `\n`-terminated lines with a hard ceiling.
pub struct LineReader<R> {
    inner: R,
    max_bytes: usize,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    /// A reader with the protocol's [`MAX_LINE_BYTES`] ceiling.
    pub fn new(inner: R) -> Self {
        Self::with_max_bytes(inner, MAX_LINE_BYTES)
    }

    /// A reader with an explicit, non-zero ceiling.
    pub fn with_max_bytes(inner: R, max_bytes: usize) -> Self {
        assert!(max_bytes > 0, "max_bytes must be non-zero");
        Self { inner, max_bytes }
    }

    /// The next line without its `\n`, or `None` at a clean end of input.
    pub async fn next_line(&mut self) -> Result<Option<String>, LineError> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            let chunk = self.inner.fill_buf().await?;
            if chunk.is_empty() {
                return match line.is_empty() {
                    true => Ok(None),
                    false => Err(LineError::Unterminated),
                };
            }
            let newline = chunk.iter().position(|b| *b == b'\n');
            let take = newline.unwrap_or(chunk.len());
            if line.len() + take > self.max_bytes {
                return Err(LineError::Oversize);
            }
            line.extend_from_slice(&chunk[..take]);
            let consumed = take + usize::from(newline.is_some());
            self.inner.consume(consumed);
            if newline.is_some() {
                return String::from_utf8(line)
                    .map(Some)
                    .map_err(|_| LineError::NotUtf8);
            }
        }
    }
}

enum Outgoing {
    Event(Event),
    Flush(oneshot::Sender<()>),
}

/// A cloneable handle for sending events to the stdout writer.
///
/// Sending waits while the queue is full. If the writer has stopped, stdout has
/// failed: the session observes that once, through [`EventWriter::failed`], and
/// exits; senders have nothing further to report and simply return.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<Outgoing>,
}

impl EventSink {
    /// Queue one event for stdout.
    pub async fn emit(&self, event: Event) {
        // An error means the writer ended because stdout failed; the session
        // reports that through `EventWriter::failed`, so nothing is added here.
        let _ = self.tx.send(Outgoing::Event(event)).await;
    }

    /// Wait until every event queued before this call is written and flushed,
    /// or `deadline` passes. Returns whether the flush completed.
    pub async fn flush(&self, deadline: Duration) -> bool {
        let (done_tx, done_rx) = oneshot::channel();
        let queued =
            async { self.tx.send(Outgoing::Flush(done_tx)).await.is_ok() && done_rx.await.is_ok() };
        matches!(tokio::time::timeout(deadline, queued).await, Ok(true))
    }
}

/// The task that owns stdout.
pub struct EventWriter {
    task: JoinHandle<std::io::Result<()>>,
}

impl EventWriter {
    /// Start writing events to `out`; returns the writer and its sink.
    pub fn spawn<W>(out: W) -> (EventWriter, EventSink)
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(EVENT_QUEUE);
        let task = tokio::spawn(write_events(rx, out));
        (EventWriter { task }, EventSink { tx })
    }

    /// Resolves only if the writer stops, which happens only when stdout fails
    /// (every sink clone is still alive while the session runs).
    pub async fn failed(&mut self) -> String {
        match (&mut self.task).await {
            Ok(Ok(())) => "stdout writer stopped".to_string(),
            Ok(Err(e)) => format!("writing stdout failed: {e}"),
            Err(e) => format!("stdout writer task failed: {e}"),
        }
    }
}

async fn write_events<W>(mut rx: mpsc::Receiver<Outgoing>, mut out: W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(item) = rx.recv().await {
        match item {
            Outgoing::Event(event) => {
                let line = event.to_line().map_err(std::io::Error::other)?;
                out.write_all(&line).await?;
                out.flush().await?;
            }
            Outgoing::Flush(done) => {
                out.flush().await?;
                // An error means the flusher stopped waiting (its deadline
                // passed); the flush itself still happened.
                let _ = done.send(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorCode, LogLevel};
    use tokio::io::{AsyncReadExt, BufReader};

    async fn read_all(input: &[u8], max: usize, capacity: usize) -> Vec<Result<String, String>> {
        let mut reader = LineReader::with_max_bytes(BufReader::with_capacity(capacity, input), max);
        let mut out = Vec::new();
        loop {
            match reader.next_line().await {
                Ok(Some(line)) => out.push(Ok(line)),
                Ok(None) => return out,
                Err(e) => {
                    out.push(Err(e.to_string()));
                    return out;
                }
            }
        }
    }

    #[tokio::test]
    async fn splits_lines_and_ends_cleanly() {
        let lines = read_all(b"{\"a\":1}\n\n{\"b\":2}\n", 64, 4).await;
        assert_eq!(
            lines,
            vec![
                Ok("{\"a\":1}".into()),
                Ok(String::new()),
                Ok("{\"b\":2}".into())
            ]
        );
    }

    #[tokio::test]
    async fn a_line_at_exactly_the_ceiling_is_accepted_and_one_more_byte_is_not() {
        let exact = format!("{}\n", "z".repeat(64));
        assert_eq!(
            read_all(exact.as_bytes(), 64, 7).await,
            vec![Ok("z".repeat(64))]
        );
        let over = format!("{}\n", "z".repeat(65));
        let lines = read_all(over.as_bytes(), 64, 7).await;
        assert!(matches!(lines.as_slice(), [Err(_)]), "{lines:?}");
    }

    #[tokio::test]
    async fn an_endless_line_is_refused_without_reading_it_all() {
        // 1 MiB with no newline through a 4 KiB buffer and a 64 KiB ceiling.
        let endless = vec![b'y'; 1024 * 1024];
        let mut src: &[u8] = &endless;
        let mut reader = LineReader::new(BufReader::with_capacity(4096, &mut src));
        assert!(matches!(reader.next_line().await, Err(LineError::Oversize)));
        drop(reader);
        assert!(
            src.len() > 900 * 1024,
            "read {} bytes",
            endless.len() - src.len()
        );
    }

    #[tokio::test]
    async fn an_unterminated_tail_and_invalid_utf8_are_errors() {
        let lines = read_all(b"{\"a\":1}\n{\"b\"", 64, 64).await;
        assert_eq!(lines[0], Ok("{\"a\":1}".into()));
        assert_eq!(lines[1], Err(LineError::Unterminated.to_string()));
        let lines = read_all(&[0x7b, 0xff, 0x7d, b'\n'], 64, 64).await;
        assert_eq!(lines, vec![Err(LineError::NotUtf8.to_string())]);
    }

    #[tokio::test]
    async fn events_are_written_as_compact_lines_in_order() {
        let (rx_side, tx_side) = tokio::io::duplex(4096);
        let (_writer, sink) = EventWriter::spawn(tx_side);
        sink.emit(Event::log(
            LogLevel::Warn,
            "bridge socket refused the connection",
        ))
        .await;
        sink.emit(Event::error(ErrorCode::Internal, "boom")).await;
        assert!(sink.flush(Duration::from_secs(5)).await);
        drop(sink);
        drop(_writer);
        let mut out = String::new();
        let mut rx_side = rx_side;
        rx_side.read_to_string(&mut out).await.unwrap();
        assert_eq!(
            out,
            "{\"event\":\"log\",\"level\":\"warn\",\"message\":\"bridge socket refused the connection\"}\n\
             {\"event\":\"error\",\"code\":\"internal\",\"message\":\"boom\"}\n"
        );
    }
}
