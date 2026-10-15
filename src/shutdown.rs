//! Graceful shutdown, bounded so the helper exits within the contract's 5 s.
//!
//! 1. Stop accepting, and tell every connection task to close its connection
//!    with application code 0, reason `shutdown` (iroh's `Endpoint::close`
//!    alone would send an empty reason), and every bridge to end; a bridge
//!    connection closes when its task ends.
//! 2. Wait for those tasks, at most [`TASK_DRAIN`].
//! 3. Close the endpoint and wait for iroh's drain, at most [`ENDPOINT_DRAIN`].
//!
//! The whole sequence is held to [`SHUTDOWN_DEADLINE`], and the final event
//! flush to [`FLUSH_DEADLINE`]: together under 5 s.

use std::time::Duration;

use iroh::Endpoint;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::ndjson::EventSink;
use crate::protocol::{Event, LogLevel};

/// How long connection and bridge tasks get to end after the stop signal.
pub const TASK_DRAIN: Duration = Duration::from_millis(1000);

/// How long iroh's own drain may take.
pub const ENDPOINT_DRAIN: Duration = Duration::from_millis(3000);

/// The bound on the whole graceful sequence.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_millis(4300);

/// How long the last events may take to reach stdout.
pub const FLUSH_DEADLINE: Duration = Duration::from_millis(400);

/// Run the graceful shutdown sequence, bounded by [`SHUTDOWN_DEADLINE`].
pub async fn graceful(
    endpoint: Endpoint,
    stop: CancellationToken,
    tasks: TaskTracker,
    sink: &EventSink,
) {
    let sequence = drain(&endpoint, &stop, &tasks, sink);
    if tokio::time::timeout(SHUTDOWN_DEADLINE, sequence)
        .await
        .is_err()
    {
        // Only reachable if stdout stalls a warning; exit regardless.
        eprintln!(
            "fermix-iroh: shutdown passed {}ms; exiting",
            SHUTDOWN_DEADLINE.as_millis()
        );
    }
}

async fn drain(
    endpoint: &Endpoint,
    stop: &CancellationToken,
    tasks: &TaskTracker,
    sink: &EventSink,
) {
    stop.cancel();
    tasks.close();
    if tokio::time::timeout(TASK_DRAIN, tasks.wait())
        .await
        .is_err()
    {
        let message = format!(
            "shutdown: {} connection or stream tasks still running after {}ms",
            tasks.len(),
            TASK_DRAIN.as_millis()
        );
        sink.emit(Event::log(LogLevel::Warn, &message)).await;
    }
    if tokio::time::timeout(ENDPOINT_DRAIN, endpoint.close())
        .await
        .is_err()
    {
        let message = format!(
            "shutdown: iroh's drain did not finish within {}ms",
            ENDPOINT_DRAIN.as_millis()
        );
        sink.emit(Event::log(LogLevel::Warn, &message)).await;
    }
}
