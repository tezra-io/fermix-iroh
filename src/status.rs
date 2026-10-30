//! Relay and path status, turned into `relay` and `path` events.
//!
//! Text that comes from iroh (a relay's error) is relay-influenced: the daemon
//! logs it and never matches on it. It is reduced to its first line, stripped of
//! any `user:password@` in URLs, and capped at 512 bytes before it leaves.

use futures_util::StreamExt;
use iroh::endpoint::{PathId, PathList, RelayStatus};
use iroh::{Endpoint, EndpointId, TransportAddr, Watcher};
use tokio_util::sync::CancellationToken;

use crate::ndjson::EventSink;
use crate::protocol::{Event, PathKind, cap_text};

/// Reduce error text to what may leave the helper: its first line, with URL
/// credentials removed, capped at 512 bytes.
pub fn sanitize_error_text(text: &str) -> String {
    let first = text.lines().next().unwrap_or("");
    cap_text(&strip_url_credentials(first))
}

/// Remove the `user[:password]@` part of every `scheme://` authority in `text`.
pub fn strip_url_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let end = tail.find(ends_authority).unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(cut) => out.push_str(&authority[cut + 1..]),
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn ends_authority(c: char) -> bool {
    matches!(
        c,
        '/' | '?' | '#' | '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ','
    ) || c.is_whitespace()
}

/// One home relay as the `relay` event needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRelay {
    /// The relay URL.
    pub url: String,
    /// Whether the endpoint is connected to it.
    pub connected: bool,
    /// iroh's most recent error for it, unsanitized.
    pub error: Option<String>,
}

impl From<&RelayStatus> for HomeRelay {
    fn from(status: &RelayStatus) -> Self {
        HomeRelay {
            url: status.url().to_string(),
            connected: status.is_connected(),
            error: status.last_error().map(|e| e.to_string()),
        }
    }
}

/// The home relay the `relay` event names: the connected entry, else the first.
pub fn choose_home(homes: &[HomeRelay]) -> Option<&HomeRelay> {
    homes.iter().find(|h| h.connected).or_else(|| homes.first())
}

/// The `relay` event for iroh's list of home relays.
pub fn relay_event(homes: &[HomeRelay]) -> Event {
    match choose_home(homes) {
        Some(home) => Event::Relay {
            home_relay: Some(home.url.clone()),
            connected: home.connected,
            error: home.error.as_deref().map(sanitize_error_text),
        },
        None => Event::Relay {
            home_relay: None,
            connected: false,
            error: None,
        },
    }
}

/// What a `relay` event reports a change of: the home relay and whether it is
/// connected. A new error text alone is not a change.
fn relay_key(homes: &[HomeRelay]) -> Option<(String, bool)> {
    choose_home(homes).map(|h| (h.url.clone(), h.connected))
}

/// Emit `relay` events until `stop` fires: once at start, then whenever the
/// home relay or its connected state changes.
pub async fn watch_relays(endpoint: Endpoint, sink: EventSink, stop: CancellationToken) {
    let mut statuses = endpoint.home_relay_status().stream();
    let mut last: Option<Option<(String, bool)>> = None;
    loop {
        let next = tokio::select! {
            _ = stop.cancelled() => return,
            next = statuses.next() => next,
        };
        let Some(list) = next else { return };
        let homes: Vec<HomeRelay> = list.iter().map(HomeRelay::from).collect();
        let key = relay_key(&homes);
        if last.as_ref() != Some(&key) {
            last = Some(key);
            sink.emit(relay_event(&homes)).await;
        }
    }
}

/// A path's kind and its relay URL (`None` for a direct path), or `None` for a
/// transport that is neither a relay nor IP (none is configured in this helper).
pub fn path_kind(remote: &TransportAddr) -> Option<(PathKind, Option<String>)> {
    match remote {
        TransportAddr::Relay(url) => Some((PathKind::Relay, Some(url.to_string()))),
        TransportAddr::Ip(_) => Some((PathKind::Direct, None)),
        _ => None,
    }
}

/// The kind and relay of a connection's selected path, if it has one.
pub fn selected_path(paths: &PathList<'_>) -> Option<(PathKind, Option<String>)> {
    let selected = paths.iter().find(|p| p.is_selected())?;
    path_kind(selected.remote_addr())
}

/// The `path` event for a selected path, or `None` for a transport that is
/// neither a relay nor IP (none is configured in this helper).
pub fn path_event(peer: &EndpointId, remote: &TransportAddr) -> Option<Event> {
    let (kind, relay) = path_kind(remote)?;
    Some(Event::Path {
        endpoint_id: peer.to_string(),
        kind,
        relay,
    })
}

/// Tracks one connection's selected path: reports each change once, and the
/// connection's end once if any path was reported.
pub struct PathTracker {
    peer: EndpointId,
    selected: Option<PathId>,
    reported: bool,
}

impl PathTracker {
    /// A tracker for the connection to `peer`.
    pub fn new(peer: EndpointId) -> Self {
        PathTracker {
            peer,
            selected: None,
            reported: false,
        }
    }

    /// The `closed` event for the connection's end, if it had a `path`; `None`
    /// otherwise. Consumes the tracker, so it is sent at most once and nothing
    /// follows it.
    pub fn closed(self) -> Option<Event> {
        self.reported.then(|| Event::Closed {
            endpoint_id: self.peer.to_string(),
        })
    }

    /// The event to send for a snapshot of the connection's paths, if its
    /// selected path changed since the last snapshot.
    pub fn observe(&mut self, paths: &PathList<'_>) -> Option<Event> {
        let selected = paths.iter().find(|p| p.is_selected())?;
        if self.selected == Some(selected.id()) {
            return None;
        }
        self.selected = Some(selected.id());
        let event = path_event(&self.peer, selected.remote_addr())?;
        self.reported = true;
        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(url: &str, connected: bool, error: Option<&str>) -> HomeRelay {
        HomeRelay {
            url: url.into(),
            connected,
            error: error.map(str::to_string),
        }
    }

    #[test]
    fn no_home_relay_yet_is_null_and_disconnected() {
        let event = relay_event(&[]);
        let line = String::from_utf8(event.to_line().unwrap()).unwrap();
        assert_eq!(
            line,
            "{\"event\":\"relay\",\"home_relay\":null,\"connected\":false}\n"
        );
    }

    #[test]
    fn the_connected_entry_wins_else_the_first() {
        let homes = [
            home("https://eu1.relay.fermix.ai/", false, Some("timed out")),
            home("https://us1.relay.fermix.ai/", true, None),
        ];
        let line = String::from_utf8(relay_event(&homes).to_line().unwrap()).unwrap();
        assert_eq!(line, include_str!("../protocol/fixtures/relay.json"));

        let event = relay_event(&homes[..1]);
        assert_eq!(
            event,
            Event::Relay {
                home_relay: Some("https://eu1.relay.fermix.ai/".into()),
                connected: false,
                error: Some("timed out".into()),
            }
        );
    }

    #[test]
    fn error_text_is_first_line_without_credentials_and_capped() {
        let raw = "connect to https://bob:hunter2@us1.relay.fermix.ai/relay failed\nbacktrace...";
        assert_eq!(
            sanitize_error_text(raw),
            "connect to https://us1.relay.fermix.ai/relay failed"
        );
        let user_only = "wss://token@relay.example:443 refused";
        assert_eq!(
            strip_url_credentials(user_only),
            "wss://relay.example:443 refused"
        );
        let two = "a http://u:p@x/ b https://y/ c ftp://q@z";
        assert_eq!(
            strip_url_credentials(two),
            "a http://x/ b https://y/ c ftp://z"
        );
        let untouched = "no urls here: user@example.com";
        assert_eq!(strip_url_credentials(untouched), untouched);
        let long = format!("https://u:p@h/{}", "x".repeat(2000));
        let clean = sanitize_error_text(&long);
        assert!(clean.len() <= 512);
        assert!(!clean.contains("u:p@"));
    }
}
