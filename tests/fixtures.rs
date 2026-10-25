//! The vendored contract, byte for byte.
//!
//! Every `protocol/fixtures/*.json` must decode into this crate's types and
//! re-encode to the same bytes, trailing newline included; `PROTOCOL_VERSION`
//! must be the one `PROTOCOL.md` names; the preamble fixture must be this
//! crate's preamble for the fixture peer; and the fixture key must yield the
//! fixture endpoint id.

mod support;

use std::path::{Path, PathBuf};

use fermix_iroh::IROH_VERSION;
use fermix_iroh::bridge::preamble;
use fermix_iroh::protocol::{Event, KIND_PHONE, Op, PROTOCOL_VERSION, decode_op};
use iroh::SecretKey;

const EVENT_FIXTURES: &[&str] = &[
    "hello.json",
    "ready.json",
    "relay.json",
    "path.json",
    "closed.json",
    "refused.json",
    "log.json",
    "error.json",
];

const OP_FIXTURES: &[&str] = &["start.json", "set_relays.json", "shutdown.json"];

const FIXTURE_ENDPOINT_ID: &str =
    "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

fn protocol_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = protocol_dir().join("fixtures").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn one_line(name: &str, bytes: &[u8]) -> String {
    assert_eq!(
        bytes.last(),
        Some(&b'\n'),
        "{name} must end with one newline"
    );
    let text = std::str::from_utf8(&bytes[..bytes.len() - 1]).expect("fixtures are UTF-8");
    assert!(!text.contains('\n'), "{name} must be one line");
    text.to_string()
}

#[test]
fn every_event_fixture_round_trips_to_the_same_bytes() {
    for name in EVENT_FIXTURES {
        let bytes = fixture(name);
        let event: Event = serde_json::from_str(&one_line(name, &bytes))
            .unwrap_or_else(|e| panic!("{name} does not decode: {e}"));
        let again = event.to_line().expect("encodes");
        assert_eq!(
            String::from_utf8_lossy(&again),
            String::from_utf8_lossy(&bytes),
            "{name}"
        );
    }
}

#[test]
fn every_op_fixture_decodes_through_the_production_path_and_round_trips() {
    for name in OP_FIXTURES {
        let bytes = fixture(name);
        let op = decode_op(&one_line(name, &bytes))
            .unwrap_or_else(|e| panic!("{name} does not decode: {e}"));
        let mut again = serde_json::to_vec(&op).expect("encodes");
        again.push(b'\n');
        assert_eq!(
            String::from_utf8_lossy(&again),
            String::from_utf8_lossy(&bytes),
            "{name}"
        );
    }
}

#[test]
fn the_start_fixture_validates() {
    let line = one_line("start.json", &fixture("start.json"));
    let Op::Start {
        secret_key_path,
        bridge_socket,
        alpn,
        relays,
        limits,
    } = decode_op(&line).unwrap()
    else {
        panic!("start.json is not a start");
    };
    let cfg = fermix_iroh::protocol::StartConfig::validate(
        &secret_key_path,
        &bridge_socket,
        &alpn,
        &relays,
        &limits,
    )
    .expect("the contract's own start is valid");
    assert_eq!(cfg.kind, KIND_PHONE);
    assert_eq!(cfg.relays.len(), 2);
}

#[test]
fn no_fixture_is_left_untested() {
    let mut listed: Vec<&str> = EVENT_FIXTURES.iter().chain(OP_FIXTURES).copied().collect();
    listed.push("bridge_preamble.bin");
    listed.sort_unstable();
    let mut on_disk: Vec<String> = std::fs::read_dir(protocol_dir().join("fixtures"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort_unstable();
    assert_eq!(on_disk, listed);
}

#[test]
fn this_build_says_hello_as_the_fixture_does() {
    // The fixture's wire and iroh versions are this build's; a release that
    // moves either must re-vendor the daemon's export in the same change. Its
    // helper_version is the daemon's example, so this build's own goes there.
    let line = one_line("hello.json", &fixture("hello.json"));
    let Event::Hello {
        protocol_version,
        iroh_version,
        ..
    } = serde_json::from_str(&line).unwrap()
    else {
        panic!("hello.json is not a hello");
    };
    assert_eq!(protocol_version, PROTOCOL_VERSION);
    assert_eq!(iroh_version, IROH_VERSION);
    let hello = Event::hello().to_line().unwrap();
    assert_eq!(
        String::from_utf8(hello).unwrap(),
        support::hello_fixture_for_this_build()
    );
}

#[test]
fn protocol_version_matches_protocol_md() {
    let doc = std::fs::read_to_string(protocol_dir().join("PROTOCOL.md")).unwrap();
    let marker = "`protocol_version`, currently **";
    let at = doc
        .find(marker)
        .expect("PROTOCOL.md names the current version")
        + marker.len();
    let digits: String = doc[at..].chars().take_while(char::is_ascii_digit).collect();
    assert_eq!(digits.parse::<u32>().unwrap(), PROTOCOL_VERSION);
}

#[test]
fn iroh_version_matches_the_locked_iroh() {
    let lock = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .expect("Cargo.lock is committed");
    let entry = "[[package]]\nname = \"iroh\"\nversion = \"";
    let at = lock.find(entry).expect("Cargo.lock resolves iroh") + entry.len();
    let version: String = lock[at..].chars().take_while(|c| *c != '"').collect();
    assert_eq!(version, IROH_VERSION);
}

fn fixture_key() -> SecretKey {
    let bytes: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
    SecretKey::from_bytes(&bytes)
}

#[test]
fn the_fixture_key_yields_the_fixture_endpoint_id() {
    let id = fixture_key().public();
    assert_eq!(id.to_string(), FIXTURE_ENDPOINT_ID);
    let ready = fixture("ready.json");
    assert!(String::from_utf8_lossy(&ready).contains(FIXTURE_ENDPOINT_ID));
}

#[test]
fn the_preamble_fixture_is_this_crates_preamble_for_the_fixture_peer() {
    let id = fixture_key().public();
    let ours = preamble(KIND_PHONE, id.as_bytes());
    assert_eq!(ours.as_slice(), fixture("bridge_preamble.bin").as_slice());
}
