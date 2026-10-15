//! Property tests for the control channel's framing and op decoder: arbitrary
//! input never panics, never yields a line over the ceiling, and an over-long
//! line is refused.

use fermix_iroh::ndjson::{LineError, LineReader};
use fermix_iroh::protocol::{MAX_LINE_BYTES, Op, decode_op};
use proptest::prelude::*;
use tokio::io::BufReader;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
}

/// Read every line of `input` with a `max`-byte ceiling through a `capacity`
/// byte buffer, decoding each one, until the end or the first framing error.
fn drive(input: &[u8], max: usize, capacity: usize) -> (Vec<String>, Option<LineError>) {
    runtime().block_on(async {
        let mut reader = LineReader::with_max_bytes(BufReader::with_capacity(capacity, input), max);
        let mut lines = Vec::new();
        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    // Any outcome is fine; it must not panic.
                    let _ = decode_op(&line);
                    lines.push(line);
                }
                Ok(None) => return (lines, None),
                Err(e) => return (lines, Some(e)),
            }
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic_and_never_exceed_the_ceiling(
        input in proptest::collection::vec(any::<u8>(), 0..4096),
        max in 1usize..256,
        capacity in 1usize..64,
    ) {
        let (lines, _) = drive(&input, max, capacity);
        for line in &lines {
            prop_assert!(line.len() <= max);
            prop_assert!(!line.contains('\n'));
        }
    }

    #[test]
    fn a_line_over_the_ceiling_is_refused(
        prefix_lines in proptest::collection::vec("[a-z{}\":,]{0,40}", 0..4),
        extra in 1usize..2048,
        capacity in 1usize..9000,
    ) {
        let mut input = String::new();
        for line in &prefix_lines {
            input.push_str(line);
            input.push('\n');
        }
        input.push_str(&"x".repeat(MAX_LINE_BYTES + extra));
        input.push('\n');
        let (lines, err) = drive(input.as_bytes(), MAX_LINE_BYTES, capacity);
        prop_assert_eq!(lines, prefix_lines);
        prop_assert!(matches!(err, Some(LineError::Oversize)));
    }

    #[test]
    fn arbitrary_text_never_panics_the_decoder(line in ".{0,512}") {
        let _ = decode_op(&line);
    }

    #[test]
    fn json_shaped_noise_never_panics_the_decoder(
        op in prop_oneof![
            Just("start"), Just("set_relays"), Just("shutdown"), Just("hello"), Just("")
        ],
        key in "[a-z_]{0,24}",
        value in prop_oneof![
            Just("null".to_string()),
            Just("[]".to_string()),
            Just("{}".to_string()),
            any::<i64>().prop_map(|n| n.to_string()),
            any::<f64>().prop_map(|f| format!("{f:?}")),
            "[a-z/:.]{0,30}".prop_map(|s| format!("\"{s}\"")),
        ],
    ) {
        let line = format!("{{\"op\":\"{op}\",\"{key}\":{value}}}");
        if let Ok(Op::Shutdown {}) = decode_op(&line) {
            prop_assert!(false, "a shutdown with an extra field must be refused: {}", line);
        }
    }
}
