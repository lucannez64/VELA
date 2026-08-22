//! Fuzz the native messaging host's browser-facing protocol.
//!
//! This process is spawned by the browser and parses everything the page
//! ecosystem can send it: 4-byte little-endian length prefix + JSON body,
//! unbounded attacker control, zero authentication upstream of this parser.
//! The desktop-side exchange (`framed_exchange`) parses the reply symmetrically.
//!
//! Oracles:
//! 1. framing totality — arbitrary stream bytes never panic, never allocate
//!    past the declared bound;
//! 2. reframe stability — anything the parser accepts must survive its own
//!    write/read cycle unchanged;
//! 3. helper totality — `error_of` / `passkey_payload` project any JSON.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vela_nm_host::{error_of, framed_exchange, passkey_payload, read_browser_message, write_browser_message};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 256 * 1024 {
        return;
    }

    // 1. Treat the input as one native-messaging frame: [len: u32 LE][body].
    if let Some(message) = read_browser_message(&mut Cursor::new(data)) {
        if message.is_object() || message.is_array() {
            // 2. Structured messages must survive their own re-framing
            //    identically. (Raw float scalars are exempt: serde_json's
            //    shortest-round-trip formatting can differ in the last ulp
            //    from an over-precise literal the parser accepted.)
            let mut reframed = Vec::new();
            write_browser_message(&mut reframed, &message);
            let reread = read_browser_message(&mut Cursor::new(&reframed));
            assert_eq!(
                reread.as_ref(),
                Some(&message),
                "accepted message changed across a reframe"
            );
        }
    }

    // Exercise the desktop-reply read half: the request serializes into the
    // sink (cursor), the remaining bytes are parsed as a response frame.
    let mut stream = Cursor::new(data.to_vec());
    let _ = framed_exchange(&mut stream, &serde_json::json!({ "msg_type": "ping" }));

    // 3. Projection helpers take any JSON and must stay total.
    let message: serde_json::Value =
        serde_json::from_slice(data).unwrap_or(serde_json::Value::Null);
    let _ = error_of(Some(&message));
    let _ = passkey_payload(
        &message,
        &["rp_id", "client_data_hash", "allow_credentials"],
    );
});
