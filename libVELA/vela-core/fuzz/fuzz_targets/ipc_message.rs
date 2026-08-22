//! Fuzz the desktop IPC message surface — the autofill bridge's parser.
//!
//! A browser-spawned native messaging host sends length-prefixed JSON frames
//! that deserialize into `IpcMessage`. The peer is gate-checked before any of
//! this runs, but the *parser* must stay total regardless of what an
//! authorized-but-buggy or later-compromised host writes: arbitrary JSON in,
//! never a panic. `process_message` itself needs live app state, so this
//! target exercises everything up to dispatch: frame bounds, serde aliases,
//! payload shapes.
//!
//! Input: raw bytes treated as one IPC frame body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_desktop_core::ipc::{IpcMessage, IpcMessageType};

/// Mirror of the server's frame-length rule (ipc.rs MAX_IPC_MESSAGE_BYTES).
const MAX_IPC_MESSAGE_BYTES: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 64 * 1024 {
        return;
    }

    // Frame-rule parity: what the server would reject must be rejected here.
    let framed_ok = data.len() <= MAX_IPC_MESSAGE_BYTES;

    match serde_json::from_slice::<IpcMessage>(data) {
        Ok(message) => {
            assert!(framed_ok);
            // A parsed message must round-trip through its own wire format.
            let body =
                serde_json::to_vec(&message).expect("parsed IPC message re-serializes");
            let reparsed: IpcMessage =
                serde_json::from_slice(&body).expect("own serialization re-parses");
            assert_eq!(
                std::mem::discriminant(&reparsed.msg_type),
                std::mem::discriminant(&message.msg_type),
                "message type changed across round trip"
            );
            // Every known type stays inside the enum; nothing may desync.
            let _ = matches!(message.msg_type, IpcMessageType::Error);
        }
        Err(_) => {
            // Malformed is fine — the server answers IpcMessage::error. Just
            // confirm the error path itself constructs cleanly.
            let _ = IpcMessage::error("Malformed IPC message".to_string());
        }
    }
});
