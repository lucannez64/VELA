//! VELA Native Messaging Host — process wrapper.
//!
//! Drives the library's protocol loop over stdio. All logic lives in the
//! `vela_nm_host` library crate.

use vela_nm_host::{handle_message, read_browser_message, write_browser_message};

fn main() {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    while let Some(message) = read_browser_message(&mut stdin) {
        let response = handle_message(&message);
        write_browser_message(&mut stdout, &response);
    }
}
