//! Dump the login sites in the vault — names and URLs only, no passwords.
//!
//! A debugging/planning tool for the in-core login recipes: it lists every
//! login item's site and every passkey the vault holds, so a human can see
//! which sites are covered (passkey) and which are candidates for a recipe.
//!
//! Run with the master password in the environment (never on the command
//! line):
//!
//! ```text
//! VELA_MASTER_PASSWORD='...' cargo run --example list_sites
//! ```
//!
//! The vault's login items are printed as `LOGIN<TAB>name<TAB>url` and its
//! passkeys as `PASSKEY<TAB>rp_id`. Nothing secret is printed; the master
//! password is read from the environment and never echoed.

fn main() {
    let password = std::env::var("VELA_MASTER_PASSWORD")
        .expect("VELA_MASTER_PASSWORD is not set; refusing to run without it");

    let rms = vela_desktop_core::biometric::authenticate_with_password(&password)
        .expect("the master password did not unlock the vault");
    let crypto = vela_desktop_core::crypto::Crypto::new(&rms);
    let store = vela_desktop_core::store::Store::new().expect("could not open the store");
    let vault = store.load_vault(&crypto).expect("could not load the vault");

    let mut logins = 0usize;
    let mut passkeys = 0usize;
    for item in &vault.items {
        match item {
            vela_desktop_core::vault::VaultItem::Login { .. } => {
                let name = item.name();
                let url = item.url().unwrap_or_default();
                println!("LOGIN\t{name}\t{url}");
                logins += 1;
            }
            vela_desktop_core::vault::VaultItem::Passkey { rp_id, .. } => {
                println!("PASSKEY\t{rp_id}");
                passkeys += 1;
            }
            _ => {}
        }
    }
    eprintln!("{logins} login items, {passkeys} passkey items");
}
