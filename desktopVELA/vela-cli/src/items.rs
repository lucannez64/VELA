//! Item commands: status, list, get, generate.

use vela_desktop_core::vault::{VaultItem, VaultStore};

use crate::session::{open_store, open_vault};
use crate::Cli;

/// Match an item by vault id, exact name (case-insensitive), or a unique
/// name substring — the ways a human refers to an item in a script.
pub fn find_item<'a>(vault: &'a VaultStore, query: &str) -> Result<&'a VaultItem, String> {
    let items = &vault.items;

    if let Some(item) = items.iter().find(|i| i.id() == query) {
        return Ok(item);
    }
    if let Some(item) = items.iter().find(|i| i.name().eq_ignore_ascii_case(query)) {
        return Ok(item);
    }
    let needle = query.to_lowercase();
    let matches: Vec<&VaultItem> = items
        .iter()
        .filter(|i| i.name().to_lowercase().contains(&needle))
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!("No item matches `{query}`")),
        n => Err(format!(
            "`{query}` matches {n} items; use the id or a more specific name"
        )),
    }
}

pub fn status(cli: &Cli) -> Result<(), String> {
    let store = open_store(cli)?;
    println!("Store:   {}", store.store_path().display());
    println!(
        "Vault:   {}",
        if store.has_existing_vault() {
            "present"
        } else {
            "not created yet"
        }
    );
    match open_vault(cli) {
        Ok(_) => println!("Session: unlocked (key accepted)"),
        Err(_) => println!("Session: locked"),
    }
    Ok(())
}

pub fn list(cli: &Cli) -> Result<(), String> {
    let vault = open_vault(cli)?;
    let mut items: Vec<&VaultItem> = vault.vault.items.iter().collect();
    items.sort_by(|a, b| a.name().to_lowercase().cmp(&b.name().to_lowercase()));

    if cli.flag("json") {
        let rows: Vec<serde_json::Value> = items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "id": item.id(),
                    "name": item.name(),
                    "type": format!("{:?}", item.item_type()).to_lowercase(),
                    "username": item.username().unwrap_or(""),
                    "url": item.url().unwrap_or(""),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!(
        "{:<38}  {:<10}  {:<26}  {}",
        "ID", "TYPE", "NAME", "USERNAME"
    );
    for item in items {
        println!(
            "{:<38}  {:<10}  {:<26}  {}",
            item.id(),
            format!("{:?}", item.item_type()).to_lowercase(),
            truncate(item.name(), 26),
            item.username().unwrap_or(""),
        );
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}

fn print_item_field(item: &VaultItem, field: &str) -> Result<(), String> {
    match field {
        "item" => println!(
            "{}",
            serde_json::to_string_pretty(item).map_err(|e| e.to_string())?
        ),
        "name" => println!("{}", item.name()),
        "username" => println!("{}", item.username().unwrap_or("")),
        "url" => println!("{}", item.url().unwrap_or("")),
        "notes" => println!("{}", item.notes().unwrap_or("")),
        "password" => println!("{}", item.password().ok_or("This item has no password")?),
        "totp" => {
            let secret = match item {
                VaultItem::Login {
                    totp: Some(secret), ..
                } => secret.clone(),
                _ => return Err("This item has no TOTP secret".to_string()),
            };
            let code = vela_desktop_core::totp::generate_totp_code(&secret)
                .ok_or("The TOTP secret is malformed")?;
            println!("{code}");
        }
        other => {
            return Err(format!(
                "Unknown field `{other}` — expected item | password | username | url | notes | totp | name"
            ));
        }
    }
    Ok(())
}

pub fn get(cli: &Cli, field: &str, query: &str) -> Result<(), String> {
    let vault = open_vault(cli)?;
    let item = find_item(&vault.vault, query)?;
    print_item_field(item, field)
}

pub fn generate(cli: &Cli) -> Result<(), String> {
    let options = vela_desktop_core::vault::PasswordGeneratorOptions {
        length: cli.opt("length").and_then(|v| v.parse().ok()).unwrap_or(20),
        uppercase: !cli.flag("no-uppercase"),
        lowercase: !cli.flag("no-lowercase"),
        numbers: !cli.flag("no-numbers"),
        symbols: !cli.flag("no-symbols"),
        easy_to_type: cli.flag("easy-to-type"),
        pronounceable: cli.flag("pronounceable"),
    };
    let generated = vela_desktop_core::commands::vault::generate_password(options)?;
    println!("{}", generated.password);
    Ok(())
}
