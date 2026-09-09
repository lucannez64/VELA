//! `vela` — the VELA command line.
//!
//! Two jobs, both thin over `vela-desktop-core`:
//!
//! 1. Vault access à la `bw`: unlock with the master password (the same
//!    Argon2id blob the desktop app verifies against), then list and read
//!    items. The session key printed by `vela unlock` is the vault's own
//!    key material, exactly like Bitwarden's — treat it accordingly.
//! 2. An SSH agent à la 1Password: `vela ssh-agent` serves the SSH agent
//!    protocol (ed25519 keys stored as secure notes) over a Unix socket or
//!    a Windows named pipe, so `ssh`/`git` sign with keys that never leave
//!    the vault.

mod items;
mod session;
mod ssh;

use std::collections::{HashMap, HashSet};

/// Parsed command line: subcommand path (`get password`), `--opt value`
/// options, and bare `--flag` switches.
pub struct Cli {
    pub command: Vec<String>,
    pub options: HashMap<String, String>,
    pub flags: HashSet<String>,
}

impl Cli {
    pub fn opt(&self, name: &str) -> Option<&str> {
        self.options.get(name).map(|s| s.as_str())
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

fn parse_args(args: Vec<String>) -> Cli {
    let mut command = Vec::new();
    let mut options = HashMap::new();
    let mut flags = HashSet::new();
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(stripped) = arg.strip_prefix("--") {
            if let Some((k, v)) = stripped.split_once('=') {
                options.insert(k.to_string(), v.to_string());
            } else if iter.peek().map(|n| !n.starts_with("--")).unwrap_or(false) {
                // Consume the next token as the option's value; a lone flag
                // with no value stays a flag.
                let value = iter.next().unwrap();
                options.insert(stripped.to_string(), value);
            } else {
                flags.insert(stripped.to_string());
            }
        } else {
            command.push(arg);
        }
    }
    Cli {
        command,
        options,
        flags,
    }
}

const HELP: &str = r#"vela — the VELA command line

Vault access:
  vela unlock                    Prompt for the master password; print a session key
  vela status                    Show vault location and whether a session key is set
  vela list items [--json]       List items (id, name, username, url)
  vela get item <id|name>        Print one item as JSON (includes secrets)
  vela get password <id|name>    Print one field: item | password | username | url | notes | totp
  vela generate [--length N] [--no-symbols] [--no-numbers]
                 [--no-uppercase] [--no-lowercase]

SSH agent (keys stored as secure notes holding an OpenSSH ed25519 key):
  vela ssh list                  Fingerprint the agent-visible keys
  vela ssh-agent [--socket P]    Serve the agent protocol until interrupted
                                 (Windows default pipe: \\.\pipe\vela-ssh-agent;
                                 pass --pipe to take the standard OpenSSH pipe name)

Global options:
  --session KEY                  Session key from `vela unlock` (or set VELA_SESSION)
  --store DIR                    Use a vault store in DIR instead of the platform default
"#;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_args(args);

    let result = match cli.command.first().map(|s| s.as_str()) {
        None => {
            println!("{HELP}");
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{HELP}");
            Ok(())
        }
        Some("version") | Some("--version") => {
            println!("vela-cli 0.1.0");
            Ok(())
        }
        Some("unlock") => session::unlock_and_print(),
        Some("status") => items::status(&cli),
        Some("list") => match cli.command.get(1).map(|s| s.as_str()) {
            Some("items") => items::list(&cli),
            _ => Err("usage: vela list items [--json]".to_string()),
        },
        Some("get") => match (cli.command.get(1), cli.command.get(2)) {
            (Some(field), Some(query)) => items::get(&cli, field, query),
            _ => {
                Err("usage: vela get <item|password|username|url|notes|totp> <id|name>".to_string())
            }
        },
        Some("generate") => items::generate(&cli),
        Some("ssh") => match cli.command.get(1).map(|s| s.as_str()) {
            Some("list") => ssh::list(&cli),
            _ => Err("usage: vela ssh list".to_string()),
        },
        Some("ssh-agent") => ssh::run_agent(&cli),
        Some(other) => Err(format!(
            "Unknown command: {other}\nRun `vela help` for the command list."
        )),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
