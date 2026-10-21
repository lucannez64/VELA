//! Facts derived from the unlocked vault for the overview and list:
//! strength, reuse, age, two-factor and favourites. Everything shown in the
//! instrument UI comes from here — there are no illustrative numbers.
//!
//! Strength uses the core's own `calculate_password_strength`, and "weak"
//! means weak or fair, the same rule `get_vault_health` applies, so the two
//! UIs agree.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use vela_desktop_core::commands::vault::calculate_password_strength;
use vela_desktop_core::vault::{ItemType, VaultItem};

pub const OLD_AFTER_DAYS: i64 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Login,
    Card,
    Note,
    Identity,
    Passkey,
}

impl Kind {
    pub fn of(item: &VaultItem) -> Option<Kind> {
        Some(match item.item_type() {
            ItemType::Login => Kind::Login,
            ItemType::CreditCard => Kind::Card,
            ItemType::SecureNote => Kind::Note,
            ItemType::Identity => Kind::Identity,
            ItemType::Passkey => Kind::Passkey,
            // Breach-monitor entries and file blobs are not browsable items.
            ItemType::BreachMonitor | ItemType::FileBlob => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Login => "Login",
            Kind::Card => "Card",
            Kind::Note => "Note",
            Kind::Identity => "Identity",
            Kind::Passkey => "Passkey",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Facts {
    /// Index into the item list this was built from.
    pub index: usize,
    pub kind: Kind,
    /// 0 (very weak) ..= 4 (strong); `None` for items without a password.
    pub strength: Option<u8>,
    pub weak: bool,
    /// How many *other* logins share this password.
    pub reused_with: usize,
    pub age_days: i64,
    pub old: bool,
    pub has_totp: bool,
    pub favorite: bool,
}

impl Facts {
    pub fn at_risk(&self) -> bool {
        self.kind == Kind::Login && (self.weak || self.reused_with > 0 || self.old)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub facts: Vec<Facts>,
    pub logins: usize,
    pub at_risk: usize,
    pub weak: Vec<usize>,
    pub reused: Vec<usize>,
    pub old: Vec<usize>,
    pub totp: usize,
    pub passkeys: usize,
    pub favorites: Vec<usize>,
    /// Logins per age bucket: <1 month, 1–3, 3–6, 6–12 months, 1–2 years, 2+.
    pub age_buckets: [usize; 6],
    /// Healthy logins ÷ logins, 0..=100.
    pub score: u32,
}

pub const AGE_LABELS: [&str; 6] = ["<1M", "1-3M", "3-6M", "6-12M", "1-2Y", "2Y+"];

fn bucket(days: i64) -> usize {
    match days {
        d if d < 30 => 0,
        d if d < 90 => 1,
        d if d < 180 => 2,
        d if d < 365 => 3,
        d if d < 730 => 4,
        _ => 5,
    }
}

pub fn strength_level(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }
    match calculate_password_strength(password).score.as_str() {
        "weak" => 1,
        "fair" => 2,
        "good" => 3,
        _ => 4,
    }
}

pub fn analyze(items: &[VaultItem], now: DateTime<Utc>) -> Analysis {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for item in items {
        if item.item_type() == ItemType::Login {
            if let Some(pw) = item.password().filter(|p| !p.is_empty()) {
                *counts.entry(pw).or_default() += 1;
            }
        }
    }

    let mut a = Analysis::default();
    for (index, item) in items.iter().enumerate() {
        let Some(kind) = Kind::of(item) else { continue };
        let age_days = (now - item.updated_at()).num_days().max(0);
        let password = item.password().unwrap_or_default();
        let is_login = kind == Kind::Login;
        let strength = (is_login && !password.is_empty()).then(|| strength_level(password));
        let weak = strength.is_some_and(|s| s <= 2);
        let reused_with = if is_login && !password.is_empty() {
            counts.get(password).copied().unwrap_or(1) - 1
        } else {
            0
        };
        let has_totp = matches!(item, VaultItem::Login { totp: Some(s), .. } if !s.trim().is_empty());
        let facts = Facts {
            index,
            kind,
            strength,
            weak,
            reused_with,
            age_days,
            old: is_login && age_days > OLD_AFTER_DAYS,
            has_totp,
            favorite: item.favorite(),
        };
        let slot = a.facts.len();
        if is_login {
            a.logins += 1;
            a.age_buckets[bucket(age_days)] += 1;
            if facts.weak {
                a.weak.push(slot);
            }
            if facts.reused_with > 0 {
                a.reused.push(slot);
            }
            if facts.old {
                a.old.push(slot);
            }
            if facts.at_risk() {
                a.at_risk += 1;
            }
        }
        if has_totp {
            a.totp += 1;
        }
        if kind == Kind::Passkey {
            a.passkeys += 1;
        }
        if facts.favorite {
            a.favorites.push(slot);
        }
        a.facts.push(facts);
    }
    a.score = if a.logins == 0 {
        100
    } else {
        (((a.logins - a.at_risk) as f32 / a.logins as f32) * 100.).round() as u32
    };
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(name: &str, pw: &str, days_old: i64, fav: bool) -> VaultItem {
        let at = (Utc::now() - chrono::Duration::days(days_old)).to_rfc3339();
        serde_json::from_value(serde_json::json!({
            "item_type": "login", "id": name, "name": name, "url": "https://x.test",
            "username": "u", "password": pw, "createdAt": at, "updatedAt": at, "favorite": fav,
        }))
        .unwrap()
    }

    #[test]
    fn counts_reuse_weak_old_and_score() {
        let items = vec![
            login("a", "Sunflower92!", 10, false),
            login("b", "Sunflower92!", 10, true),
            login("c", "x7#Lq9!vR2@pM4^z", 10, false),
            login("d", "k3$Tz8&Wq1*Ln6%y", 800, false),
        ];
        let a = analyze(&items, Utc::now());
        assert_eq!(a.logins, 4);
        assert_eq!(a.reused.len(), 2);
        assert_eq!(a.old.len(), 1);
        assert_eq!(a.at_risk, 3);
        assert_eq!(a.score, 25);
        assert_eq!(a.favorites.len(), 1);
        assert_eq!(a.age_buckets[0], 3);
        assert_eq!(a.age_buckets[5], 1);
        assert_eq!(a.facts[0].reused_with, 1);
    }

    #[test]
    fn empty_vault_is_healthy() {
        assert_eq!(analyze(&[], Utc::now()).score, 100);
    }

    #[test]
    fn demo_vault_analyses_without_panicking() {
        let demo = crate::demo::DemoVault::new().unwrap();
        let items = demo.state.vault.read().items.clone();
        let a = analyze(&items, Utc::now());
        assert!(a.logins > 0);
        assert!(a.facts.len() <= items.len());
    }
}
