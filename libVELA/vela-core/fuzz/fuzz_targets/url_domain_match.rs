//! Fuzz the URL/domain matching path that gates autofill.
//!
//! `search_by_domain` decides which saved login a web page gets offered. The
//! fast host splitter must agree with the `url` crate whenever it takes a
//! URL (the repo's own invariant), public-suffix boundaries must hold
//! (`evil.github.io` must never match `victim.github.io`), and nothing may
//! panic on hostile input.
//!
//! Oracle: a faithful reference model of `DomainQuery::matches`, rebuilt from
//! the same `url` + `psl` crates the implementation delegates to on its slow
//! path. Any fast-path disagreement, port mishandling, or cross-suffix match
//! diverges from the model and fires. When the reference parser cannot parse
//! an input at all, the check is skipped (the impl's last-resort fallback owns
//! those, and there is nothing sound to assert about them).
//!
//! Input: two space-separated tokens — query domain, stored URL.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vela_core::vault::{VaultItem, VaultMeta, VaultStore};

fn tokens(data: &[u8], n: usize) -> Vec<String> {
    String::from_utf8_lossy(data)
        .split_whitespace()
        .take(n)
        .map(|t| t.chars().filter(|c| !c.is_control()).collect())
        .collect()
}

/// What the `url` crate says a URL-ish string's host and port are, mirroring
/// `extract_host_and_port`'s slow path (prepend `https://` for bare hosts).
/// The implementation lowercases BEFORE scheme detection, so the model must
/// too — an uppercase `HTTP://` must not fall into the bare-host branch.
fn ref_host(url: &str) -> Option<(String, Option<u16>)> {
    let lowered = url.to_lowercase();
    let parsed = if lowered.starts_with("http://") || lowered.starts_with("https://") {
        url::Url::parse(&lowered).ok()?
    } else {
        url::Url::parse(&format!("https://{lowered}")).ok()?
    };
    let host = parsed.host_str()?.trim_matches('.').to_lowercase();
    Some((host, parsed.port()))
}

/// Mirror of `DomainQuery::matches` using reference-parsed hosts.
fn expected_match(query: &str, stored: &str) -> bool {
    let Some((q_host, q_port)) = ref_host(query) else { return false };
    let Some((s_host, s_port)) = ref_host(stored) else { return false };

    // Port guard: enforced only when BOTH sides carry an explicit,
    // non-default port (default ports are elided on both sides).
    if let (Some(qp), Some(sp)) = (q_port, s_port) {
        if qp != sp {
            return false;
        }
    }
    if q_host == s_host {
        return true;
    }
    // Either side an IPv4-shaped literal: never a domain relation.
    let is_ip = |h: &str| h.split('.').all(|p| p.parse::<u8>().is_ok());
    if is_ip(&q_host) || is_ip(&s_host) {
        return false;
    }
    let (Some(q_dom), Some(s_dom)) = (psl::domain_str(&q_host), psl::domain_str(&s_host)) else {
        return false;
    };
    if q_dom != s_dom {
        return false;
    }
    // Query host must sit at or below the stored host (dot-boundary safe).
    let (h, sfx) = (&q_host, s_host.as_str());
    match h.len().checked_sub(sfx.len() + 1) {
        Some(dot) => h.as_bytes()[dot] == b'.' && &h[dot + 1..] == sfx,
        None => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let parts = tokens(data, 2);
    if parts.len() < 2 {
        return;
    }
    let (query, stored_url) = (&parts[0], &parts[1]);

    let mut store = VaultStore::new();
    let now = chrono::Utc::now();
    store.add_item(VaultItem::Login {
        meta: VaultMeta {
            id: "1".into(),
            name: "t".into(),
            notes: None,
            created_at: now,
            updated_at: now,
            last_modified_device: None,
            favorite: false,
            shared: false,
            share_recipient: None,
        },
        url: stored_url.clone(),
        username: "u".into(),
        pass: "p".into(),
        totp: None,
        app_ids: Vec::new(),
        credential_change_needs_reauth: None,
        allow_second_factor_downgrade: None,
    });

    let got = !store.search_by_domain(query).is_empty();

    // Only assertable when the reference model could fully parse both sides.
    if ref_host(query).is_some() && ref_host(stored_url).is_some() {
        let want = expected_match(query, stored_url);
        assert_eq!(
            got, want,
            "autofill match disagreed with reference model: query={query:?} stored={stored_url:?} got={got} want={want}"
        );
    }
});
