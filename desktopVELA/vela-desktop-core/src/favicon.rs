//! Favicon fetching for login items — moved verbatim (minus the
//! `#[tauri::command]` wrapper) from `src-tauri/src/commands/vault.rs`.
//! Pure network/HTML-parsing logic, no `AppState` dependency, same trust
//! level as any other read-only network call this app already makes.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use once_cell::sync::Lazy;
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

fn normalize_login_domain(url: &str) -> Option<String> {
    let normalized = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    let parsed = url::Url::parse(&normalized).ok()?;
    let host = parsed.host_str()?.trim().to_lowercase();
    // `host_str` keeps the brackets on IPv6 literals ("[::1]") — strip them
    // before the IpAddr check or literal v6 hosts slip past this layer.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(host)
}

static FAVICON_CACHE: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
const FAVICON_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// SSRF guard: reject IPs that aren't globally routable (loopback, RFC 1918
/// private ranges, link-local — which also covers the 169.254.169.254 cloud
/// metadata endpoint, CGNAT, IPv6 unique-local/ULA, multicast, etc.).
fn is_globally_routable_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // CGNAT 100.64.0.0/10 — some cloud providers serve metadata here too.
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local addresses fc00::/7 (Ipv6Addr::is_unique_local()
                // isn't stable yet, so check the prefix manually).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // IPv4-mapped (::ffff:a.b.c.d) — recheck the embedded v4 address.
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| !is_globally_routable_ip(IpAddr::V4(v4))))
        }
    }
}

/// Resolve `host` and reject it (return false) if *any* resolved address is
/// not globally routable, or if it fails to resolve at all. Applied both to
/// the initial favicon host and to every redirect hop, since DNS can
/// legitimately answer with a public IP at check time and still rebind (or
/// redirect) to an internal one on the actual connection.
fn is_safe_favicon_host(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    match (host, 443u16).to_socket_addrs() {
        Ok(addrs) => {
            let mut resolved_any = false;
            for addr in addrs {
                resolved_any = true;
                if !is_globally_routable_ip(addr.ip()) {
                    return false;
                }
            }
            resolved_any
        }
        Err(_) => false,
    }
}

fn detect_image_content_type(content_type: Option<&str>, bytes: &[u8]) -> Option<String> {
    // Reject obvious non-image responses (e.g. HTML pages served for missing icons).
    if let Some(ct) = content_type {
        let ct = ct.trim().to_lowercase();
        if ct.starts_with("text/html") || ct.starts_with("text/plain") {
            return None;
        }
    }

    if bytes.is_empty() {
        return None;
    }

    // Detect actual image format from magic bytes.
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png".to_string());
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif".to_string());
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg".to_string());
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp".to_string());
    }
    if bytes.len() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0x01 && bytes[3] == 0x00
    {
        return Some("image/x-icon".to_string());
    }

    // SVG may start with whitespace; strip it before checking tags.
    let body = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .map(|start| &bytes[start..])
        .unwrap_or(bytes);
    if body.starts_with(b"<?xml")
        || body.starts_with(b"<!DOCTYPE svg")
        || body.starts_with(b"<svg")
    {
        return Some("image/svg+xml".to_string());
    }

    // Fall back to the server's content-type only if it already claims to be an image.
    content_type
        .and_then(|ct| ct.split(';').next())
        .map(|ct| ct.trim())
        .filter(|ct| ct.starts_with("image/"))
        .map(|ct| ct.to_string())
}

async fn fetch_favicon_data_url_from(client: &reqwest::Client, candidate: &str) -> Option<String> {
    let response = client.get(candidate).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let bytes = response.bytes().await.ok()?;
    let content_type = detect_image_content_type(content_type.as_deref(), &bytes)?;

    Some(format!(
        "data:{content_type};base64,{}",
        B64.encode(bytes.as_ref())
    ))
}

async fn discover_favicon_from_html(
    client: &reqwest::Client,
    base: &str,
) -> Result<Option<String>, String> {
    let html = client
        .get(base)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    let base_url = Url::parse(base).map_err(|e| e.to_string())?;
    pick_best_favicon_url(&html, &base_url)
}

/// Choose the best `<link rel*=`icon`>` candidate from an HTML document.
/// Preference order is a score: declared icon type (apple-touch-icon >
/// generic icon > shortcut icon) + declared size + format bonus (SVG > PNG >
/// ICO).
fn pick_best_favicon_url(html: &str, base_url: &Url) -> Result<Option<String>, String> {
    let document = Html::parse_document(html);
    let selector =
        Selector::parse("link[rel*='icon']").map_err(|e| format!("Failed to parse selector: {e:?}"))?;

    let mut best: Option<(String, u32)> = None;

    for link in document.select(&selector) {
        let rel = link.value().attr("rel").unwrap_or("").to_lowercase();
        let href = match link.value().attr("href") {
            Some(h) => h,
            None => continue,
        };

        let resolved = match base_url.join(href) {
            Ok(url) => url.to_string(),
            Err(_) => continue,
        };

        // Prefer declared icon types, then apple-touch-icon, then shortcut icon.
        let rel_score = if rel.contains("apple-touch-icon") {
            30
        } else if rel.contains("shortcut") {
            10
        } else {
            20
        };

        // Parse sizes="192x192" to prefer larger icons.
        let sizes = link.value().attr("sizes").unwrap_or("");
        let size_score: u32 = sizes
            .split('x')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Slightly prefer vector / PNG over generic ICO.
        let type_score = if resolved.ends_with(".svg") || resolved.contains("svg+xml") {
            100
        } else if resolved.ends_with(".png") {
            50
        } else {
            0
        };

        let total = rel_score + size_score + type_score;

        if best.as_ref().map_or(true, |(_, current)| total > *current) {
            best = Some((resolved, total));
        }
    }

    Ok(best.map(|(url, _)| url))
}

pub async fn fetch_favicon(url: String) -> Result<Option<String>, String> {
    let Some(domain) = normalize_login_domain(&url) else {
        return Ok(None);
    };

    // Check in-memory cache first.
    {
        let cache = FAVICON_CACHE.lock().unwrap();
        if let Some((data_url, fetched_at)) = cache.get(&domain) {
            if fetched_at.elapsed() < FAVICON_CACHE_TTL {
                return Ok(Some(data_url.clone()));
            }
        }
    }

    // Reject the initial host up front (before opening any connection) if it
    // resolves to a non-public address — closes the direct SSRF vector
    // (`normalize_login_domain` only rejects literal IP *strings*, not
    // hostnames that resolve to an internal/loopback/metadata address).
    if !is_safe_favicon_host(&domain) {
        return Ok(None);
    }

    let client = reqwest::Client::builder()
        .user_agent("VELA Desktop/1.0")
        .timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many redirects");
            }
            match attempt.url().host_str() {
                Some(host) if is_safe_favicon_host(host) => attempt.follow(),
                _ => attempt.error("redirect target is not a public host"),
            }
        }))
        .build()
        .map_err(|e| format!("Failed to create favicon client: {e}"))?;

    let base = format!("https://{domain}");

    // 1. Fast fallbacks: DuckDuckGo + common well-known paths.
    let candidates = [
        format!("https://icons.duckduckgo.com/ip3/{domain}.ico"),
        format!("https://{domain}/favicon.ico"),
        format!("https://{domain}/favicon.svg"),
        format!("https://{domain}/favicon.png"),
        format!("https://{domain}/apple-touch-icon.png"),
    ];

    for candidate in candidates {
        if let Some(data_url) = fetch_favicon_data_url_from(&client, &candidate).await {
            FAVICON_CACHE
                .lock()
                .unwrap()
                .insert(domain.clone(), (data_url.clone(), Instant::now()));
            return Ok(Some(data_url));
        }
    }

    // 2. Slower HTML discovery for sites that declare icons via <link rel="icon">.
    if let Ok(Some(found)) = discover_favicon_from_html(&client, &base).await {
        if let Some(data_url) = fetch_favicon_data_url_from(&client, &found).await {
            FAVICON_CACHE
                .lock()
                .unwrap()
                .insert(domain.clone(), (data_url.clone(), Instant::now()));
            return Ok(Some(data_url));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn normalize_login_domain_adds_scheme_and_lowercases() {
        assert_eq!(normalize_login_domain("Example.COM"), Some("example.com".into()));
        assert_eq!(normalize_login_domain("https://ExAmple.com/path?q=1"), Some("example.com".into()));
        assert_eq!(normalize_login_domain("http://sub.example.com"), Some("sub.example.com".into()));
    }

    #[test]
    fn normalize_login_domain_rejects_ips_and_garbage() {
        assert_eq!(normalize_login_domain("192.168.1.1"), None);
        assert_eq!(normalize_login_domain("https://127.0.0.1:8080"), None);
        assert_eq!(normalize_login_domain("https://[::1]"), None);
        assert_eq!(normalize_login_domain(""), None);
    }

    #[test]
    fn globally_routable_ip_classification() {
        let cases: &[(&str, bool)] = &[
            ("8.8.8.8", true),
            ("1.1.1.1", true),
            ("127.0.0.1", false),        // loopback
            ("10.0.0.5", false),         // RFC 1918
            ("172.16.0.5", false),       // RFC 1918
            ("192.168.1.1", false),      // RFC 1918
            ("169.254.169.254", false),  // link-local cloud metadata
            ("100.64.0.1", false),       // CGNAT
            ("100.127.255.254", false),  // CGNAT upper edge
            ("0.0.0.0", false),          // unspecified
            ("255.255.255.255", false),  // broadcast
            ("224.0.0.1", false),        // multicast
            ("192.0.2.1", false),        // documentation TEST-NET-1
            ("::1", false),              // v6 loopback
            ("::", false),               // v6 unspecified
            ("fc00::1", false),          // v6 unique-local
            ("fdff::1", false),          // v6 unique-local
            ("ff02::1", false),          // v6 multicast
            ("::ffff:127.0.0.1", false), // v4-mapped loopback
            ("::ffff:8.8.8.8", true),    // v4-mapped public
        ];
        for (ip, expected) in cases {
            let parsed: IpAddr = ip.parse().unwrap();
            assert_eq!(is_globally_routable_ip(parsed), *expected, "ip {ip}");
        }
    }

    #[test]
    fn content_type_detection_by_magic_bytes() {
        assert_eq!(
            detect_image_content_type(None, b"\x89PNG\r\n\x1a\nrest"),
            Some("image/png".into())
        );
        assert_eq!(detect_image_content_type(None, b"GIF89a...."), Some("image/gif".into()));
        assert_eq!(detect_image_content_type(None, b"GIF87a...."), Some("image/gif".into()));
        assert_eq!(
            detect_image_content_type(None, &[0xff, 0xd8, 0xff, 0xe0]),
            Some("image/jpeg".into())
        );
        assert_eq!(
            detect_image_content_type(None, b"RIFF\x00\x00\x00\x00WEBP"),
            Some("image/webp".into())
        );
        assert_eq!(
            detect_image_content_type(None, &[0x00, 0x00, 0x01, 0x00]),
            Some("image/x-icon".into())
        );
        assert_eq!(
            detect_image_content_type(None, b"  \n<svg xmlns=\"http://www.w3.org/2000/svg\">"),
            Some("image/svg+xml".into())
        );
        assert_eq!(
            detect_image_content_type(None, b"<?xml version=\"1.0\"?><svg>"),
            Some("image/svg+xml".into())
        );
    }

    #[test]
    fn content_type_detection_rejects_non_images() {
        // HTML error pages served at /favicon.ico must not become icons.
        assert_eq!(detect_image_content_type(Some("text/html; charset=utf-8"), b"<html>"), None);
        assert_eq!(detect_image_content_type(Some("text/plain"), b"404"), None);
        assert_eq!(detect_image_content_type(None, b""), None);
        assert_eq!(detect_image_content_type(None, b"random bytes here"), None);
    }

    #[test]
    fn content_type_detection_falls_back_to_declared_image_type() {
        // Unknown magic but the server insists it's an image → trust the header.
        assert_eq!(
            detect_image_content_type(Some("image/avif"), b"\x00\x00\x00"),
            Some("image/avif".into())
        );
        // But only image/* — never a generic type.
        assert_eq!(detect_image_content_type(Some("application/octet-stream"), b"\x00\x00\x00"), None);
    }

    fn base() -> Url {
        Url::parse("https://example.com").unwrap()
    }

    #[test]
    fn pick_best_favicon_resolves_relative_hrefs() {
        let html = r#"<html><head><link rel="icon" href="/icons/favicon.ico"></head></html>"#;
        assert_eq!(
            pick_best_favicon_url(html, &base()).unwrap(),
            Some("https://example.com/icons/favicon.ico".into())
        );
    }

    #[test]
    fn pick_best_favicon_prefers_svg_then_png_then_ico() {
        let html = r#"<html><head>
            <link rel="icon" href="/favicon.ico">
            <link rel="icon" type="image/png" href="/favicon.png">
            <link rel="icon" type="image/svg+xml" href="/favicon.svg">
        </head></html>"#;
        assert_eq!(
            pick_best_favicon_url(html, &base()).unwrap(),
            Some("https://example.com/favicon.svg".into())
        );
    }

    #[test]
    fn pick_best_favicon_prefers_larger_declared_size() {
        let html = r#"<html><head>
            <link rel="icon" sizes="16x16" href="/small.png">
            <link rel="icon" sizes="192x192" href="/large.png">
        </head></html>"#;
        assert_eq!(
            pick_best_favicon_url(html, &base()).unwrap(),
            Some("https://example.com/large.png".into())
        );
    }

    #[test]
    fn pick_best_favicon_apple_touch_icon_beats_plain_icon() {
        let html = r#"<html><head>
            <link rel="icon" href="/favicon.ico">
            <link rel="apple-touch-icon" href="/touch.png">
        </head></html>"#;
        assert_eq!(
            pick_best_favicon_url(html, &base()).unwrap(),
            Some("https://example.com/touch.png".into())
        );
    }

    #[test]
    fn pick_best_favicon_handles_missing_and_broken_links() {
        assert_eq!(pick_best_favicon_url("<html><head></head></html>", &base()).unwrap(), None);
        // No href → skipped, not a crash.
        let html = r#"<html><head><link rel="icon"></head></html>"#;
        assert_eq!(pick_best_favicon_url(html, &base()).unwrap(), None);
    }
}
