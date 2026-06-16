//! Client-IP resolution for rate limiting.
//!
//! Rate limiters key on the client's IP. When VELA runs behind a trusted
//! reverse proxy / Cloudflare Tunnel, the socket peer is always the proxy
//! (e.g. `127.0.0.1`), so every remote client would otherwise collapse into a
//! single rate-limit bucket. This module resolves the *real* client IP from
//! proxy-set headers — but **only** when the request actually arrives from a
//! configured trusted proxy, so a direct client can't spoof its IP to dodge
//! limits.

use std::net::IpAddr;

use axum::http::HeaderMap;

use crate::config::Config;

/// Whether `ip` falls within `cidr` (e.g. `127.0.0.1/32`, `::1/128`).
pub fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };

    match (ip, network.parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(network))) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(ip), Ok(IpAddr::V6(network))) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(ip) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

/// Whether `peer` is one of the configured trusted proxy networks.
pub fn from_trusted_proxy(peer: IpAddr, config: &Config) -> bool {
    config
        .trusted_proxy_cidrs
        .iter()
        .any(|cidr| ip_in_cidr(peer, cidr))
}

/// Resolve the client IP to key rate limits on, as a string.
///
/// When `TRUST_PROXY_HEADERS` is set and the request came from a trusted proxy,
/// prefer `CF-Connecting-IP` (Cloudflare overwrites any client-supplied value),
/// then the first hop of `X-Forwarded-For`. Forwarded values are validated as
/// real IPs so an attacker behind the proxy can't inject arbitrary bucket keys.
/// Otherwise — and for direct/untrusted peers — fall back to the socket peer.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, config: &Config) -> String {
    if config.trust_proxy_headers {
        if let Some(peer) = peer {
            if from_trusted_proxy(peer, config) {
                if let Some(ip) = forwarded_ip(headers) {
                    return ip;
                }
            }
        }
    }

    peer.map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// Extract a validated client IP from proxy headers, if present.
fn forwarded_ip(headers: &HeaderMap) -> Option<String> {
    let parse_valid = |s: &str| -> Option<String> {
        let s = s.trim();
        s.parse::<IpAddr>().ok().map(|ip| ip.to_string())
    };

    if let Some(cf) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        if let Some(ip) = parse_valid(cf) {
            return Some(ip);
        }
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            if let Some(ip) = parse_valid(first) {
                return Some(ip);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(trust_proxy_headers: bool, trusted_proxy_cidrs: &[&str]) -> Config {
        Config {
            listen_addr: "127.0.0.1:8443".into(),
            tls_listen_addr: None,
            tls_cert_path: None,
            tls_key_path: None,
            http3_enabled: false,
            http3_listen_addr: None,
            http3_alt_svc_max_age: 0,
            db_path: String::new(),
            sled_path: String::new(),
            webauthn_rp_id: String::new(),
            webauthn_rp_origin: String::new(),
            webauthn_rp_name: String::new(),
            paseto_secret_key: Vec::new(),
            paseto_public_key: Vec::new(),
            max_body_bytes: 0,
            max_chunk_bytes: 0,
            cors_origins: Vec::new(),
            allow_wildcard_cors: false,
            allow_insecure_lan: false,
            trust_proxy_headers,
            trusted_proxy_cidrs: trusted_proxy_cidrs.iter().map(|s| s.to_string()).collect(),
            production: true,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn peer(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn cidr_matching() {
        assert!(ip_in_cidr("127.0.0.1".parse().unwrap(), "127.0.0.1/32"));
        assert!(ip_in_cidr("10.1.2.3".parse().unwrap(), "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1".parse().unwrap(), "10.0.0.0/8"));
        assert!(ip_in_cidr("::1".parse().unwrap(), "::1/128"));
        assert!(!ip_in_cidr("127.0.0.1".parse().unwrap(), "::1/128"));
    }

    #[test]
    fn direct_peer_when_proxy_untrusted() {
        // trust disabled entirely
        let c = cfg(false, &["127.0.0.1/32"]);
        let h = headers(&[("cf-connecting-ip", "9.9.9.9")]);
        assert_eq!(client_ip(&h, peer("127.0.0.1"), &c), "127.0.0.1");

        // trust on, but the peer is NOT a trusted proxy → ignore headers (anti-spoof)
        let c = cfg(true, &["127.0.0.1/32"]);
        assert_eq!(client_ip(&h, peer("203.0.113.7"), &c), "203.0.113.7");
    }

    #[test]
    fn cf_connecting_ip_wins_from_trusted_proxy() {
        let c = cfg(true, &["127.0.0.1/32"]);
        let h = headers(&[
            ("cf-connecting-ip", "198.51.100.4"),
            ("x-forwarded-for", "203.0.113.9, 70.70.70.70"),
        ]);
        assert_eq!(client_ip(&h, peer("127.0.0.1"), &c), "198.51.100.4");
    }

    #[test]
    fn x_forwarded_for_first_hop_when_no_cf_header() {
        let c = cfg(true, &["127.0.0.1/32"]);
        let h = headers(&[("x-forwarded-for", "203.0.113.9, 70.70.70.70")]);
        assert_eq!(client_ip(&h, peer("127.0.0.1"), &c), "203.0.113.9");
    }

    #[test]
    fn garbage_forwarded_value_falls_back_to_peer() {
        let c = cfg(true, &["127.0.0.1/32"]);
        let h = headers(&[("cf-connecting-ip", "not-an-ip")]);
        assert_eq!(client_ip(&h, peer("127.0.0.1"), &c), "127.0.0.1");
    }
}
