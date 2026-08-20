//! Harvest the session cookies a browser-driven login produced, into the
//! usual [`crate::login::SessionCookie`] shape so the caller installs them
//! exactly as the form/recipe tiers hand them over.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::browser::cdp::{self, Cdp};
use crate::login::SessionCookie;

/// Read the browser's cookies scoped to `site` (a URL on the logged-in
/// domain) and convert them to the session artifact the caller installs.
pub async fn harvest(cdp: &Cdp, session: &str, site: &str) -> Result<Vec<SessionCookie>, String> {
    let response = cdp
        .call_scoped("Network.getCookies", json!({ "urls": [site] }), session)
        .await?;
    let cookies = response
        .get("cookies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(cookies
        .into_iter()
        .filter_map(to_session_cookie)
        .collect())
}

/// Read the page's storage — the token-session sites' session (Firebase Auth
/// keeps the token in localStorage when "remember me" is on and in
/// sessionStorage when it is off; monkeytype is the canonical example).
/// sessionStorage wins over localStorage for the same key, and the merged map
/// is replicated into the user's tab as localStorage, which is what the auth
/// SDKs rehydrate from. Like the cookies: short-lived, a secret, never logged.
pub async fn harvest_local_storage(
    cdp: &Cdp,
    session: &str,
) -> Result<BTreeMap<String, String>, String> {
    let script = r#"
        (() => {
          const collect = (storage) => {
            const out = {};
            for (let i = 0; i < storage.length; i++) {
              const key = storage.key(i);
              if (key) out[key] = storage.getItem(key);
            }
            return out;
          };
          return { local: collect(localStorage), session: collect(sessionStorage) };
        })()
    "#;
    let response = cdp::evaluate(cdp, session, script).await?;
    let value = response
        .get("result")
        .and_then(|x| x.get("value"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut out = BTreeMap::new();
    for which in ["local", "session"] {
        if let Some(object) = value.get(which).and_then(Value::as_object) {
            for (key, entry) in object {
                if let Some(value) = entry.as_str() {
                    // session wins: it is the fresher persistence when the
                    // form's "remember me" was off.
                    out.insert(key.clone(), value.to_string());
                }
            }
        }
    }
    Ok(out)
}

/// Read the auth SDK's IndexedDB — the storage Firebase puts the session in
/// when its configured persistence is `indexedDBLocalPersistence` (monkeytype
/// uses it whenever "remember me" is on). The record keys are like
/// `firebase:authUser:<apiKey>:[DEFAULT]`; the values are the auth user objects
/// (the value carries the token). Returned as key → value so the caller (and
/// ultimately the user's browser) can write them straight back.
pub async fn harvest_indexed_db(
    cdp: &Cdp,
    session: &str,
) -> Result<BTreeMap<String, Value>, String> {
    let script = r#"
        (() => new Promise((resolve) => {
          const readStore = (dbName, storeName) => {
            const req = indexedDB.open(dbName);
            req.onerror = () => resolve({});
            req.onsuccess = () => {
              const db = req.result;
              const tx = db.transaction(storeName, 'readonly');
              const store = tx.objectStore(storeName);
              const all = store.getAll();
              all.onsuccess = () => {
                const out = {};
                for (const rec of all.result) {
                  if (rec && typeof rec.fbase_key === 'string') {
                    out[rec.fbase_key] = rec.value;
                  }
                }
                resolve(out);
              };
              all.onerror = () => resolve({});
            };
          };
          try { readStore('firebaseLocalStorageDb', 'firebaseLocalStorage'); }
          catch (e) { resolve({}); }
        }))()
    "#;
    let response = cdp::evaluate(cdp, session, script).await?;
    let value = response
        .get("result")
        .and_then(|x| x.get("value"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(value
        .as_object()
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default())
}

pub(crate) fn to_session_cookie(cookie: Value) -> Option<SessionCookie> {
    let name = cookie.get("name")?.as_str()?.to_string();
    if name.is_empty() {
        return None;
    }
    let domain = cookie
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let same_site = cookie
        .get("sameSite")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase())
        .filter(|s| !s.is_empty() && s != "unspecified");
    let expires_at = cookie.get("expires").and_then(Value::as_f64).map(|t| t as i64);
    let expires_at = expires_at.filter(|t| *t > 0);

    Some(SessionCookie {
        name,
        value: cookie.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        domain,
        path: cookie.get("path").and_then(Value::as_str).unwrap_or("/").to_string(),
        secure: cookie.get("secure").and_then(Value::as_bool).unwrap_or(false),
        http_only: cookie.get("httpOnly").and_then(Value::as_bool).unwrap_or(false),
        same_site,
        expires_at,
        host_only: !cookie.get("domain").and_then(Value::as_str).unwrap_or_default().starts_with('.'),
    })
}
