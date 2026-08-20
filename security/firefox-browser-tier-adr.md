# ADR — Firefox-family support in the browser-driven login tier

**Status:** Accepted — in progress (implementation PR builds; the driver must be
validated against real `geckodriver` + Firefox in a desktop environment).
**Date:** 2026-08-20
**Applies to:** `desktopVELA/vela-desktop-core/src/browser/`
**Related:** `security/browser-driven-login-design.md`,
`security/exploits/test_firefox_tier_memleak.py`

---

## Context

The browser-driven login tier (in-core login for bot-walled sites) drives a
disposable real browser, fills the login form with a **placeholder** password,
and substitutes the real credential at the **network layer** so the page's
JavaScript never sees it. On Chromium that substitution is CDP's `Fetch`
domain. Firefox and its forks (Zen, Waterfox, Floorp, LibreWolf) implement **no
CDP**, so the tier cannot drive them today.

User asked to support the Firefox family now. A separate finding
(`test_firefox_tier_memleak.py`) showed the co-resident same-UID memory-read
residual is **browser-agnostic** (measured on Firefox too), so the
transport-agnostic mitigations (Tier-3 core-perform default-on; Tier-1
distinct-UID isolation) apply unchanged to a Firefox tier.

## Decision

### 1. Driver: geckodriver + WebDriver BiDi

Drive the disposable Firefox through **`geckodriver`** over **WebDriver BiDi**
(not classic Marionette). BiDi is the W3C cross-browser protocol that Chrome,
Edge and Firefox all speak, and — decisively — its `network` module provides
**request interception**:

- `network.addIntercept(phases: ["beforeRequestSent"])` (optionally with a
  URL pattern) pauses matching requests;
- `network.beforeRequestSent` events carry the request (url, method, headers,
  body);
- **`network.continueRequest(request, body, …)` can override the request
  `body`** — the exact network-layer substitution the tier needs.

So a Firefox login can reproduce the Chromium flow: the page fills with the
placeholder, the human submits, the request pauses at the network layer, and
the core continues it with the real credential substituted — the password
never enters the page's JS. **The core security property is preserved.**

### 2. Geckodriver discovery + disposable launch

- Discover `geckodriver` on PATH (plus `FIREFOX_BIN` override), like the
  Chromium `host.rs` candidates.
- Spawn `geckodriver --marionette-port <0>` (or a derived port) with a throwaway
  Firefox profile; Firefox is auto-launched by geckodriver with `--marionette`.
- Connect to the BiDi WebSocket session; there is **no Chromium-style CDP pipe**
  here (geckodriver's BiDi is a WebSocket on a loopback port), so the RT-10
  "no TCP listener" property does not transfer to the Firefox driver the same
  way. The same-user CDP-port finding concerned the *browser's own* debug
  endpoint; here the loopback is geckodriver's, and the residual is addressed by
  Tier-3 (core-perform) default-on plus the disposable-profile teardown.

### 3. Reuse the ceremony where possible

- The placeholder `PLACEHOLDER_PASSWORD`, the
  `CapturedRequest::substitute`/`check_same_site` rules, and the `SiteMode`
  residual modelling already live in the core and are browser-agnostic — reuse
  them.
- New only where the browser differs: a BiDi/WebDriver client, the
  `network.beforeRequestSent`→`continueRequest` substitution mapping, form fill
  via WebDriver element commands, and session harvest (Firefox credentials are
  cookies and, for token sites, the same localStorage/IndexedDB replication).
- Form fill uses classic WebDriver over HTTP (element send keys), while
  interception/substitution uses BiDi over the WebSocket; geckodriver exposes
  both. The driver keeps one session.

### 4. Security parity

- Password reaches the browser only at the network layer (placeholder in the
  page), matching the Chromium tier.
- Same-site + scheme rule (RT-12) and the identity-provider allowlist apply to
  the substituted `continueRequest` body.
- Tier-3 core-perform isn't relevant to *how* Firefox is driven (it's about
  whether the browser sends the credential at all) — a Firefox tier uses the
  browser-sends network-substitution path, so the residual is the same as
  Chromium's browser-send path, mitigated by Tier-3 where the site accepts a
  core client and by Tier-1 UID isolation for the disposable browser.

## Consequences

- **Positive.** Firefox family becomes a first-class tier target with the same
  "page never sees the password" property, and the same mitigations.
- **Accepted.** Needs `geckodriver` present on the target (a dependency the
  Chromium tier did not have) and real-browser validation. The full driver
  (form-fill heuristics, harvest, OAuth/second-factor, human-click flow) mirrors
  the Chromium tier and is a sizeable body of new code, landed incrementally
  behind the existing `browser-login` feature; a browser-resolved as Gecko
  routed to the new driver.

## Open items
- Whether classic-WebDriver element fill is reliable enough across sites given
  Firefox's form handling, or whether Shadow-DOM-interop fill (the Chromium
  `fill.rs` gained) needs a Firefox sibling.
- Version floors: BiDi `network.continueRequest` body override needs a modern
  Firefox (≥ ~129) + matching geckodriver; document the floor.
