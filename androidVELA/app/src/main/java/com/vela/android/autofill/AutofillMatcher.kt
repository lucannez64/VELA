package com.vela.android.autofill

import com.vela.android.core.VaultItem
import java.net.URI
import java.util.Locale

/**
 * Decides which saved logins may be offered to an autofill request.
 *
 * Pure and side-effect free (network verification arrives as a lambda) so the
 * rules that govern where credentials go can be tested directly.
 *
 * The request gives us two things, and neither is trustworthy on its own:
 *
 *  * `packageName` — genuine, the framework fills it in, but it says nothing
 *    about which *site* the app speaks for. `com.ubercab` is not `ubercab.com`,
 *    and anyone can publish `com.paypal.anything`.
 *  * `webDomain` — set by the app being filled, via `ViewStructure.setWebDomain`.
 *    Any app can claim any domain (audit A-2).
 *
 * So a login is offered only when something *outside* the request vouches for
 * the pairing: the user linked the app, the site published an asset link, the
 * request came from a real browser, or the app is on the curated list. When
 * nothing does, the answer is no suggestions — not a guess.
 */
object AutofillMatcher {

    /** How many distinct hosts we will ask about over the network for one request. */
    private const val MAX_ASSET_LINK_LOOKUPS = 8

    /**
     * @param isTrustedBrowser see [BrowserAllowlist]. Defaults to "not a browser",
     *   so a caller that cannot check signatures never grants browser trust by
     *   omission.
     * @param installedSignatures the SHA-256 fingerprints the requesting app is
     *   actually signed with, for links that pinned one. Defaults to none, so a
     *   pinned link fails closed rather than degrading to name-only trust.
     * @param verifyAssetLinks `(domain, packageName) -> vouched`, see
     *   [AssetLinksVerifier]. Defaults to "no network answer", which is also the
     *   right behaviour offline: matching falls back to the local evidence.
     */
    fun match(
        logins: List<VaultItem.Login>,
        webDomain: String?,
        packageName: String?,
        isTrustedBrowser: (String) -> Boolean = { false },
        installedSignatures: (String) -> Set<String> = { emptySet() },
        verifyAssetLinks: (String, String) -> Boolean = { _, _ -> false },
    ): List<VaultItem.Login> {
        val pkg = packageName?.trim()?.lowercase(Locale.US)?.takeIf { it.isNotEmpty() }
        val claimedDomain = webDomain?.trim()?.takeIf { it.isNotEmpty() }

        // Resolved once: a link that pinned a signing key only counts if the app
        // asking is still signed with it.
        val actualSignatures by lazy { pkg?.let(installedSignatures).orEmpty() }

        val trustedDomains = buildSet {
            if (claimedDomain != null) {
                // A browser reports the origin it is actually displaying; that is
                // the one case where the field means what it says.
                if (pkg == null || isTrustedBrowser(pkg)) {
                    add(claimedDomain)
                } else if (hostOf(claimedDomain)?.let { verifyAssetLinks(it, pkg) } == true) {
                    // Not a browser, but the site it names vouches for this exact
                    // app — the usual shape for a login screen inside a WebView.
                    add(claimedDomain)
                }
            }
            AppAssociations.curatedDomain(pkg)?.let { add(it) }
        }

        val local = logins.filter { login ->
            // 1. The user linked this app to this login. Strongest signal there is.
            (pkg != null && login.appIds.any { linkGrants(it, pkg, actualSignatures) }) ||
                // 2. Saved from this app before the link existed: the URL *is* the
                //    package name. Still the user's own data, so still honoured.
                (pkg != null && login.url.trim().equals(pkg, ignoreCase = true)) ||
                // 3. A domain we are entitled to believe.
                trustedDomains.any { domain -> domainsMatch(domain, login.url) }
        }
        if (local.isNotEmpty() || pkg == null) return local

        // 4. Nothing local matched: ask the sites themselves. Only now, because
        //    it costs a network round trip per host (cached, but still).
        val hosts = logins.mapNotNull { hostOf(it.url) }.distinct().take(MAX_ASSET_LINK_LOOKUPS)
        val vouched = hosts.filter { host -> verifyAssetLinks(host, pkg) }.toSet()
        if (vouched.isEmpty()) return emptyList()
        return logins.filter { login -> hostOf(login.url)?.let { it in vouched } == true }
    }

    /**
     * Whether an `androidapp://…` link on an item grants this request.
     *
     * The package must match, and — when the link pinned a signing certificate —
     * the app must still be signed with it. An unpinned link is honoured on the
     * package name alone: that is what the user chose, and it is the only form
     * that existed before pinning did.
     */
    fun linkGrants(link: String, packageName: String, signatures: Set<String>): Boolean {
        val linked = AppAssociations.packageFromUri(link) ?: return false
        if (!linked.equals(packageName, ignoreCase = true)) return false
        val pinned = AppAssociations.certFromUri(link) ?: return true
        return signatures.any { AppSignatures.normalize(it) == pinned }
    }

    /**
     * Whether a request for `current` should be filled from a login stored for
     * `stored`: same host, or `current` is a subdomain of it.
     */
    fun domainsMatch(current: String, stored: String): Boolean {
        val currentHost = hostOf(current) ?: current.lowercase(Locale.US)
        val storedHost = hostOf(stored) ?: stored.lowercase(Locale.US)
        if (currentHost.isEmpty() || storedHost.isEmpty()) return false
        if (currentHost == storedHost) return true
        if (currentHost.isIpAddress()) return false
        val currentParts = currentHost.split(".")
        val storedParts = storedHost.split(".")
        if (storedParts.size < 2 || storedParts.size > currentParts.size) return false
        return currentParts.takeLast(storedParts.size) == storedParts
    }

    /** Host of a URL or bare domain, `www.` stripped; null when it isn't one. */
    fun hostOf(value: String): String? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return null
        val normalized = if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            trimmed
        } else {
            "https://$trimmed"
        }
        return runCatching {
            URI(normalized).host?.removePrefix("www.")?.lowercase(Locale.US)
        }.getOrNull()?.takeIf { it.isNotEmpty() }
    }

    private fun String.isIpAddress(): Boolean = split(".").all { it.toIntOrNull() in 0..255 }
}
