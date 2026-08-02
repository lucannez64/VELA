package com.vela.android.autofill

import android.content.Context
import android.util.Log
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONObject

/**
 * Which apps may be believed when they claim to be showing a website.
 *
 * `AssistStructure` fields are filled in by the app being autofilled, and any
 * app can call `ViewStructure.setWebDomain("paypal.com")`. A browser is the one
 * caller genuinely in a position to report the origin on screen, so a browser
 * is the only caller whose `webDomain` is trusted (audit A-2).
 *
 * That makes "is this a browser?" a security decision, and a package name is not
 * an answer to it — `com.android.chrome` is squattable on any third-party store.
 * So the allowlist pins **signing certificates**: an app is a trusted browser
 * when the certificate it is actually signed with is one the list names for that
 * package. This is the same list, and the same check, that Android uses to
 * decide which apps may assert a web origin for passkeys — the identical
 * question, so there is no reason to invent a second answer to it.
 *
 * Two sources ship in `assets/`:
 *
 *  * `privileged_browsers_google.json` — Google's published list, verbatim from
 *    `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json`. It
 *    includes a few non-browsers that host web sessions (Play Services, work-
 *    profile containers); that is Google's curation of "may speak for an origin",
 *    which is exactly what we are asking, so it is kept as published.
 *  * `privileged_browsers_community.json` — privacy-focused forks (IronFox,
 *    Cromite, Iceraven, Mull, …) that Google does not list. Sourced from
 *    `bitwarden/android`'s `fido2_privileged_community.json`.
 *
 * Refresh both by re-downloading; they are data, and nothing here needs to change.
 *
 * A browser on neither list gets no browser trust — there is no name-only tier,
 * because a package name is the thing this finding is about. The cost is real:
 * passwords saved in such a browser are filed under its package rather than the
 * site, and are then offered across every site in it. See issue on unpinned
 * browsers; the fix is a published fingerprint, not a looser rule here.
 */
class BrowserAllowlist(private val context: Context) {

    private val pinned: Map<String, Set<String>> by lazy { loadPinned() }
    private val answers = ConcurrentHashMap<String, Boolean>()

    /**
     * Whether [packageName] is a browser whose `webDomain` may be believed.
     *
     * Answers are memoised: an app's signature cannot change without a reinstall,
     * which restarts us anyway, and this runs on the fill path.
     */
    fun isTrustedBrowser(packageName: String?): Boolean {
        val pkg = packageName?.trim()?.lowercase(Locale.US)?.takeIf { it.isNotEmpty() } ?: return false
        return answers.getOrPut(pkg) { evaluate(pkg) }
    }

    private fun evaluate(pkg: String): Boolean {
        // No pinned fingerprint, no trust. A package name on its own is exactly
        // what this finding is about, so there is no weaker tier to fall back to.
        val expected = pinned[pkg] ?: return false
        val actual = AppSignatures.sha256(context, pkg)
        if (actual.isEmpty()) return false
        return expected.intersect(actual).isNotEmpty()
    }

    private fun loadPinned(): Map<String, Set<String>> {
        val merged = mutableMapOf<String, MutableSet<String>>()
        for (asset in ASSETS) {
            val body = runCatching {
                context.assets.open(asset).bufferedReader().use { it.readText() }
            }.onFailure { Log.w(TAG, "missing browser allowlist asset: $asset") }.getOrNull() ?: continue

            for ((pkg, fingerprints) in parse(body)) {
                merged.getOrPut(pkg) { mutableSetOf() }.addAll(fingerprints)
            }
        }
        return merged
    }

    companion object {
        private const val TAG = "BrowserAllowlist"

        private val ASSETS = listOf(
            "privileged_browsers_google.json",
            "privileged_browsers_community.json",
        )

        /**
         * `{"apps":[{"type":"android","info":{"package_name":…,"signatures":[{"cert_fingerprint_sha256":…}]}}]}`
         * → package → fingerprints. Kept pure so it can be tested off-device.
         */
        internal fun parse(json: String): Map<String, Set<String>> {
            val apps = runCatching { JSONObject(json).optJSONArray("apps") }.getOrNull() ?: return emptyMap()
            val out = mutableMapOf<String, MutableSet<String>>()

            for (index in 0 until apps.length()) {
                val app = apps.optJSONObject(index) ?: continue
                if (app.optString("type") != "android") continue

                val info = app.optJSONObject("info") ?: continue
                val pkg = info.optString("package_name")
                    .trim()
                    .lowercase(Locale.US)
                    .takeIf { it.isNotEmpty() } ?: continue

                val signatures = info.optJSONArray("signatures") ?: continue
                val fingerprints = (0 until signatures.length())
                    .mapNotNull { signatures.optJSONObject(it)?.optString("cert_fingerprint_sha256") }
                    .mapNotNull { AppSignatures.normalize(it) }
                // A package with no usable fingerprint is not an entry — it would
                // silently degrade to trusting the name.
                if (fingerprints.isEmpty()) continue

                out.getOrPut(pkg) { mutableSetOf() }.addAll(fingerprints)
            }
            return out
        }
    }
}
