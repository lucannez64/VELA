package com.vela.android.autofill

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import java.util.Locale

/**
 * Browsers the user has vouched for on this device.
 *
 * Google's privileged-apps list and the community one cover most browsers, and
 * [BrowserAllowlist] pins the rest we could verify from a vendor's own APK. Some
 * are reachable through neither: Ecosia, Opera GX and UC ship only through Play,
 * and where a vendor uses Play App Signing the certificate on the device is
 * Google's re-signed one, which the vendor never publishes anywhere (#125).
 *
 * The device itself is the remaining authority. The user can see which browser
 * they installed and from where; we cannot. So the same anchor as an app link
 * (audit A-2, #124) applies here: the user vouches once, and the grant is pinned
 * to the certificate the app carries *at that moment*, so it does not transfer
 * if the package is later re-signed by someone else.
 *
 * This is weaker than a published fingerprint — it trusts a human's judgement
 * about what they installed — and it is offered rather than assumed: nothing is
 * trusted until the user says so.
 */
class TrustedBrowsers(private val context: Context) {

    private val prefs by lazy {
        com.vela.android.sync.EncryptedPrefs.open(context, "vela_trusted_browsers")
    }

    /** Packages the user has trusted, each with the fingerprint pinned at the time. */
    fun pinned(): Map<String, String> =
        prefs.all.entries
            .mapNotNull { (key, value) -> (value as? String)?.let { key to it } }
            .toMap()

    /**
     * Whether [packageName] is user-trusted *and* still signed with the key it
     * had when trusted.
     */
    fun isTrusted(packageName: String): Boolean {
        val pinned = prefs.getString(packageName.lowercase(Locale.US), null) ?: return false
        return AppSignatures.sha256(context, packageName)
            .any { AppSignatures.normalize(it) == pinned }
    }

    /**
     * Trust [packageName], pinning whatever it is signed with right now.
     *
     * Returns false when the app has no readable signature — trusting something
     * we cannot identify would record a grant on the package name alone, which
     * is the thing this whole area exists to avoid.
     */
    fun trust(packageName: String): Boolean {
        val fingerprint = AppSignatures.sha256(context, packageName)
            .firstNotNullOfOrNull { AppSignatures.normalize(it) } ?: return false
        prefs.edit().putString(packageName.lowercase(Locale.US), fingerprint).apply()
        return true
    }

    fun revoke(packageName: String) {
        prefs.edit().remove(packageName.lowercase(Locale.US)).apply()
    }

    companion object {
        /**
         * Browsers installed on this device.
         *
         * Asking the package manager who would handle an `https://` VIEW intent
         * is how Android itself decides what a browser is — far better than
         * matching names, and it cannot be gamed by calling yourself
         * "com.something.browser".
         */
        fun installedBrowsers(context: Context): List<InstalledApps.Entry> {
            val pm = context.packageManager
            val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"))
            return runCatching {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(probe, PackageManager.MATCH_ALL)
            }
                .getOrDefault(emptyList())
                .mapNotNull { it.activityInfo?.packageName }
                .distinct()
                .filter { it != context.packageName }
                .map { InstalledApps.describe(context, it) }
                .sortedBy { it.label.lowercase(Locale.US) }
        }
    }
}
