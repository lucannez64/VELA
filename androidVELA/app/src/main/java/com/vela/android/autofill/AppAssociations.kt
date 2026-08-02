package com.vela.android.autofill

import java.util.Locale

/**
 * Deciding which saved login belongs to an Android app.
 *
 * A package name cannot be turned into a domain by rule. `com.ubercab` is not
 * `ubercab.com`, `com.zhiliaoapp.musically` is TikTok, and — the part that
 * matters — anyone can publish `com.paypal.anything` to a third-party store and
 * be offered PayPal credentials (audit A-2). No password manager infers this;
 * they use, in order of strength:
 *
 *  1. **Digital Asset Links** — the site itself names the package *and its
 *     signing certificate*. See [AssetLinksVerifier]. Strongest, needs network.
 *  2. **An explicit association the user confirmed**, stored on the item as
 *     `androidapp://<package>`. Offline, and the user is the trust anchor.
 *  3. **A curated list** for well-known apps, as a convenience for the long tail
 *     where neither of the above has happened yet.
 *
 * The old `com.<x>` → `<x>.com` fallback is gone; matching nothing is the
 * correct answer for an app nobody has vouched for.
 *
 * Browsers are a separate question — they claim a *site* rather than being one —
 * and live in [BrowserAllowlist].
 */
object AppAssociations {

    /**
     * `androidapp://com.example` — the URI form stored on a vault item, with an
     * optional `?cert=<SHA-256>` pinning the app's signing certificate.
     *
     * A link is the user saying "this app may have this password". Without a
     * fingerprint that grant rides on the package name, which survives an app
     * changing hands or being rebuilt by someone else; with one, it is the same
     * check asset links and the browser allowlist make. Both forms are kept
     * because pinning is not always right: the same app signed by F-Droid and by
     * Play has different keys, and a user who switches builds should not silently
     * lose autofill. Unpinned is the older format, so it must keep working
     * forever regardless.
     */
    const val ANDROID_APP_SCHEME = "androidapp://"

    private const val CERT_PARAM = "?cert="

    fun appUri(packageName: String, certFingerprint: String? = null): String {
        val base = ANDROID_APP_SCHEME + packageName.lowercase(Locale.US)
        val cert = certFingerprint?.let { AppSignatures.normalize(it) } ?: return base
        return base + CERT_PARAM + cert
    }

    fun packageFromUri(uri: String): String? =
        uri.takeIf { it.startsWith(ANDROID_APP_SCHEME, ignoreCase = true) }
            ?.substring(ANDROID_APP_SCHEME.length)
            ?.substringBefore('?')
            ?.lowercase(Locale.US)
            ?.takeIf { it.isNotBlank() }

    /** The pinned signing certificate, or null for a link that trusts the name alone. */
    fun certFromUri(uri: String): String? =
        uri.takeIf { it.startsWith(ANDROID_APP_SCHEME, ignoreCase = true) }
            ?.substringAfter(CERT_PARAM, "")
            ?.takeIf { it.isNotBlank() }
            ?.let { AppSignatures.normalize(it) }

    /**
     * Well-known app → site pairs, as data rather than a branch in a repository.
     *
     * A convenience only: every entry here could equally be established by the
     * user linking the app once. Entries must be verified by hand — this list is
     * a trust statement, not a guess.
     */
    private val CURATED_DOMAINS = mapOf(
        "com.instagram.android" to "instagram.com",
        "com.zhiliaoapp.musically" to "tiktok.com",
        "com.whatsapp" to "whatsapp.com",
        "com.facebook.orca" to "facebook.com",
        "com.facebook.katana" to "facebook.com",
        "com.snapchat.android" to "snapchat.com",
        "com.linkedin.android" to "linkedin.com",
        "com.pinterest" to "pinterest.com",
        "com.reddit.frontpage" to "reddit.com",
        "com.spotify.music" to "spotify.com",
        "com.netflix.mediaclient" to "netflix.com",
        "com.amazon.mShop.android.shopping" to "amazon.com",
        "com.paypal.android.p2pmobile" to "paypal.com",
        "com.ubercab" to "uber.com",
        "com.airbnb.android" to "airbnb.com",
        "com.discord" to "discord.com",
        "com.twitch.android.app" to "twitch.tv",
        "com.ebay.mobile" to "ebay.com",
        "com.dropbox.android" to "dropbox.com",
        "com.slack" to "slack.com",
        "com.skype.raider" to "skype.com",
        "com.vkontakte.android" to "vk.com",
        "org.telegram.messenger" to "telegram.org",
    )

    fun curatedDomain(packageName: String?): String? =
        packageName?.lowercase(Locale.US)?.let { CURATED_DOMAINS[it] }
}
