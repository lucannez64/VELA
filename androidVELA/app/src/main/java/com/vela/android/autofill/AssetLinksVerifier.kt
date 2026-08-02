package com.vela.android.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import com.vela.android.sync.EncryptedPrefs
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import org.json.JSONArray

/**
 * Digital Asset Links: asks the *site* which app may receive its credentials.
 *
 * `https://<domain>/.well-known/assetlinks.json` lists packages under the
 * `delegate_permission/common.get_login_creds` relation, each with the SHA-256
 * fingerprints of its signing certificates. Checking the fingerprint is the
 * point: a package name alone is squattable on a third-party store, a signing
 * key is not. It is the same mechanism Android requires for passkeys.
 *
 * A site that publishes nothing is not evidence either way — the user can still
 * link the app by hand ([AppAssociations]) — so a negative answer narrows
 * suggestions rather than blocking anything.
 *
 * **[verify] never blocks.** `onFillRequest` runs on the main thread, so a
 * lookup that is not already cached returns `false` and schedules the fetch in
 * the background; the answer is there for the next request. Autofill requests
 * repeat as the user types, so "correct a moment later" is a good trade for
 * never stalling the keyboard.
 */
class AssetLinksVerifier(private val context: Context) {

    // Cached answers steer where credentials may go, so they live in the same
    // Keystore-backed store as everything else rather than plain preferences.
    private val prefs by lazy { EncryptedPrefs.open(context, "vela_asset_links") }
    private val inFlight = ConcurrentHashMap.newKeySet<String>()
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "vela-assetlinks").apply { isDaemon = true }
    }

    /**
     * Whether `domain` vouches for `packageName`, from cache only. Schedules a
     * background refresh when the cached answer is missing or stale.
     */
    fun verify(domain: String, packageName: String): Boolean {
        val host = AutofillMatcher.hostOf(domain) ?: return false
        val key = cacheKey(host, packageName)
        val cached = cached(key)
        if (cached == null) refreshInBackground(host, packageName, key)
        return cached ?: false
    }

    private fun refreshInBackground(domain: String, packageName: String, key: String) {
        if (!inFlight.add(key)) return
        executor.execute {
            try {
                val fingerprints = signingFingerprints(packageName)
                val verified = fingerprints.isNotEmpty() &&
                    runCatching { fetchAndCheck(domain, packageName, fingerprints) }
                        .onFailure { Log.d(TAG, "asset link lookup failed") }
                        .getOrDefault(false)
                prefs.edit()
                    .putBoolean(key, verified)
                    .putLong(key + TIMESTAMP_SUFFIX, System.currentTimeMillis())
                    .apply()
            } finally {
                inFlight.remove(key)
            }
        }
    }

    private fun cached(key: String): Boolean? {
        if (!prefs.contains(key)) return null
        val answer = prefs.getBoolean(key, false)
        val storedAt = prefs.getLong(key + TIMESTAMP_SUFFIX, 0)
        val ttl = if (answer) POSITIVE_TTL_MS else NEGATIVE_TTL_MS
        if (System.currentTimeMillis() - storedAt > ttl) return null
        return answer
    }

    private fun fetchAndCheck(
        domain: String,
        packageName: String,
        fingerprints: Set<String>
    ): Boolean {
        // https only, and no redirects: this decides who receives credentials,
        // so neither the network nor an off-origin hop may answer for the site.
        val connection = (
            URL("https://$domain/.well-known/assetlinks.json").openConnection() as HttpURLConnection
            ).apply {
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            instanceFollowRedirects = false
            requestMethod = "GET"
        }
        try {
            if (connection.responseCode != 200) return false
            val body = connection.inputStream.bufferedReader().use { reader ->
                reader.readAtMost(MAX_BODY_CHARS)
            }
            return statementGrantsLogin(body, packageName, fingerprints)
        } finally {
            connection.disconnect()
        }
    }

    /** SHA-256 of every certificate the installed [packageName] is signed with. */
    private fun signingFingerprints(packageName: String): Set<String> = runCatching {
        val pm = context.packageManager
        val signatures: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signing = pm.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            ).signingInfo
            when {
                signing == null -> emptyArray()
                // Rotated keys count: the app is still the one the site named.
                signing.hasMultipleSigners() -> signing.apkContentsSigners ?: emptyArray()
                else -> signing.signingCertificateHistory ?: emptyArray()
            }
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures ?: emptyArray()
        }

        signatures.map { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString(":") { byte -> "%02X".format(byte) }
        }.toSet()
    }.getOrDefault(emptySet())

    private fun cacheKey(domain: String, packageName: String) =
        "dal:" + domain.lowercase(Locale.US) + ":" + packageName.lowercase(Locale.US)

    companion object {
        private const val TAG = "AssetLinksVerifier"
        private const val LOGIN_CREDS_RELATION = "delegate_permission/common.get_login_creds"
        private const val TIMEOUT_MS = 5_000
        private const val TIMESTAMP_SUFFIX = ":at"
        private const val MAX_BODY_CHARS = 256 * 1024

        /**
         * A positive answer is a deliberate statement by the site; a negative one
         * is often just "not published yet", so it is retried sooner.
         */
        private const val POSITIVE_TTL_MS = 30L * 24 * 60 * 60 * 1000
        private const val NEGATIVE_TTL_MS = 24L * 60 * 60 * 1000

        /**
         * Whether an `assetlinks.json` body grants login credentials to
         * [packageName] signed by one of [fingerprints].
         *
         * Kept pure and separate from the fetch so the rule can be tested directly.
         */
        internal fun statementGrantsLogin(
            json: String,
            packageName: String,
            fingerprints: Set<String>
        ): Boolean {
            if (fingerprints.isEmpty()) return false
            val ours = fingerprints.mapNotNull { it.normalizedFingerprint() }.toSet()
            val statements = runCatching { JSONArray(json) }.getOrNull() ?: return false

            for (index in 0 until statements.length()) {
                val statement = statements.optJSONObject(index) ?: continue

                val relations = statement.optJSONArray("relation") ?: continue
                val grantsLogin = (0 until relations.length()).any {
                    relations.optString(it) == LOGIN_CREDS_RELATION
                }
                if (!grantsLogin) continue

                val target = statement.optJSONObject("target") ?: continue
                if (target.optString("namespace") != "android_app") continue
                if (!target.optString("package_name").equals(packageName, ignoreCase = true)) continue

                val listed = target.optJSONArray("sha256_cert_fingerprints") ?: continue
                val theirs = (0 until listed.length())
                    .mapNotNull { listed.optString(it).normalizedFingerprint() }
                    .toSet()
                // The package must match *and* be signed by a key the site named.
                if (theirs.intersect(ours).isNotEmpty()) return true
            }
            return false
        }

        /** `AB:CD:…` uppercase, however the site chose to write it. */
        private fun String.normalizedFingerprint(): String? =
            trim().uppercase(Locale.US).replace(" ", "").takeIf { it.isNotEmpty() }

        /** Reads at most [limit] chars, so a hostile server cannot stream forever. */
        private fun java.io.Reader.readAtMost(limit: Int): String {
            val out = StringBuilder()
            val buffer = CharArray(8 * 1024)
            while (out.length < limit) {
                val count = read(buffer, 0, minOf(buffer.size, limit - out.length))
                if (count < 0) break
                out.appendRange(buffer, 0, count)
            }
            return out.toString()
        }
    }
}
