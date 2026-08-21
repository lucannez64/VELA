package com.vela.android.autofill

import android.content.Context
import android.util.Log
import com.vela.android.sync.EncryptedPrefs
import java.net.HttpURLConnection
import java.net.URL
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
                val fingerprints = AppSignatures.sha256(context, packageName)
                // null = could not determine (network failure). A failed lookup
                // must not be persisted as a "no": that would let a momentary
                // disruption — or an attacker who can cause one — suppress DAL
                // matching for a legitimate pairing for a full TTL. Only
                // well-formed HTTP answers, including non-200s, are cached.
                val answer: Boolean? =
                    if (fingerprints.isEmpty()) false
                    else runCatching { fetchAndCheck(domain, packageName, fingerprints) }
                        .onFailure { Log.d(TAG, "asset link lookup failed") }
                        .getOrNull()
                if (answer != null) {
                    prefs.edit()
                        .putBoolean(key, answer)
                        .putLong(key + TIMESTAMP_SUFFIX, System.currentTimeMillis())
                        .apply()
                }
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
            val ours = fingerprints.mapNotNull { AppSignatures.normalize(it) }.toSet()
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
                    .mapNotNull { AppSignatures.normalize(listed.optString(it)) }
                    .toSet()
                // The package must match *and* be signed by a key the site named.
                if (theirs.intersect(ours).isNotEmpty()) return true
            }
            return false
        }

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
