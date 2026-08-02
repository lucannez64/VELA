package com.vela.android.autofill

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * One-time tokens that prove an "unlock then fill" intent really came from
 * [VelaAutofillService].
 *
 * `MainActivity` is the launcher, so it is necessarily `exported="true"` and any
 * app on the device can start it with whatever extras it likes. Without a proof
 * of origin, a malicious app could hand it a set of [android.view.autofill.AutofillId]s
 * and receive a `FillResponse` containing plaintext credentials (audit A-1).
 * Caller identity does not help here: the Autofill framework launches our
 * `PendingIntent` from the *filled app's* process, so `getCallingPackage()` is
 * attacker-influenced.
 *
 * So the service mints a token per locked response and only it knows the value;
 * the activity redeems it exactly once. The store is in-memory: if the process
 * died between issuing and redeeming, the redemption fails and the flow falls
 * back to a plain unlock, which is the safe direction.
 */
object AutofillUnlockTokens {
    /** Tokens outlive a user tapping "Unlock VELA", nothing more. */
    private const val TTL_MILLIS = 5 * 60 * 1000L

    /** Bounds memory if responses are built but never used (the common case). */
    private const val MAX_OUTSTANDING = 8

    private val random = SecureRandom()
    private val outstanding = LinkedHashMap<String, Long>()

    /** Mint a token for one locked `FillResponse`. */
    @Synchronized
    fun issue(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        val token = Base64.encodeToString(bytes, Base64.NO_WRAP)
        prune()
        while (outstanding.size >= MAX_OUTSTANDING) {
            val oldest = outstanding.keys.firstOrNull() ?: break
            outstanding.remove(oldest)
        }
        outstanding[token] = System.currentTimeMillis() + TTL_MILLIS
        return token
    }

    /**
     * Redeem a token. Returns true only for a token this process issued, which
     * has not expired and has not been redeemed before.
     */
    @Synchronized
    fun redeem(token: String?): Boolean {
        prune()
        if (token == null) return false
        // Compare against every outstanding token in constant time, so a caller
        // cannot learn a valid prefix from how long the check takes.
        val presented = token.toByteArray(Charsets.UTF_8)
        var matched: String? = null
        for (candidate in outstanding.keys) {
            if (constantTimeEquals(candidate.toByteArray(Charsets.UTF_8), presented)) {
                matched = candidate
            }
        }
        return matched?.let { outstanding.remove(it) != null } ?: false
    }

    private fun prune() {
        val now = System.currentTimeMillis()
        outstanding.entries.removeAll { it.value <= now }
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean =
        MessageDigest.isEqual(a, b)
}
