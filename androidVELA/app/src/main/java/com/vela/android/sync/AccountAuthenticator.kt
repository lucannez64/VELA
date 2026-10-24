package com.vela.android.sync

/**
 * The production account authentication state machine.
 *
 * This is deliberately a class with injected callbacks instead of anonymous
 * code in [VaultSyncManager]: the identity-pin decision is the security
 * boundary, and tests must exercise the real ordering (load/pin/validate,
 * register-or-verify, persist, return token) rather than a test-only lambda.
 *
 * Invariants:
 * - A deliberate [IdentityBindingMode.INITIAL] flow may establish a first pin
 *   but may not replace a different existing pin.
 * - [IdentityBindingMode.EXISTING] requires a stored pin and never calls
 *   `getOrCreate`; it cannot create an account binding.
 * - The verified user id is validated *before* the identity record is
 *   updated and before the token is returned. A mismatch throws with the
 *   persisted record unchanged, so a caller cannot commit a token derived
 *   from another account.
 */
internal class AccountAuthenticator(
    private val loadIdentity: () -> ServerIdentity?,
    private val getOrCreateIdentity: () -> ServerIdentity,
    private val saveIdentity: (ServerIdentity) -> Unit,
    private val updateIdentity: ((ServerIdentity) -> ServerIdentity) -> ServerIdentity?,
    private val signChallenge: (deviceId: String, challengeB64: String) -> String,
    private val registerAccount: (ServerIdentity) -> RegisterAccountResponse,
    private val getChallenge: () -> ChallengeResponse,
    private val verifySignature: (deviceId: String, challengeB64: String, signature: String) -> VerifyResponse,
    private val updateKeyEpoch: (Long) -> Unit,
) {
    /**
     * Register or re-authenticate this device. Returns only a token whose
     * account id was validated against the local pin.
     */
    fun authenticate(binding: IdentityBindingMode): String {
        var identity = if (binding == IdentityBindingMode.EXISTING) {
            val stored = loadIdentity() ?: throw IdentityBindingException(
                "This device has no stored identity, so it cannot re-authenticate " +
                    "automatically. Enroll or sign in again."
            )
            if (stored.userId.isNullOrBlank()) {
                // Re-authentication only ever confirms an existing account.
                // Without a readable pin there is nothing to confirm, and the
                // baseline namespace is unknown; do not even ask the server.
                throw IdentityBindingException(
                    "This device has no stored account pin, so it cannot re-authenticate " +
                        "automatically. Sign in or enroll again."
                )
            }
            stored
        } else {
            getOrCreateIdentity()
        }

        if (identity.deviceId.isNullOrBlank()) {
            if (binding == IdentityBindingMode.EXISTING) {
                throw IdentityBindingException(
                    "This device has no registered identity, so it cannot re-authenticate " +
                        "automatically. Enroll or sign in again."
                )
            }
            val registered = registerAccount(identity)
            val pinnedUserId = bindVerifiedUserId(binding, identity.userId, registered.userId)
            identity = updateIdentity { current ->
                requireUnchangedAuthenticationIdentity(identity, current)
                current.copy(userId = pinnedUserId, deviceId = registered.deviceId)
            } ?: throw IdentityBindingException("Identity disappeared during registration; token refused.")
            updateKeyEpoch(1)
            registered.token?.takeIf { it.isNotBlank() }?.let { return it }
        }

        val deviceId = identity.deviceId ?: error("Server identity has no device id")
        val challenge = getChallenge()
        // Signed natively through the handle in production — the signing key
        // never comes back across the boundary to be signed with here.
        val signature = signChallenge(deviceId, challenge.challengeB64)
        val verified = verifySignature(deviceId, challenge.challengeB64, signature)
        // Validate before saving the identity and before the caller can
        // persist the returned token. On a mismatch this throws with both
        // untouched.
        val pinnedUserId = bindVerifiedUserId(binding, identity.userId, verified.userId)
        updateIdentity { current ->
            requireUnchangedAuthenticationIdentity(identity, current)
            current.copy(userId = pinnedUserId)
        }
            ?: throw IdentityBindingException(
                "This device's identity disappeared while verifying its account pin; " +
                    "the token was not accepted. Sign in or enroll again."
            )
        return verified.token
    }

}
