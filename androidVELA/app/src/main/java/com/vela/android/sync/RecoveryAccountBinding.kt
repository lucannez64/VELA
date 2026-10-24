package com.vela.android.sync

/**
 * Production account-recovery binding order.
 *
 * Recovery is an explicit [IdentityBindingMode.INITIAL] flow: on a fresh
 * device it may create the first pin. It must not, however, replace a
 * different pin that is already stored. The previous code saved the
 * caller-supplied user id before `/auth/verify` re-validated it, so a
 * recovery attempt for another account replaced the local pin and only then
 * failed the pin check — leaving new state behind.
 *
 * This helper validates the target against the existing pin **before** the
 * device-enrollment request and before any local write. A genuinely different
 * account requires an explicit local reset first.
 */
internal class RecoveryAccountBinder(
    private val loadOrCreateIdentity: () -> ServerIdentity,
    private val enrollDevice: (ServerIdentity, String?) -> String,
    private val updateIdentity: ((ServerIdentity) -> ServerIdentity) -> ServerIdentity?,
) {
    fun bind(callerUserId: String, deviceName: String?): ServerIdentity {
        val targetUserId = callerUserId.trim()
        if (targetUserId.isEmpty()) {
            throw IdentityBindingException(
                "Recovery requires a non-empty account id; no identity or pin was changed."
            )
        }
        val identity = loadOrCreateIdentity()
        // Throws for a different existing pin, before the server is asked to
        // enroll this device and before any local write.
        val pinnedUserId = bindVerifiedUserId(
            IdentityBindingMode.INITIAL,
            identity.userId,
            targetUserId,
        )
        val deviceId = enrollDevice(identity, deviceName)
        return updateIdentity { current ->
            current.copy(userId = pinnedUserId, deviceId = deviceId)
        } ?: throw IdentityBindingException(
            "This device's identity disappeared during recovery; its account pin was not " +
                "changed. Retry recovery."
        )
    }
}
