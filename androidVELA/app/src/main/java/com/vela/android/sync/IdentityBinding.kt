package com.vela.android.sync

/**
 * How a successful `/account/register` or `/auth/verify` may bind the returned
 * account id to this device.
 *
 * The rollback baseline namespace includes the authenticated account id. If an
 * automatic re-authentication silently adopted a different id, every baseline
 * would move to a fresh namespace: old counters would be ignored, an archived
 * clock could be admitted again, and the user would lose rollback protection
 * without any local reset. The two modes make that distinction explicit:
 *
 * - [INITIAL] is chosen by a flow that deliberately establishes the account on
 *   this device (first registration, enrollment, recovery). It may pin an id
 *   that was not known before, but it still refuses to replace a different
 *   pin that is already stored.
 * - [EXISTING] is automatic re-authentication of an already-bound device. It
 *   requires a stored pin and only ever confirms that same id.
 */
internal enum class IdentityBindingMode {
    INITIAL,
    EXISTING,
}

/** A server-verified account id contradicts this device's persisted pin. */
internal class IdentityBindingException(message: String) : IllegalStateException(message)

/**
 * Validate the account id returned by the server before it is persisted or a
 * token derived from it is stored. This is deliberately pure so the production
 * auth paths and the regression tests share exactly the same decision.
 */
internal fun bindVerifiedUserId(
    mode: IdentityBindingMode,
    pinnedUserId: String?,
    verifiedUserId: String,
): String {
    val verified = verifiedUserId.trim()
    if (verified.isEmpty()) {
        throw IdentityBindingException(
            "The server returned an empty account id; refusing to change this device's " +
                "sync baseline namespace."
        )
    }
    val pinned = pinnedUserId?.trim()?.takeIf { it.isNotEmpty() }
    if (mode == IdentityBindingMode.EXISTING && pinned == null) {
        throw IdentityBindingException(
            "This device is not bound to an account, so it cannot re-authenticate " +
                "automatically. Sign in or enroll again."
        )
    }
    if (pinned != null && pinned != verified) {
        throw IdentityBindingException(
            "The server authenticated this device as a different account ($verified) than " +
                "the one stored locally ($pinned). Refusing to re-authenticate or move the " +
                "rollback baselines to the new account. Sign in again if the account really " +
                "changed."
        )
    }
    return verified
}

/**
 * The account component of a rollback baseline namespace.
 *
 * A missing pin is not "the empty account". Treating it as one would create a
 * fresh, empty namespace, so every previously recorded floor would be
 * bypassed — exactly the failure a durable token with a lost/corrupt identity
 * record would otherwise cause. Callers must fail closed and require an
 * explicit re-enrollment or local reset instead.
 */
internal fun requireBaselineAccountId(pinnedUserId: String?): String {
    val accountId = pinnedUserId?.trim().orEmpty()
    if (accountId.isEmpty()) {
        throw IdentityBindingException(
            "This device has no readable account pin, so its rollback baseline namespace " +
                "is unknown. Refusing to sync. Sign in or enroll again; if local " +
                "security state is corrupt, reset local security deliberately."
        )
    }
    return accountId
}

/**
 * Reject sync requests before any network call when a durable bearer token
 * exists but the identity record no longer yields an account id (corruption,
 * interrupted write, or a truncated migration).
 *
 * A blank token is allowed: that is the fresh-install path that deliberately
 * registers/enrolls and then pins the first account via
 * [IdentityBindingMode.INITIAL]. Automatic re-authentication is always
 * [IdentityBindingMode.EXISTING] and may never create a pin.
 */
internal fun requireSyncBaselineAccount(
    hasDurableToken: Boolean,
    pinnedUserId: String?,
): String? {
    val accountId = pinnedUserId?.trim()?.takeIf { it.isNotEmpty() }
    if (hasDurableToken && accountId == null) {
        throw IdentityBindingException(
            "This device has a stored sync token but no readable account pin. Refusing to " +
                "contact the server or use rollback baselines whose account context is " +
                "unknown. Sign in or enroll again; if local security state is corrupt, " +
                "reset local security deliberately."
        )
    }
    return accountId
}

/** Check under the identity-record monitor before applying an HTTP result. */
internal fun requireUnchangedAuthenticationIdentity(
    expected: ServerIdentity,
    current: ServerIdentity,
) {
    if (expected.userId != current.userId || expected.deviceId != current.deviceId ||
        expected.hybridEkB64 != current.hybridEkB64 ||
        expected.hybridVkB64 != current.hybridVkB64 || expected.sealedB64 != current.sealedB64) {
        throw IdentityBindingException(
            "This device's identity changed during authentication; the response was not accepted. Retry."
        )
    }
}
