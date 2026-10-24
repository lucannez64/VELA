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
