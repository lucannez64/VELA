package com.vela.android.core

/** Passwords shorter than this are reported as needing attention. */
const val MIN_HEALTHY_PASSWORD_LENGTH = 12

/**
 * Logins the overview and the Attention filter call out: missing or short
 * passwords, and passwords shared by more than one account.
 *
 * This is a local, explainable heuristic — not a breach check. Breach results
 * come from the dedicated monitor, which needs a network round trip.
 */
fun List<VaultItem>.accountsNeedingAttention(): Set<String> {
    val logins = filterIsInstance<VaultItem.Login>()
    val reused = logins.filter { it.password.isNotBlank() }
        .groupBy { it.password }
        .filterValues { it.size > 1 }
        .keys
    return logins
        .filter { it.password.isBlank() || it.password.length < MIN_HEALTHY_PASSWORD_LENGTH || it.password in reused }
        .map { it.id }
        .toSet()
}
