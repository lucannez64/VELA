package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression for the hostile-401 baseline reset.
 *
 * The production auth paths call [bindVerifiedUserId] before persisting the
 * server's user id or returning a token. These tests exercise that same
 * function rather than a duplicate test-only policy.
 */
class IdentityBindingTest {
    @Test
    fun initialRegistrationMayEstablishTheFirstPin() {
        assertEquals("alice", bindVerifiedUserId(IdentityBindingMode.INITIAL, null, "alice"))
        // A surrounding flow that already knows the account (recovery) may
        // confirm the same pin but not replace it.
        assertEquals("alice", bindVerifiedUserId(IdentityBindingMode.INITIAL, "alice", "alice"))
    }

    @Test
    fun explicitInitialEnrollmentCannotReplaceADifferentPin() {
        val error = assertThrows(IdentityBindingException::class.java) {
            bindVerifiedUserId(IdentityBindingMode.INITIAL, "alice", "mallory")
        }
        assertTrue(error.message!!.contains("different account"))
    }

    @Test
    fun automaticReauthRequiresAnExistingPin() {
        val error = assertThrows(IdentityBindingException::class.java) {
            bindVerifiedUserId(IdentityBindingMode.EXISTING, null, "alice")
        }
        assertTrue(error.message!!.contains("not bound"))
    }

    @Test
    fun automaticReauthMayOnlyConfirmThePinnedAccount() {
        assertEquals("alice", bindVerifiedUserId(IdentityBindingMode.EXISTING, "alice", "alice"))
        val error = assertThrows(IdentityBindingException::class.java) {
            bindVerifiedUserId(IdentityBindingMode.EXISTING, "alice", "mallory")
        }
        assertTrue(error.message!!.contains("different account"))
    }

    @Test
    fun hostile401WithChangedUserIdLeavesPinAndBaselinesUntouched() {
        // Models the production re-auth ordering: validate, then (only on
        // success) persist the identity/baseline-visible state. The failure
        // path must not reach either write.
        var storedUserId: String? = "alice"
        val baselineContext = syncBaselineScope("https://vault.example", storedUserId, 1).key
        val baselines = mapOf(baselineContext to mapOf("vault-data-000000" to 20L))
        var admittedBaseline: Long? = baselines.getValue(baselineContext)["vault-data-000000"]

        val reauthenticate = { verifiedUserId: String ->
            val pinned = bindVerifiedUserId(
                IdentityBindingMode.EXISTING, storedUserId, verifiedUserId)
            storedUserId = pinned
            // A successful re-auth may touch the token, but the baselines are
            // keyed by the unchanged pin.
            admittedBaseline = baselines.getValue(
                syncBaselineScope("https://vault.example", pinned, 1).key
            )["vault-data-000000"]
        }

        assertThrows(IdentityBindingException::class.java) { reauthenticate("mallory") }

        assertEquals("alice", storedUserId)
        assertEquals(20L, admittedBaseline)
        assertEquals(
            baselineContext,
            syncBaselineScope("https://vault.example", storedUserId, 1).key,
        )
    }
}
