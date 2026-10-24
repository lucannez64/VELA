package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AuthenticationReplacementTest {
    private val original = ServerIdentity("alice", "device-a", "ek-a", "vk-a", sealedB64 = "sealed-a")
    private val replacement = ServerIdentity("bob", "device-b", "ek-b", "vk-b", sealedB64 = "sealed-b")

    @Test
    fun authResponseCannotOverwriteAReplacementOrRecreateAMissingRecord() {
        for (register in listOf(false, true)) for (missing in listOf(false, true)) {
            val snapshot = if (register) original.copy(userId = null, deviceId = null) else original
            var stored: ServerIdentity? = snapshot
            val authenticator = AccountAuthenticator(
                loadIdentity = { stored }, getOrCreateIdentity = { snapshot },
                saveIdentity = { error("must not recreate identity") },
                updateIdentity = { transform -> stored?.let { transform(it).also { stored = it } } },
                signChallenge = { _, _ -> "signature" },
                registerAccount = {
                    stored = if (missing) null else replacement
                    RegisterAccountResponse(userId = "alice", deviceId = "registered", token = "token")
                },
                getChallenge = { ChallengeResponse("challenge") },
                verifySignature = { _, _, _ ->
                    stored = if (missing) null else replacement
                    VerifyResponse(token = "token", userId = "alice")
                },
                updateKeyEpoch = { error("stale registration must not update epoch") },
            )
            assertThrows(IdentityBindingException::class.java) {
                authenticator.authenticate(if (register) IdentityBindingMode.INITIAL else IdentityBindingMode.EXISTING)
            }
            assertEquals(if (missing) null else replacement, stored)
        }
    }

    @Test
    fun recoveryResponseCannotOverwriteAReplacementIdentity() {
        var stored = original
        val binder = RecoveryAccountBinder(
            loadOrCreateIdentity = { stored },
            enrollDevice = { _, _ -> stored = replacement; "new-device" },
            updateIdentity = { transform -> transform(stored).also { stored = it } },
        )
        assertThrows(IdentityBindingException::class.java) { binder.bind("alice", null) }
        assertEquals(replacement, stored)
    }

    @Test
    fun metadataOnlyRotationIsPreservedByTheSnapshotGuard() {
        requireUnchangedAuthenticationIdentity(original, original.copy(shareEkRegistrationPending = true))
    }
}
