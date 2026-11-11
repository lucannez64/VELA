package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regressions for R5 F5: recovery used to write the caller-supplied account id
 * to the identity record *before* `/auth/verify` re-checked it, so a recovery
 * for another account replaced a good pin and only then failed. The invariant
 * is "INITIAL may establish a first pin, never replace a different one".
 *
 * This drives [RecoveryAccountBinder], the production ordering helper used by
 * `VaultSyncManager.recoverAccount`, with in-memory identity/settings state.
 * It does not run the actual recovery network ceremony or native key combine.
 */
class RecoveryAccountBindingTest {
    private val server = "https://vault.example"
    private val chunk = "vault-data-000000"

    @Test
    fun differentExistingPinFailsBeforeEnrollmentAndLeavesStateUntouched() {
        var identity = ServerIdentity(
            userId = "alice",
            deviceId = "device-alice",
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            sealedB64 = "sealed",
        )
        var enrollments = 0
        var writes = 0
        val binder = RecoveryAccountBinder(
            loadOrCreateIdentity = { identity },
            enrollDevice = { _, _ -> enrollments++; "device-new" },
            updateIdentity = { transform ->
                writes++
                identity = transform(identity)
                identity
            },
        )
        val scope = syncBaselineScope(server, "alice", 1)
        val settings = SyncSettingsState(
            SyncSettings(
                serverUrl = server,
                bearerToken = "alice-token",
                seenLamportByContext = mapOf(scope.key to mapOf(chunk to 20L)),
            )
        ) { it }

        val error = assertThrows(IdentityBindingException::class.java) {
            binder.bind(callerUserId = "mallory", deviceName = "phone")
        }

        assertTrue(error.message!!.contains("different account"))
        assertEquals("the enrollment request must not run for a mismatched pin", 0, enrollments)
        assertEquals("no identity write may occur", 0, writes)
        assertEquals("alice", identity.userId)
        assertEquals("device-alice", identity.deviceId)
        assertEquals("alice-token", settings.settings.value.bearerToken)
        assertEquals(20L, settings.settings.value.seenLamportByContext.getValue(scope.key)[chunk])
        assertEquals(scope.key, syncBaselineScope(
            server, identity.userId, settings.settings.value.keyEpoch).key)
    }

    @Test
    fun firstRecoveryOnAFreshDeviceMayEstablishTheInitialPin() {
        var identity = ServerIdentity(
            userId = null,
            deviceId = null,
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            sealedB64 = "sealed",
        )
        var enrolledFor: String? = null
        val binder = RecoveryAccountBinder(
            loadOrCreateIdentity = { identity },
            enrollDevice = { current, name ->
                enrolledFor = "${current.hybridEkB64}:$name"
                "device-new"
            },
            updateIdentity = { transform ->
                identity = transform(identity)
                identity
            },
        )

        val bound = binder.bind(callerUserId = "alice", deviceName = "phone")

        assertEquals("ek:phone", enrolledFor)
        assertEquals("alice", bound.userId)
        assertEquals("device-new", bound.deviceId)
    }

    @Test
    fun samePinRecoveryUpdatesOnlyTheDeviceId() {
        var identity = ServerIdentity(
            userId = "alice",
            deviceId = "device-old",
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            sealedB64 = "sealed",
        )
        val binder = RecoveryAccountBinder(
            loadOrCreateIdentity = { identity },
            enrollDevice = { _, _ -> "device-new" },
            updateIdentity = { transform ->
                identity = transform(identity)
                identity
            },
        )

        val bound = binder.bind(callerUserId = "alice", deviceName = "phone")

        assertEquals("alice", bound.userId)
        assertEquals("device-new", bound.deviceId)
        assertEquals("ek", bound.hybridEkB64)
    }

    @Test
    fun emptyRecoveryAccountIsRejectedBeforeEnrollment() {
        var enrollments = 0
        var loads = 0
        val binder = RecoveryAccountBinder(
            loadOrCreateIdentity = {
                loads++
                ServerIdentity(
                    userId = "alice",
                    deviceId = "device-alice",
                    hybridEkB64 = "ek",
                    hybridVkB64 = "vk",
                )
            },
            enrollDevice = { _, _ -> enrollments++; "device-new" },
            updateIdentity = { error("must not write") },
        )

        assertThrows(IdentityBindingException::class.java) {
            binder.bind(callerUserId = "", deviceName = null)
        }
        assertEquals(0, loads)
        assertEquals(0, enrollments)
    }
}
