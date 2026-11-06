package com.vela.android.sync

import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Focused regression for the identity-snapshot guard.
 *
 * `requireUnchangedAuthenticationIdentity` is re-checked inside the atomic
 * identity-record update, so a concurrent replacement cannot be overwritten by
 * an authentication response. The residual-coverage note asks for a
 * field-isolated refusal: changing *any one* authenticated field must refuse,
 * not just a whole-record replacement.
 *
 * The share-key fields are deliberately not part of that guard: a share-key
 * rotation is a separate targeted update and an auth response only writes
 * `userId` (or `userId`/`deviceId` on registration), so it cannot resurrect the
 * old share key.
 */
class IdentityRotationFieldIsolationTest {
    private val original = ServerIdentity(
        userId = "alice",
        deviceId = "device-a",
        hybridEkB64 = "ek-a",
        hybridVkB64 = "vk-a",
        shareEkB64 = "share-a",
        sealedB64 = "sealed-a",
    )

    @Test
    fun everyAuthenticatedIdentityFieldChangeIsRefusedInIsolation() {
        val isolatedChanges = mapOf(
            "userId" to original.copy(userId = "bob"),
            "userId removed" to original.copy(userId = null),
            "deviceId" to original.copy(deviceId = "device-b"),
            "deviceId removed" to original.copy(deviceId = null),
            "hybridEkB64" to original.copy(hybridEkB64 = "ek-b"),
            "hybridVkB64" to original.copy(hybridVkB64 = "vk-b"),
            "sealedB64" to original.copy(sealedB64 = "sealed-b"),
        )
        for ((field, changed) in isolatedChanges) {
            val error = assertThrows(
                "a concurrent change to $field was accepted",
                IdentityBindingException::class.java,
            ) {
                requireUnchangedAuthenticationIdentity(original, changed)
            }
            assertTrue(
                "the refusal for $field must name the changed identity",
                error.message!!.contains("changed during authentication"),
            )
        }
    }

    @Test
    fun shareKeyRotationAndRegistrationMetadataAreNotIdentityReplacement() {
        // Rotation/backfill updates the share key and its retry metadata in the
        // same record. That is not a replacement of this device's identity, and
        // the auth guard must not turn an unrelated share-key rotation into a
        // failed sign-in.
        requireUnchangedAuthenticationIdentity(original, original.copy(shareEkB64 = "share-b"))
        requireUnchangedAuthenticationIdentity(
            original,
            original.copy(shareEkRegistrationPending = true),
        )
        requireUnchangedAuthenticationIdentity(
            original,
            original.copy(
                shareEkSignedAt = "2026-01-01T00:00:00Z",
                shareEkSignature = "signature",
            ),
        )
    }
}
