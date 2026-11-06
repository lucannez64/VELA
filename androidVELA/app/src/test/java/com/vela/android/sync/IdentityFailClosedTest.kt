package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Fail-closed identity/baseline regressions (R5 F3/F5).
 *
 * A durable bearer token must never be usable with an unknown or corrupt
 * account pin: the old code mapped a missing pin to the empty-account baseline
 * namespace, which is a fresh floor set and therefore silently bypasses
 * rollback protection. The identity record now commits synchronously and its
 * targeted updates are serialized.
 */
class IdentityFailClosedTest {
    private val server = "https://vault.example"
    private val chunk = "vault-data-000000"

    @Test
    fun baselineScopeNeverUsesAnEmptyAccountNamespace() {
        assertThrows(IdentityBindingException::class.java) {
            syncBaselineScope(server, null, 1)
        }
        assertThrows(IdentityBindingException::class.java) {
            syncBaselineScope(server, "", 1)
        }
        assertThrows(IdentityBindingException::class.java) {
            syncBaselineScope(server, "   ", 1)
        }
        assertEquals(
            syncBaselineScope(server, "alice", 1).key,
            syncBaselineScope(server, " alice ", 1).key,
        )
    }

    @Test
    fun durableTokenWithoutAReadablePinIsRejectedBeforeBaselineUse() {
        val error = assertThrows(IdentityBindingException::class.java) {
            requireSyncBaselineAccount(hasDurableToken = true, pinnedUserId = null)
        }
        assertTrue(error.message!!.contains("stored sync token"))
        assertThrows(IdentityBindingException::class.java) {
            requireSyncBaselineAccount(hasDurableToken = true, pinnedUserId = "  ")
        }

        // A blank token is the deliberate fresh-install registration flow: no
        // account exists yet, and INITIAL may create the first pin.
        assertNull(requireSyncBaselineAccount(hasDurableToken = false, pinnedUserId = null))
        assertEquals("alice", requireSyncBaselineAccount(true, " alice "))
    }

    @Test
    fun corruptIdentityRecordDecodesAsNoPinNotAnEmptyAccount() {
        assertNull(ServerIdentityJson.decode(null))
        assertNull(ServerIdentityJson.decode(""))
        assertNull(ServerIdentityJson.decode("not json"))
        assertNull(ServerIdentityJson.decode("""{"user_id":"alice"}"""))
        assertNull(ServerIdentityJson.decode("""{"hybrid_ek_b64":"ek"}"""))

        val roundTrip = ServerIdentityJson.decode(
            ServerIdentityJson.encode(ServerIdentity(
                userId = "alice",
                deviceId = "device-alice",
                hybridEkB64 = "ek",
                hybridVkB64 = "vk",
                sealedB64 = "sealed",
            ))
        )!!
        assertEquals("alice", roundTrip.userId)
    }

    @Test
    fun identityRecordUpdateIsSerializedAndCannotLoseAConcurrentRotation() {
        val initial = ServerIdentity(
            userId = "alice",
            deviceId = "device-alice",
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            sealedB64 = "sealed",
            shareEkB64 = "",
        )
        var raw: String? = ServerIdentityJson.encode(initial)
        val record = SerializedIdentityRecord({ raw }, { raw = it })
        val writers = 8
        val iterations = 25
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(writers)
        try {
            val futures = (0 until writers).map { writer ->
                pool.submit {
                    start.await()
                    repeat(iterations) {
                        record.update { current ->
                            current.copy(shareEkB64 = current.shareEkB64 + writer)
                        }
                    }
                }
            }
            start.countDown()
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        val final = record.load()!!
        assertEquals(writers * iterations, final.shareEkB64.length)
        // A lost read-modify-write would resurrect an older pin or leave an
        // older share key, both of which the pin check treats as meaningful.
        assertEquals("alice", final.userId)
        assertEquals("device-alice", final.deviceId)
    }

    @Test
    fun failedIdentityWriteFailsBeforeATokenCanBeReturned() {
        var raw: String? = ServerIdentityJson.encode(ServerIdentity(
            userId = null,
            deviceId = "device-alice",
            hybridEkB64 = "ek",
            hybridVkB64 = "vk",
            sealedB64 = "sealed",
        ))
        val record = SerializedIdentityRecord({ raw }, { throw IOException("disk full") })
        assertThrows(IOException::class.java) {
            record.update { it.copy(userId = "alice") }
        }
        // Nothing durable changed, so the caller cannot return a token that
        // outlives the pin write.
        assertEquals(null, ServerIdentityJson.decode(raw)!!.userId)

        val authenticator = AccountAuthenticator(
            loadIdentity = { ServerIdentityJson.decode(raw) },
            getOrCreateIdentity = { ServerIdentityJson.decode(raw)!! },
            saveIdentity = { error("must not fall back") },
            updateIdentity = { transform -> record.update(transform) },
            signChallenge = { _, _ -> "signature" },
            registerAccount = { error("already registered") },
            getChallenge = { ChallengeResponse("challenge") },
            verifySignature = { _, _, _ -> VerifyResponse(token = "token", userId = "alice") },
            updateKeyEpoch = { error("must not change the epoch") },
        )

        assertThrows(IOException::class.java) {
            authenticator.authenticate(IdentityBindingMode.INITIAL)
        }
    }

    @Test
    fun automaticReauthWithAnEmptyPinFailsBeforeAnyRequest() {
        var requests = 0
        val authenticator = AccountAuthenticator(
            loadIdentity = {
                ServerIdentity(
                    userId = null,
                    deviceId = "device-alice",
                    hybridEkB64 = "ek",
                    hybridVkB64 = "vk",
                    sealedB64 = "sealed",
                )
            },
            getOrCreateIdentity = { error("EXISTING must never create an identity") },
            saveIdentity = { error("must not save") },
            updateIdentity = { error("must not update") },
            signChallenge = { _, _ -> requests++; error("must not sign") },
            registerAccount = { error("must not register") },
            getChallenge = { requests++; error("must not request a challenge") },
            verifySignature = { _, _, _ -> requests++; error("must not verify") },
            updateKeyEpoch = { error("must not change the epoch") },
        )

        val error = assertThrows(IdentityBindingException::class.java) {
            authenticator.authenticate(IdentityBindingMode.EXISTING)
        }
        assertTrue(error.message!!.contains("no stored account pin"))
        assertEquals(0, requests)
    }

    @Test
    fun durableTokenAndCorruptIdentityLeaveStoredBaselinesUntouched() {
        val scope = syncBaselineScope(server, "alice", 1)
        val state = SyncSettingsState(
            SyncSettings(
                serverUrl = server,
                bearerToken = "durable-token",
                seenLamportByContext = mapOf(scope.key to mapOf(chunk to 12L)),
            )
        ) { it }

        // `ServerIdentityStore.load()` returns null for corrupt JSON, which is
        // exactly this input to the pre-request gate.
        val error = assertThrows(IdentityBindingException::class.java) {
            requireSyncBaselineAccount(
                state.settings.value.bearerToken.isNotBlank(),
                ServerIdentityJson.decode("corrupt")?.userId,
            )
        }
        assertTrue(error.message!!.contains("stored sync token"))
        assertEquals("durable-token", state.settings.value.bearerToken)
        assertEquals(12L, state.settings.value.seenLamportByContext.getValue(scope.key).getValue(chunk))
    }
}
