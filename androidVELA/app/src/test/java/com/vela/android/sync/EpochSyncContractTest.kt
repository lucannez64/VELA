package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class EpochSyncContractTest {
    @Test
    fun manifestParserRequiresAndPreservesEpoch() {
        val manifest = parseSyncManifest(
            """{"epoch":2,"chunks":[{"chunk_id":"vault-data-000000","version":3,"lamport_clock":4,"last_writer":null}]}"""
                .toByteArray()
        )
        assertEquals(2L, manifest.epoch)
        assertEquals(4L, manifest.chunks.single().lamportClock)

        assertEquals(1L, parseSyncManifest("""{"chunks":[]}""".toByteArray()).epoch)
        assertThrows(IllegalArgumentException::class.java) {
            parseSyncManifest("""{"epoch":0,"chunks":[]}""".toByteArray())
        }
    }

    @Test
    fun chunkMutationsAlwaysCarryPositiveEpochHeader() {
        assertEquals(mapOf("X-Vela-Epoch" to "2"), vaultEpochHeaders(2))
        assertThrows(IllegalArgumentException::class.java) { vaultEpochHeaders(0) }
    }

    @Test
    fun syncRequiresManifestAndLocalEpochToMatch() {
        requireMatchingSyncEpoch(2, 2)
        assertThrows(IllegalStateException::class.java) { requireMatchingSyncEpoch(2, 1) }
        assertThrows(IllegalStateException::class.java) { requireMatchingSyncEpoch(1, 2) }
        assertThrows(IllegalArgumentException::class.java) { requireMatchingSyncEpoch(0, 1) }
    }

    @Test
    fun perChunkBaselinesRoundTripAndNeverRegress() {
        val context = syncBaselineScope("https://vault.example", "account-a", 1).key
        val initial = mapOf(context to mapOf("vault-data-000000" to 4L))
        val encoded = encodeSeenLamportContexts(initial)
        assertEquals(initial, parseSeenLamportContexts(encoded))

        // A stale write must not lower the recorded revision.
        val merged = mergeSeenLamports(
            initial.getValue(context),
            mapOf("vault-data-000000" to 3L),
        )
        assertEquals(initial.getValue(context), merged)
        // A forward write advances it, and new chunks are recorded.
        val advanced = mergeSeenLamports(
            initial.getValue(context),
            mapOf("vault-data-000000" to 7L, "vault-data-000001" to 2L),
        )
        assertEquals(7L, advanced["vault-data-000000"])
        assertEquals(2L, advanced["vault-data-000001"])
    }

    @Test
    fun baselinesAreNamespacedByServerAccountAndEpoch() {
        val accountA = syncBaselineScope("https://vault.example/", "account-a", 1)
        // Same server, trailing slash and host case normalized away.
        val accountAAgain = syncBaselineScope("HTTPS://VAULT.EXAMPLE", "account-a", 1)
        assertEquals(accountA.key, accountAAgain.key)

        // A different account, epoch, or server is a different context: it
        // must not inherit another context's counter.
        val accountB = syncBaselineScope("https://vault.example", "account-b", 1)
        val adoptedEpoch = syncBaselineScope("https://vault.example", "account-a", 2)
        val otherServer = syncBaselineScope("https://other.example", "account-a", 1)
        for (other in listOf(accountB, adoptedEpoch, otherServer)) {
            assertNotEquals(accountA.key, other.key)
        }

        // Epoch adoption restarts the server's counters, so a fresh context is
        // first contact (null), not a rejection of the restarted clock.
        val byContext = mapOf(
            accountA.key to mapOf("vault-data-000000" to 9L),
            accountB.key to mapOf("vault-data-000000" to 2L),
        )
        val encoded = encodeSeenLamportContexts(byContext)
        val decoded = parseSeenLamportContexts(encoded)!!
        assertEquals(mapOf("vault-data-000000" to 9L), decoded[accountA.key])
        // Switching back preserves each account's own baseline.
        assertEquals(mapOf("vault-data-000000" to 2L), decoded[accountB.key])
        assertNull(decoded[adoptedEpoch.key])

        val manifest = encodeManifestLamports(mapOf(accountA.key to 9L))
        assertEquals(mapOf(accountA.key to 9L), parseManifestLamports(manifest))
    }

    @Test
    fun corruptBaselineFailsClosedInsteadOfResetting() {
        // Unreadable JSON, wrong shapes, and nonpositive revisions are all
        // corruption: `null` makes the sync refuse instead of silently
        // treating the file as an empty (fail-open) baseline.
        assertNull(parseSeenLamportContexts("not json"))
        assertNull(parseSeenLamportContexts("""["not","a","map"]"""))
        assertNull(parseSeenLamportContexts("""{"ctx":{"vault-data-000000":0}}"""))
        assertNull(parseSeenLamportContexts("""{"ctx":"not an object"}"""))
        assertNull(parseManifestLamports("""{"ctx":"high"}"""))
        assertNull(parseManifestLamports("""{"ctx":-1}"""))

        // Absent data is a fresh install, not corruption.
        assertEquals(emptyMap<String, Map<String, Long>>(), parseSeenLamportContexts(null))
        assertEquals(emptyMap<String, Map<String, Long>>(), parseSeenLamportContexts(""))
        assertEquals(emptyMap<String, Long>(), parseManifestLamports(""))
    }

    @Test
    fun concurrentTokenAndBaselineWritersNeverLoseUpdates() {
        // The old store computed `_settings.value.copy(...)` outside any lock
        // and persisted with `apply()`, so a token renewal and a baseline
        // commit could each start from the same snapshot: whichever apply
        // landed last resurrected the other's stale field. This models both
        // writers against the serialized cell and requires every update to
        // survive.
        val initial = SerializedProbeState("token-0", emptyMap())
        val cell = SerializedSettings(initial, persist = { it })
        val writers = 8
        val iterations = 200
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(writers)
        val futures = (0 until writers).map { writer ->
            pool.submit {
                start.await()
                repeat(iterations) { step ->
                    if (writer % 2 == 0) {
                        cell.update { it.copy(token = "token-${writer * iterations + step}") }
                    } else {
                        cell.update { current ->
                            current.copy(
                                baselines = mergeSeenLamports(
                                    current.baselines,
                                    mapOf("vault-data-${writer.toString().padStart(6, '0')}" to
                                        (step + 1).toLong()),
                                )
                            )
                        }
                    }
                }
            }
        }
        start.countDown()
        futures.forEach { it.get(60, TimeUnit.SECONDS) }
        pool.shutdown()

        val final = cell.current
        assertTrue(final.token.startsWith("token-"))
        // Every baseline writer's chunk is present at its final revision; a
        // lost update would leave one missing or behind.
        val baselineWriters = (0 until writers).filter { it % 2 == 1 }
        for (writer in baselineWriters) {
            val chunk = "vault-data-${writer.toString().padStart(6, '0')}"
            assertEquals(iterations.toLong(), final.baselines[chunk] ?: -1L)
        }
    }
}

private data class SerializedProbeState(
    val token: String,
    val baselines: Map<String, Long>,
)
