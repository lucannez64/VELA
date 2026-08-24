package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

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
}
