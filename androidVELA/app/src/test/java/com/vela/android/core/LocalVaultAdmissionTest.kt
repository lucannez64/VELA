package com.vela.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Regressions for the admitted-sync persistence gate.
 *
 * `LocalVaultRepository.replaceAll` keeps its historical "no-op if AutoLock
 * raced us" behavior for ordinary callers. An admitted download is different:
 * if persistence did not happen, recording the admitted clocks would let a
 * later retry look like a rollback. [persistVaultThenRecord] is the production
 * ordering helper used by `replaceAllAdmitted`.
 */
class LocalVaultAdmissionTest {
    @Test
    fun lockedVaultThrowsBeforeAnyBaselineIsRecorded() {
        val recorded = AtomicInteger()
        val error = assertThrows(IllegalStateException::class.java) {
            persistVaultThenRecord(
                rms = null,
                save = { error("must not be called") },
                afterPersist = { recorded.incrementAndGet() },
            )
        }
        assertTrue(error.message!!.contains("locked"))
        assertEquals(0, recorded.get())
    }

    @Test
    fun storageFailureThrowsBeforeAnyBaselineIsRecorded() {
        val rms = ByteArray(32) { it.toByte() }
        val recorded = AtomicInteger()
        assertThrows(IOException::class.java) {
            persistVaultThenRecord(
                rms = rms,
                save = { throw IOException("disk full") },
                afterPersist = { recorded.incrementAndGet() },
            )
        }
        assertEquals(0, recorded.get())
        // The key material is wiped even though the write failed.
        assertArrayEquals(ByteArray(32), rms)
    }

    @Test
    fun successRecordsOnlyAfterThePersistCompleted() {
        val rms = ByteArray(32) { it.toByte() }
        val order = mutableListOf<String>()
        val result = persistVaultThenRecord(
            rms = rms,
            save = { key ->
                assertFalse(order.contains("record"))
                assertEquals(31.toByte(), key[31])
                order += "persist"
            },
            afterPersist = {
                order += "record"
                "recorded"
            },
        )
        assertEquals("recorded", result)
        assertEquals(listOf("persist", "record"), order)
        assertArrayEquals(ByteArray(32), rms)
    }
}
