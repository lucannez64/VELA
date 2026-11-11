package com.vela.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Regressions for R5 F4: the RMS used to be a plain field. `lock()` zeroized
 * the array in place while `currentRmsCopy()` could be copying it, producing a
 * torn or all-zero array of valid length 32 that the vault path would happily
 * use as a key.
 *
 * These tests exercise [RmsHolder], the synchronized production helper now used
 * by [SecureVaultManager]. A snapshot that was already returned may outlive
 * `lock()` and finish in-flight I/O; the tests document that exact semantics
 * instead of claiming that lock cancels all in-flight work.
 */
class RmsHolderTest {
    @Test
    fun snapshotIsDetachedAndSurvivesALaterLock() {
        val holder = RmsHolder()
        val original = ByteArray(32) { (it + 1).toByte() }
        holder.replaceAndWipeInput(original)
        assertArrayEquals(ByteArray(32), original)

        val snapshot = holder.copy()
        holder.clear()

        // The captured key is a coherent copy, not a view into the zeroized
        // buffer. A background save may therefore finish after lock().
        assertArrayEquals(ByteArray(32) { (it + 1).toByte() }, snapshot)
        assertNull(holder.copy())
        assertFalse(holder.isUnlocked())

        // Mutating the snapshot must not affect the holder (and vice versa).
        snapshot!!.fill(0)
        assertNull(holder.copy())
    }

    @Test
    fun concurrentCopiesNeverObserveATornOrZeroizedKey() {
        val holder = RmsHolder()
        val patternA = ByteArray(32) { 0x11 }
        val patternB = ByteArray(32) { 0x22 }
        holder.replaceAndWipeInput(patternA.copyOf())

        val iterations = 2_000
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val writer = pool.submit {
                start.await()
                repeat(iterations) { index ->
                    when (index % 5) {
                        0, 1, 2, 3 -> holder.replaceAndWipeInput(
                            if (index % 2 == 0) patternA.copyOf() else patternB.copyOf()
                        )
                        else -> holder.clear()
                    }
                }
            }
            var snapshots = 0
            val reader = pool.submit {
                start.await()
                repeat(iterations * 2) {
                    holder.copy()?.let { copy ->
                        snapshots++
                        assertEquals(32, copy.size)
                        val allA = copy.all { it == 0x11.toByte() }
                        val allB = copy.all { it == 0x22.toByte() }
                        assertTrue(
                            "copy observed a torn or zeroized key: ${copy.toList()}",
                            allA || allB,
                        )
                    }
                }
            }
            start.countDown()
            writer.get(30, TimeUnit.SECONDS)
            reader.get(30, TimeUnit.SECONDS)
            assertTrue("the race should have produced at least one snapshot", snapshots > 0)
        } finally {
            pool.shutdownNow()
        }
    }
}
