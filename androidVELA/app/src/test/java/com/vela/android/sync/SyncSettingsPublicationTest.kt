package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Regression for the publish-after-unlock race.
 *
 * The old store did `_settings.value = state.update(transform)`: T1 could
 * commit its snapshot S1, T2 could commit and publish the newer S2, and then
 * T1 resumed and published the stale S1, leaving the in-memory baseline behind
 * disk. These tests drive the exact production [SyncSettingsState] cell (real
 * StateFlow + serialized persist/publish), not a `persist = { it }` probe.
 */
class SyncSettingsPublicationTest {
    private val chunk = "vault-data-000000"
    private val context = syncBaselineScope("https://vault.example", "alice", 1).key

    @Test
    fun olderCommitCannotPublishAfterANewerCommit() {
        val initial = SyncSettings(
            bearerToken = "token-old",
            seenLamportByContext = mapOf(context to mapOf(chunk to 1L)),
        )
        val disk = AtomicReference(initial)
        val firstPersistEntered = CountDownLatch(1)
        val releaseFirstPersist = CountDownLatch(1)
        val persistCalls = AtomicInteger()
        val state = SyncSettingsState(initial) { next ->
            if (persistCalls.incrementAndGet() == 1) {
                firstPersistEntered.countDown()
                releaseFirstPersist.await(10, TimeUnit.SECONDS)
            }
            disk.set(next)
            next
        }
        val secondTransformRan = CountDownLatch(1)
        val publishedWhenSecondTransformBegan = AtomicReference<SyncSettings>()
        val pool = Executors.newFixedThreadPool(2)
        try {
            val tokenWriter = pool.submit {
                state.update { it.copy(bearerToken = "token-new") }
            }
            assertTrue(firstPersistEntered.await(10, TimeUnit.SECONDS))

            val baselineWriter = pool.submit {
                state.update { current ->
                    // Runs only after T1 released the same lock that published
                    // its commit. Under the old code, T1's publication could
                    // still be pending here.
                    publishedWhenSecondTransformBegan.set(state.settings.value)
                    secondTransformRan.countDown()
                    current.copy(
                        seenLamportByContext = mapOf(context to mapOf(chunk to 10L))
                    )
                }
            }

            // T2 must not even begin its transform while T1 holds the cell.
            assertFalse(secondTransformRan.await(250, TimeUnit.MILLISECONDS))
            assertEquals("token-old", state.settings.value.bearerToken)

            releaseFirstPersist.countDown()
            tokenWriter.get(10, TimeUnit.SECONDS)
            baselineWriter.get(10, TimeUnit.SECONDS)

            val published = state.settings.value
            assertEquals("token-new", published.bearerToken)
            assertEquals(10L, published.seenLamportByContext.getValue(context).getValue(chunk))
            // The flow the UI observes and the last committed snapshot agree.
            assertEquals(published, disk.get())
            assertEquals(published, state.current)
            // Publication is part of the same critical section: the next
            // writer never transforms against a state the flow has not seen.
            assertEquals("token-new", publishedWhenSecondTransformBegan.get()!!.bearerToken)
        } finally {
            releaseFirstPersist.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun failedPersistPublishesNothingAndKeepsPreviousState() {
        val initial = SyncSettings(
            bearerToken = "token-old",
            seenLamportByContext = mapOf(context to mapOf(chunk to 4L)),
        )
        var fail = true
        val state = SyncSettingsState(initial) { next ->
            if (fail) error("disk full")
            next
        }

        assertThrows(IllegalStateException::class.java) {
            state.update { it.copy(bearerToken = "token-new") }
        }
        assertEquals(initial, state.settings.value)
        assertEquals(initial, state.current)

        fail = false
        state.update { it.copy(bearerToken = "token-new") }
        assertEquals("token-new", state.settings.value.bearerToken)
        assertEquals(4L, state.settings.value.seenLamportByContext.getValue(context).getValue(chunk))
    }

    @Test
    fun concurrentTokenAndBaselineWritersThroughPublishedFlowNeverLoseUpdates() {
        val scope = syncBaselineScope("https://vault.example", "alice", 1)
        val initial = SyncSettings(bearerToken = "token-0")
        val disk = AtomicReference(initial)
        val state = SyncSettingsState(initial) { next ->
            disk.set(next)
            next
        }
        val writers = 8
        val iterations = 100
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(writers)
        try {
            val futures = (0 until writers).map { writer ->
                pool.submit {
                    start.await()
                    repeat(iterations) { step ->
                        if (writer % 2 == 0) {
                            state.update {
                                it.copy(bearerToken = "token-${writer * iterations + step}")
                            }
                        } else {
                            state.update { current ->
                                current.copy(
                                    seenLamportByContext = mapOf(
                                        scope.key to mergeSeenLamports(
                                            current.seenLamportByContext[scope.key].orEmpty(),
                                            mapOf(
                                                "vault-data-${writer.toString().padStart(6, '0')}" to
                                                    (step + 1).toLong()
                                            ),
                                        )
                                    )
                                )
                            }
                        }
                    }
                }
            }
            start.countDown()
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        val published = state.settings.value
        val baselineWriters = (0 until writers).filter { it % 2 == 1 }
        for (writer in baselineWriters) {
            val id = "vault-data-${writer.toString().padStart(6, '0')}"
            assertEquals(iterations.toLong(), published.seenLamportByContext.getValue(scope.key)[id])
        }
        assertEquals(published, disk.get())
        assertEquals(published, state.current)
    }
}
