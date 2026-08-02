package com.vela.android.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Audit A-1: `MainActivity` is the launcher, so it is exported and any app can
 * start it with crafted extras. These tokens are the only thing separating an
 * unlock intent this app issued from one an attacker forged, so the properties
 * below are load-bearing, not incidental.
 */
class AutofillUnlockTokensTest {

    @Before
    fun reset() {
        AutofillUnlockTokens.clear()
    }

    @Test
    fun `a token this process issued is accepted exactly once`() {
        val token = AutofillUnlockTokens.issue()

        assertTrue("the flow we started must work", AutofillUnlockTokens.redeem(token))
        assertFalse("replaying it must not", AutofillUnlockTokens.redeem(token))
    }

    @Test
    fun `tokens nobody issued are refused`() {
        AutofillUnlockTokens.issue()

        assertFalse(AutofillUnlockTokens.redeem(null))
        assertFalse(AutofillUnlockTokens.redeem(""))
        assertFalse(AutofillUnlockTokens.redeem("hFqQ0Yy0m0EJvJk8vJp0kA=="))
    }

    @Test
    fun `tokens are unpredictable and distinct`() {
        val first = AutofillUnlockTokens.issue()
        val second = AutofillUnlockTokens.issue()

        assertNotEquals(first, second)
        // 32 random bytes, base64 -> 44 chars. A shorter token would mean the
        // entropy assumption behind this whole check is wrong.
        assertTrue("token is 32 random bytes: ${first.length}", first.length >= 44)
        assertTrue(AutofillUnlockTokens.redeem(first))
        assertTrue(AutofillUnlockTokens.redeem(second))
    }

    @Test
    fun `an expired token is refused`() {
        val stale = AutofillUnlockTokens.issueExpiringAt(System.currentTimeMillis() - 1)

        assertFalse(AutofillUnlockTokens.redeem(stale))
    }

    @Test
    fun `outstanding tokens are bounded, dropping the oldest`() {
        // Responses are built far more often than they are used (the user
        // usually ignores the "Unlock VELA" chip), so the store must not grow.
        val tokens = (1..12).map { AutofillUnlockTokens.issue() }

        assertFalse("the oldest is evicted", AutofillUnlockTokens.redeem(tokens.first()))
        assertTrue("the newest still works", AutofillUnlockTokens.redeem(tokens.last()))
    }
}
