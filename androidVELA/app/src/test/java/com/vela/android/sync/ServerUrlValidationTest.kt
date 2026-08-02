package com.vela.android.sync

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cleartext server URLs were accepted here and then blocked at runtime by the
 * OS, so sync failed with a bare network error and nothing said why.
 */
class ServerUrlValidationTest {

    @Test
    fun `cleartext is refused with a reason`() {
        val problem = SyncSettingsStore.serverUrlProblem("http://vault.example.com")
        assertNotNull(problem)
        // The reason has to say what is actually at stake: the vault is
        // encrypted either way, so what cleartext costs is the metadata.
        assertTrue(problem!!, problem.contains("HTTPS"))
    }

    @Test
    fun `case does not get a caller past it`() {
        assertNotNull(SyncSettingsStore.serverUrlProblem("HTTP://vault.example.com"))
        assertNotNull(SyncSettingsStore.serverUrlProblem("HtTp://vault.example.com"))
    }

    @Test
    fun `https addresses are accepted`() {
        assertNull(SyncSettingsStore.serverUrlProblem("https://vault.example.com"))
        assertNull(SyncSettingsStore.serverUrlProblem("https://vault.example.com/"))
        assertNull(SyncSettingsStore.serverUrlProblem("https://vault.example.com:8443"))
        assertNull(SyncSettingsStore.serverUrlProblem("vault.example.com"))
    }

    @Test
    fun `an empty field is not an error yet`() {
        // Nothing typed is not a mistake — it is just not finished.
        assertNull(SyncSettingsStore.serverUrlProblem(""))
        assertNull(SyncSettingsStore.serverUrlProblem("   "))
    }

    @Test
    fun `an address that is not one is refused`() {
        assertNotNull(SyncSettingsStore.serverUrlProblem("localhost"))
        assertNotNull(SyncSettingsStore.serverUrlProblem("https://"))
        assertNotNull(SyncSettingsStore.serverUrlProblem("https:///path"))
    }
}
