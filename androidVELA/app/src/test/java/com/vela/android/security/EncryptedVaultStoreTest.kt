package com.vela.android.security

import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import com.vela.android.core.VaultStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

class EncryptedVaultStoreTest {
    @Test
    fun organizationWriterIsStablePerInstallAndDistinctAcrossInstalls() {
        val first = Files.createTempDirectory("vela-writer-a").toFile()
        val second = Files.createTempDirectory("vela-writer-b").toFile()
        try {
            val id = EncryptedVaultStore(first).organizationWriterId()
            assertEquals(id, EncryptedVaultStore(first).organizationWriterId())
            assertTrue(id != EncryptedVaultStore(second).organizationWriterId())
        } finally { first.deleteRecursively(); second.deleteRecursively() }
    }

    @Test
    fun resetRemovesTheEncryptedSafetyCopy() {
        val dir = Files.createTempDirectory("vela-reset").toFile()
        try {
            val store = EncryptedVaultStore(dir)
            store.save(ByteArray(32), VaultStore())
            store.safetyBackup()
            val backup = java.io.File(dir, "vault.before-rich-items.enc")
            assertTrue(backup.exists())
            store.delete()
            assertFalse(store.exists())
            assertFalse(backup.exists())
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun encryptedVaultRoundTripPreservesItems() {
        val dir = Files.createTempDirectory("vela-vault").toFile()
        val store = EncryptedVaultStore(dir)
        val rms = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vault = VaultStore(
            items = listOf(
                VaultItem.Login(
                    meta = VaultMeta(
                        name = "Example"
                    ),
                    url = "https://example.com",
                    username = "alice@example.com",
                    password = "secret"
                )
            )
        )

        assertFalse(store.exists())
        store.save(rms, vault)

        assertTrue(store.exists())
        val loaded = store.load(rms)
        assertEquals(1, loaded.items.size)
        assertEquals("Example", loaded.items.single().name)
        assertEquals("alice@example.com", (loaded.items.single() as VaultItem.Login).username)
    }

    @Test(expected = AEADBadTagException::class)
    fun wrongRmsCannotDecryptVault() {
        val dir = Files.createTempDirectory("vela-vault-wrong-key").toFile()
        val store = EncryptedVaultStore(dir)
        val rms = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val wrongRms = ByteArray(32).also { SecureRandom().nextBytes(it) }

        store.save(rms, VaultStore(items = listOf(VaultItem.Login(
            meta = VaultMeta(name = "Example"),
            url = "example.com",
            username = "a",
            password = "b"
        ))))
        store.load(wrongRms)
    }
}
