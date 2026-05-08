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
