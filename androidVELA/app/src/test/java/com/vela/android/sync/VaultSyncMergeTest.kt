package com.vela.android.sync

import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import com.vela.android.core.VaultStore
import com.vela.android.core.normalizeTags
import com.vela.android.core.withTagRemovalsRecorded
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * The vault-merge rules, off-device. The passkey key backfill is the load-
 * bearing part (security/passkey-android-provider-adr.md): before the Android
 * passkey provider existed, this app stored and uploaded passkeys as
 * metadata-only, so a merge must never turn a keyed credential into a keyless
 * one — whichever side holds the key, the merged item gets it.
 */
class VaultSyncMergeTest {

    private val now: Instant = Instant.parse("2026-09-09T00:00:00Z")
    private val earlier: Instant = Instant.parse("2026-09-08T00:00:00Z")

    private fun passkey(
        id: String,
        name: String = "Example",
        updatedAt: Instant = now,
        privateKey: String = "",
        signCount: Long = 1,
    ) = VaultItem.Passkey(
        meta = VaultMeta(id = id, name = name, createdAt = earlier, updatedAt = updatedAt),
        rpId = "example.com",
        credentialId = "AQ",
        userHandle = "AA",
        userName = "ada",
        privateKey = privateKey,
        signCount = signCount,
    )

    private fun login(id: String, name: String = "Site") = VaultItem.Login(
        meta = VaultMeta(id = id, name = name, createdAt = earlier, updatedAt = now),
        url = "https://$id.example",
        username = "ada",
        password = "hunter2",
    )

    @Test
    fun `a keyless local copy gains the key from a keyed server copy`() {
        // The common upgrade path: the phone synced before the provider
        // existed (keyless), the desktop holds the key; timestamps match
        // because it is the same item.
        val merged = mergeVaultStores(
            VaultStore(listOf(passkey("pk-1"))),
            VaultStore(listOf(passkey("pk-1", privateKey = "KEY"))),
        )

        assertEquals("KEY", (merged.items.single() as VaultItem.Passkey).privateKey)
    }

    @Test
    fun `a keyless server copy never strips a key the local copy has`() {
        // Same timestamps, remote wins ties — but the remote copy is keyless,
        // so the backfill must restore the local key.
        val merged = mergeVaultStores(
            VaultStore(listOf(passkey("pk-1", privateKey = "KEY"))),
            VaultStore(listOf(passkey("pk-1"))),
        )

        assertEquals("KEY", (merged.items.single() as VaultItem.Passkey).privateKey)
    }

    @Test
    fun `a locally newer rename keeps the rename and gains the key`() {
        val renamed = passkey(
            "pk-1", name = "Renamed on phone", updatedAt = now.plusSeconds(60)
        )
        val merged = mergeVaultStores(
            VaultStore(listOf(renamed)),
            VaultStore(listOf(passkey("pk-1", name = "Example", privateKey = "KEY"))),
        )

        val item = merged.items.single() as VaultItem.Passkey
        assertEquals("Renamed on phone", item.name)
        assertEquals("KEY", item.privateKey)
    }

    @Test
    fun `a keyless passkey with no keyed copy anywhere stays keyless`() {
        // Both sides keyless (the credential was created before any of this):
        // nothing to backfill, merge proceeds normally.
        val merged = mergeVaultStores(
            VaultStore(listOf(passkey("pk-1"))),
            VaultStore(listOf(passkey("pk-1"))),
        )

        assertTrue((merged.items.single() as VaultItem.Passkey).privateKey.isEmpty())
    }

    @Test
    fun `non passkey items merge by the timestamp rules as before`() {
        val merged = mergeVaultStores(
            VaultStore(listOf(login("a"), login("b", name = "Local edit"))),
            VaultStore(listOf(login("a", name = "Server edit"))),
        )

        val byId = merged.items.associateBy { it.id }
        // Same timestamps, remote applied last wins the tie.
        assertEquals("Server edit", byId.getValue("a").name)
        assertEquals("Local edit", byId.getValue("b").name)
    }

    private fun tagged(
        id: String,
        updatedAt: Instant,
        tags: List<String>,
        folder: String? = null,
        name: String = "Site",
    ) = VaultItem.Login(
        meta = VaultMeta(
            id = id, name = name, createdAt = earlier, updatedAt = updatedAt,
            tags = tags, folder = folder,
        ),
        url = "https://$id.example", username = "ada", password = "hunter2",
    )

    /** The §1.1 done-when, on Android: a tag added on the phone and a newer
     *  edit of another field from another device merge without losing the tag
     *  and without a fight; tags from BOTH sides survive, canonically ordered,
     *  and the folder follows the newer copy. */
    @Test
    fun `a tag added offline survives a concurrent edit`() {
        val local = tagged("a", earlier, tags = listOf("banking"))
        val remote = tagged(
            "a", now, tags = listOf("shared"), folder = "Finance", name = "Renamed",
        )

        val merged = mergeVaultStores(VaultStore(listOf(local)), VaultStore(listOf(remote)))
        val item = merged.items.single()

        assertEquals("Renamed", item.name)
        assertEquals("Finance", item.folder)
        assertEquals(listOf("banking", "shared"), item.tags)
    }

    @Test
    fun `tag canonicalization trims deduplicates and sorts`() {
        val tags = normalizeTags(listOf("  Work ", "work", "VPN", "", "  "))
        assertEquals(listOf("VPN", "Work"), tags)
    }

    /** The removal record is written against the STORED item's tags and the
     *  merged result honors it — the Android twin of the desktop test. */
    @Test
    fun `a tag removal beats a stale copy in the merge`() {
        val removalTime = now
        val staleCarrier = tagged("a", earlier, tags = listOf("work"))
        // The remover's copy: no tags, but the removal recorded at `now`.
        val remover = tagged("a", now, tags = emptyList())
            .withTagRemovalsRecorded(staleCarrier, removalTime)

        assertTrue(remover.tagTombstones.any { it.tag == "work" })

        val merged = mergeVaultStores(
            VaultStore(listOf(staleCarrier)),
            VaultStore(listOf(remover)),
        )
        val item = merged.items.single()
        assertTrue(
            "the removal must beat the stale copy, got ${item.tags}",
            item.tags.isEmpty(),
        )
        assertTrue(item.tagTombstones.any { it.tag == "work" })

        // A copy edited AFTER the removal that still carries the tag has
        // re-affirmed it — the tag survives.
        val reaffirmed = tagged("a", now.plusSeconds(60), tags = listOf("work"))
        val mergerWithRemoval = mergeVaultStores(
            VaultStore(listOf(remover)),
            VaultStore(listOf(reaffirmed)),
        )
        assertEquals(listOf("work"), mergerWithRemoval.items.single().tags)
    }
}
