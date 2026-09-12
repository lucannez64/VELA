package com.vela.android.core

import java.time.Instant

class VaultStore(
    items: List<VaultItem> = emptyList(),
    tombstones: List<Tombstone> = emptyList(),
    deletedItems: List<DeletedItem> = emptyList()
) {
    var items: List<VaultItem> = items
        private set

    var tombstones: List<Tombstone> = tombstones
        private set

    /** The trash (§1.2): deleted items, restorable until purged. */
    var deletedItems: List<DeletedItem> = deletedItems
        private set

    private val itemIndex = mutableMapOf<String, Int>()

    init {
        if (items.isNotEmpty()) reindex()
    }

    private fun reindex() {
        itemIndex.clear()
        items.forEachIndexed { i, item -> itemIndex[item.id] = i }
    }

    private fun ensureIndex() {
        if (itemIndex.isEmpty() && items.isNotEmpty()) {
            reindex()
        }
    }

    fun getItem(id: String): VaultItem? {
        val idx = itemIndex[id]
        if (idx != null) return items.getOrNull(idx)
        return items.find { it.id == id }
    }

    fun addItem(item: VaultItem) {
        ensureIndex()
        val id = item.id
        val idx = items.size
        items = items + item
        itemIndex[id] = idx
    }

    fun updateItem(item: VaultItem) {
        ensureIndex()
        val id = item.id
        val idx = itemIndex[id]
        // Record tag removals against the STORED item (the merge suppresses
        // union'd tags whose removal record is newer than the carrier's last
        // edit); same instant as the caller's updated_at stamp.
        val adjusted = getItem(id)?.let { existing ->
            item
                .withTagRemovalsRecorded(existing, Instant.now())
                // §1.3: a changed login password pushes the old value into
                // the history.
                .withPasswordHistoryRecorded(existing, Instant.now())
        } ?: item
        if (idx != null) {
            items = items.toMutableList().also { it[idx] = adjusted }
        } else {
            val foundIdx = items.indexOfFirst { it.id == id }
            if (foundIdx >= 0) {
                items = items.toMutableList().also { it[foundIdx] = adjusted }
                reindex()
            } else {
                addItem(adjusted)
                return
            }
        }
    }

    fun deleteItem(id: String, deviceId: String? = null) {
        ensureIndex()
        // The item's content moves to the trash before it leaves `items`:
        // the tombstone is what sync propagates, the copy is what makes an
        // undo possible.
        val trashed = getItem(id)
        val idx = itemIndex.remove(id)
        if (idx != null) {
            items = items.toMutableList().also { it.removeAt(idx) }
            reindex()
        } else {
            items = items.filterNot { it.id == id }
        }
        trashed?.let { existing ->
            deletedItems = deletedItems.filterNot { it.item.id == id } + DeletedItem(
                item = existing,
                deletedAt = Instant.now(),
                deletedBy = deviceId
            )
        }
        tombstones = mergeTombstones(
            tombstones + Tombstone(
                id = id,
                deletedAt = Instant.now(),
                deletedBy = deviceId
            )
        )
    }

    /** Puts a trashed item back into the live vault (§1.2): newer than every
     *  tombstone, tombstone dropped, trash entry removed. */
    fun restoreItem(id: String): VaultItem? {
        val entry = deletedItems.find { it.item.id == id } ?: return null
        deletedItems = deletedItems.filterNot { it.item.id == id }
        tombstones = tombstones.filterNot { it.id == id }
        val restored = entry.item.withUpdatedAt(Instant.now())
        items = items + restored
        reindex()
        return restored
    }

    /** Erases a trash entry for good; the tombstone stays so sync cannot
     *  resurrect the item from another device's copy. */
    fun purgeDeletedItem(id: String): Boolean {
        val before = deletedItems.size
        deletedItems = deletedItems.filterNot { it.item.id == id }
        return deletedItems.size != before
    }

    fun pruneTombstones(retentionDays: Long = 30) {
        val cutoff = Instant.now().minus(java.time.Duration.ofDays(retentionDays))
        tombstones = tombstones.filter { it.deletedAt >= cutoff }
        deletedItems = deletedItems.filter { it.deletedAt >= cutoff }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultStore) return false
        return items == other.items && tombstones == other.tombstones
    }

    override fun hashCode(): Int {
        var result = items.hashCode()
        result = 31 * result + tombstones.hashCode()
        return result
    }

    override fun toString(): String =
        "VaultStore(items=${items.size}, tombstones=${tombstones.size})"
}

data class Tombstone(
    val id: String,
    val deletedAt: Instant,
    val deletedBy: String? = null
)

/** An item sitting in the trash (§1.2): the tombstone propagates the
 *  deletion, the copy makes an undo possible. Serialized as
 *  `{"item": …, "deleted_at": …, "deleted_by": …}` to match the desktop. */
data class DeletedItem(
    val item: VaultItem,
    val deletedAt: Instant,
    val deletedBy: String? = null
)

private fun mergeTombstones(values: List<Tombstone>): List<Tombstone> =
    values.groupBy { it.id }.map { (_, tombstones) -> tombstones.maxBy { it.deletedAt } }
