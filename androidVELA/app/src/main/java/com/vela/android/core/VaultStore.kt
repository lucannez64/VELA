package com.vela.android.core

import java.time.Instant

class VaultStore(
    items: List<VaultItem> = emptyList(),
    tombstones: List<Tombstone> = emptyList()
) {
    var items: List<VaultItem> = items
        private set

    var tombstones: List<Tombstone> = tombstones
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
        if (idx != null) {
            items = items.toMutableList().also { it[idx] = item }
        } else {
            val foundIdx = items.indexOfFirst { it.id == id }
            if (foundIdx >= 0) {
                items = items.toMutableList().also { it[foundIdx] = item }
                reindex()
            } else {
                addItem(item)
                return
            }
        }
    }

    fun deleteItem(id: String, deviceId: String? = null) {
        ensureIndex()
        val idx = itemIndex[id]
        if (idx != null) {
            items = items.toMutableList().also { it.removeAt(idx) }
            itemIndex.remove(id)
            reindex()
        } else {
            items = items.filterNot { it.id == id }
        }
        tombstones = mergeTombstones(
            tombstones + Tombstone(
                id = id,
                deletedAt = Instant.now(),
                deletedBy = deviceId
            )
        )
    }

    fun pruneTombstones(retentionDays: Long = 30) {
        val cutoff = Instant.now().minus(java.time.Duration.ofDays(retentionDays))
        tombstones = tombstones.filter { it.deletedAt >= cutoff }
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

private fun mergeTombstones(values: List<Tombstone>): List<Tombstone> =
    values.groupBy { it.id }.map { (_, tombstones) -> tombstones.maxBy { it.deletedAt } }
