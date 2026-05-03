package com.vela.android.core

import java.time.Instant

data class VaultStore(
    val items: List<VaultItem> = emptyList(),
    val tombstones: List<Tombstone> = emptyList()
)

data class Tombstone(
    val id: String,
    val deletedAt: Instant,
    val deletedBy: String? = null
)
