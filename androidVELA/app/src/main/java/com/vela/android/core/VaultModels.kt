package com.vela.android.core

import java.time.Instant
import java.util.UUID

enum class VaultItemType {
    Login,
    CreditCard,
    SecureNote,
    FileBlob,
    BreachMonitor
}

data class VaultMeta(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val notes: String? = null,
    val createdAt: Instant = Instant.now(),
    val updatedAt: Instant = Instant.now(),
    val lastModifiedDevice: String? = null,
    val favorite: Boolean = false,
    val shared: Boolean = false,
    val shareRecipient: String? = null,
)

sealed interface VaultItem {
    val meta: VaultMeta
    val id: String get() = meta.id
    val name: String get() = meta.name
    val notes: String? get() = meta.notes
    val createdAt: Instant get() = meta.createdAt
    val updatedAt: Instant get() = meta.updatedAt
    val lastModifiedDevice: String? get() = meta.lastModifiedDevice
    val favorite: Boolean get() = meta.favorite
    val shared: Boolean get() = meta.shared
    val shareRecipient: String? get() = meta.shareRecipient
    val type: VaultItemType

    data class Login(
        override val meta: VaultMeta,
        val url: String,
        val username: String,
        val password: String,
        val totp: String? = null,
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.Login
    }

    data class CreditCard(
        override val meta: VaultMeta,
        val cardholderName: String = "",
        val cardNumber: String = "",
        val expiration: String = "",
        val cvv: String = "",
        val pin: String? = null,
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.CreditCard
    }

    data class SecureNote(
        override val meta: VaultMeta,
        val content: String,
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.SecureNote
    }

    data class FileBlob(
        override val meta: VaultMeta,
        val fileName: String = "",
        val mimeType: String = "",
        val sizeBytes: Long = 0,
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.FileBlob
    }

    data class BreachMonitor(
        override val meta: VaultMeta,
        val email: String,
        val checkedAt: Instant? = null,
        val breachCount: Int = 0,
        val breaches: List<BreachEntry> = emptyList(),
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.BreachMonitor
    }
}

fun VaultItem.withMeta(transform: (VaultMeta) -> VaultMeta): VaultItem = when (this) {
    is VaultItem.Login -> copy(meta = transform(meta))
    is VaultItem.CreditCard -> copy(meta = transform(meta))
    is VaultItem.SecureNote -> copy(meta = transform(meta))
    is VaultItem.FileBlob -> copy(meta = transform(meta))
    is VaultItem.BreachMonitor -> copy(meta = transform(meta))
}

fun VaultItem.withId(newId: String) = withMeta { it.copy(id = newId) }

fun VaultItem.withUpdatedAt(newUpdatedAt: Instant) = withMeta { it.copy(updatedAt = newUpdatedAt) }

fun VaultItem.withSharedStatus(shared: Boolean, shareRecipient: String?) =
    withMeta { it.copy(shared = shared, shareRecipient = shareRecipient) }

val VaultItem.url: String? get() = when (this) {
    is VaultItem.Login -> url
    else -> null
}

val VaultItem.username: String? get() = when (this) {
    is VaultItem.Login -> username
    else -> null
}

val VaultItem.password: String? get() = when (this) {
    is VaultItem.Login -> password
    else -> null
}

val VaultItem.displayValue: String get() = when (this) {
    is VaultItem.Login -> password
    is VaultItem.CreditCard -> cardNumber
    is VaultItem.SecureNote -> "Secure Note"
    is VaultItem.FileBlob -> fileName
    is VaultItem.BreachMonitor -> email
}

val VaultItem.maskedValue: String get() = when (this) {
    is VaultItem.Login -> "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
    is VaultItem.CreditCard -> if (cardNumber.length >= 4) {
        "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 ${cardNumber.takeLast(4)}"
    } else {
        "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022"
    }
    is VaultItem.SecureNote -> "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
    is VaultItem.FileBlob -> fileName
    is VaultItem.BreachMonitor -> email
}

data class BreachEntry(
    val name: String,
    val title: String,
    val domain: String,
    val breachDate: String,
    val description: String,
    val dataClasses: List<String>,
    val isVerified: Boolean = false,
    val isFabricated: Boolean = false,
    val isSensitive: Boolean = false,
    val isRetired: Boolean = false,
    val isSpamList: Boolean = false
)

data class AutofillCandidate(
    val itemId: String,
    val label: String,
    val username: String?,
    val domain: String?,
    val hasTotp: Boolean,
    val itemType: VaultItemType
)
