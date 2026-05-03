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

sealed interface VaultItem {
    val id: String
    val name: String
    val createdAt: Instant
    val updatedAt: Instant
    val lastModifiedDevice: String?
    val favorite: Boolean
    val shared: Boolean
    val shareRecipient: String?
    val type: VaultItemType

    data class Login(
        override val id: String = UUID.randomUUID().toString(),
        override val name: String,
        val url: String,
        val username: String,
        val password: String,
        val totp: String? = null,
        val notes: String? = null,
        override val createdAt: Instant = Instant.now(),
        override val updatedAt: Instant = Instant.now(),
        override val lastModifiedDevice: String? = null,
        override val favorite: Boolean = false,
        override val shared: Boolean = false,
        override val shareRecipient: String? = null
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.Login
    }

    data class CreditCard(
        override val id: String = UUID.randomUUID().toString(),
        override val name: String,
        val cardholderName: String = "",
        val cardNumber: String = "",
        val expiration: String = "",
        val cvv: String = "",
        val pin: String? = null,
        val notes: String? = null,
        override val createdAt: Instant = Instant.now(),
        override val updatedAt: Instant = Instant.now(),
        override val lastModifiedDevice: String? = null,
        override val favorite: Boolean = false,
        override val shared: Boolean = false,
        override val shareRecipient: String? = null
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.CreditCard
    }

    data class SecureNote(
        override val id: String = UUID.randomUUID().toString(),
        override val name: String = "Secure Note",
        val notes: String = "",
        override val createdAt: Instant = Instant.now(),
        override val updatedAt: Instant = Instant.now(),
        override val lastModifiedDevice: String? = null,
        override val favorite: Boolean = false,
        override val shared: Boolean = false,
        override val shareRecipient: String? = null
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.SecureNote
    }

    data class FileBlob(
        override val id: String = UUID.randomUUID().toString(),
        override val name: String = "File",
        val fileName: String = "",
        val mimeType: String = "",
        val sizeBytes: Long = 0,
        override val createdAt: Instant = Instant.now(),
        override val updatedAt: Instant = Instant.now(),
        override val lastModifiedDevice: String? = null,
        override val favorite: Boolean = false,
        override val shared: Boolean = false,
        override val shareRecipient: String? = null
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.FileBlob
    }

    data class BreachMonitor(
        override val id: String = UUID.randomUUID().toString(),
        override val name: String,
        val email: String,
        val checkedAt: Instant? = null,
        val breachCount: Int = 0,
        val breaches: List<BreachEntry> = emptyList(),
        override val createdAt: Instant = Instant.now(),
        override val updatedAt: Instant = Instant.now(),
        override val lastModifiedDevice: String? = null,
        override val favorite: Boolean = false,
        override val shared: Boolean = false,
        override val shareRecipient: String? = null
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.BreachMonitor
    }
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
