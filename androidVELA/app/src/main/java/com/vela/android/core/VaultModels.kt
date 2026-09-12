package com.vela.android.core

import java.time.Instant
import java.util.UUID

enum class VaultItemType {
    Login,
    CreditCard,
    SecureNote,
    Passkey,
    FileBlob,
    BreachMonitor,
    Address,
    BankAccount,
    ApiKey,
    SshKey
}

data class VaultMeta(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val notes: String? = null,
    val createdAt: Instant = Instant.now(),
    val updatedAt: Instant = Instant.now(),
    val lastModifiedDevice: String? = null,
    val favorite: Boolean = false,
    /**
     * §1.1 organization: canonical tags and one optional folder name.
     * Canonical form (trimmed, deduplicated case-insensitively, sorted) is
     * applied by [normalizeTags] on write; the sync merge unions tags and
     * keeps the newer copy's folder, mirroring `vela-sync-policy`'s
     * `merge_org_fields` on the desktop.
     */
    val tags: List<String> = emptyList(),
    /**
     * Removal records for tags: without one, the union merge resurrects a
     * removed tag from every stale copy that still carries it. `tag` is the
     * canonical (lowercased) key; a merge suppresses a union'd tag whose
     * removal is newer than the carrying copy's last edit, and an edit that
     * (re-)adds the tag clears its record.
     */
    val tagTombstones: List<TagTombstone> = emptyList(),
    /**
     * §1.3: user-defined extra fields, available on every item type. A
     * `Hidden` value is masked like a password.
     */
    val customFields: List<CustomField> = emptyList(),
    val folder: String? = null,
    val shared: Boolean = false,
    val shareRecipient: String? = null,
)

/// A recorded tag removal (see [VaultMeta.tagTombstones]). Serialized as
/// `{"tag": "work", "deleted_at": "<rfc3339>"}` to match the desktop's
/// `TagTombstone`.
data class TagTombstone(
    val tag: String,
    val deletedAt: Instant,
)

/// §1.3: a user-defined extra field. A `Hidden` value is masked like a
/// password. Serialized as `{"label": …, "value": …, "field_type": …}` to
/// match the desktop's `CustomField`.
data class CustomField(
    val label: String,
    val value: String = "",
    val fieldType: CustomFieldType = CustomFieldType.Text,
)

enum class CustomFieldType {
    Text,
    Hidden
}

/** §1.3: a previous password value with the time it was replaced. Old
 *  passwords are still secrets. Serialized as
 *  `{"password": …, "changed_at": …}` to match the desktop. */
data class PasswordHistoryEntry(
    val password: String,
    val changedAt: Instant,
)

/// Removal-record retention: the same 30-day window item tombstones get.
const val TAG_REMOVAL_RETENTION_MS: Long = 30L * 24 * 60 * 60 * 1000

/// Collapses removal records: newest per tag, expired dropped, sorted —
/// mirroring `vela-sync-policy::normalize_tag_removals`.
fun normalizeTagRemovals(removals: List<TagTombstone>, nowMs: Long): List<TagTombstone> {
    val cutoff = nowMs - TAG_REMOVAL_RETENTION_MS
    return removals.groupBy { it.tag }
        .map { (_, sameTag) -> sameTag.maxBy { it.deletedAt } }
        .filter { it.deletedAt.toEpochMilli() > cutoff }
        .sortedBy { it.tag }
}

/// The canonical tag list: trimmed, empties dropped, deduplicated
/// case-insensitively (first spelling wins), sorted — the same rule the
/// desktop's `vela-sync-policy::normalize_tags` applies, so both platforms
/// store the same bytes for the same tags.
fun normalizeTags(tags: Iterable<String>): List<String> =
    tags.mapNotNull { it.trim().takeIf(String::isNotEmpty) }
        .fold(LinkedHashMap<String, String>()) { acc, tag -> acc.putIfAbsent(tag.lowercase(), tag); acc }
        .values
        .sortedBy(String::lowercase)

sealed interface VaultItem {
    val meta: VaultMeta
    val id: String get() = meta.id
    val name: String get() = meta.name
    val notes: String? get() = meta.notes
    val createdAt: Instant get() = meta.createdAt
    val updatedAt: Instant get() = meta.updatedAt
    val lastModifiedDevice: String? get() = meta.lastModifiedDevice
    val favorite: Boolean get() = meta.favorite
    val tags: List<String> get() = meta.tags
    val tagTombstones: List<TagTombstone> get() = meta.tagTombstones
    val folder: String? get() = meta.folder
    val shared: Boolean get() = meta.shared
    val shareRecipient: String? get() = meta.shareRecipient
    val type: VaultItemType

    data class Login(
        override val meta: VaultMeta,
        val url: String,
        val username: String,
        val password: String,
        val totp: String? = null,
        /**
         * Apps the user has linked to this login, as `androidapp://<package>`.
         *
         * A package name cannot be turned into a domain by rule, so the link is
         * recorded when the user confirms it rather than guessed (audit A-2).
         * See [com.vela.android.autofill.AppAssociations].
         */
        val appIds: List<String> = emptyList(),
        /**
         * §1.3: previous password values, newest first. Recorded by
         * [com.vela.android.core.VaultStore.updateItem] when an edit changes
         * the password; the live password is never in here. Written as
         * `password_history` to match the desktop.
         */
        val passwordHistory: List<PasswordHistoryEntry> = emptyList(),
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

    /**
     * A WebAuthn credential scoped to one relying party.
     *
     * Android is a passkey provider (`security/passkey-android-provider-adr.md`):
     * it serves these credentials to websites and apps through Credential
     * Manager. The private key lives here, sealed with the rest of the vault —
     * it is used where it is stored (in the native bridge, one signature at a
     * time) and never leaves the device; only signatures cross the provider
     * boundary. Items synced before the provider existed carry an empty key
     * and are metadata-only until the next sync delivers it.
     */
    data class Passkey(
        override val meta: VaultMeta,
        val rpId: String = "",
        val rpName: String = "",
        val credentialId: String = "",
        val userHandle: String = "",
        val userName: String = "",
        val userDisplayName: String = "",
        /** ES256 private scalar, base64url. The secret — never logged, never rendered. */
        val privateKey: String = "",
        /** WebAuthn signature counter, incremented after every assertion. */
        val signCount: Long = 0,
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.Passkey
    }

    /** §1.3: a postal address — reference data, nothing secret-grade. */
    data class Address(
        override val meta: VaultMeta,
        val fullName: String = "",
        val street: String = "",
        val streetLine2: String = "",
        val city: String = "",
        val state: String = "",
        val postalCode: String = "",
        val country: String = "",
        val phone: String = "",
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.Address
    }

    /** §1.3: a bank account. `accountNumber` and `iban` are secrets. */
    data class BankAccount(
        override val meta: VaultMeta,
        val bankName: String = "",
        val accountKind: String = "",
        val holder: String = "",
        val accountNumber: String = "",
        val routingNumber: String = "",
        val iban: String = "",
        val swift: String = "",
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.BankAccount
    }

    /** §1.3: an API credential. `apiKey` is a secret — it leaves the vault
     *  (the user pastes it into config), so it gets the password treatment:
     *  masked, copyable. */
    data class ApiKey(
        override val meta: VaultMeta,
        val url: String = "",
        val username: String = "",
        val apiKey: String = "",
        val expires: String? = null,
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.ApiKey
    }

    /** §1.3: an SSH key pair, stored for the CLI/SSH agent. The private key
     *  and passphrase are secrets; the public key is the shareable half. */
    data class SshKey(
        override val meta: VaultMeta,
        val kind: String = "",
        val publicKey: String = "",
        val privateKey: String = "",
        val passphrase: String = "",
        val comment: String = "",
    ) : VaultItem {
        override val type: VaultItemType = VaultItemType.SshKey
    }
}

fun VaultItem.withMeta(transform: (VaultMeta) -> VaultMeta): VaultItem = when (this) {
    is VaultItem.Login -> copy(meta = transform(meta))
    is VaultItem.CreditCard -> copy(meta = transform(meta))
    is VaultItem.SecureNote -> copy(meta = transform(meta))
    is VaultItem.FileBlob -> copy(meta = transform(meta))
    is VaultItem.BreachMonitor -> copy(meta = transform(meta))
    is VaultItem.Passkey -> copy(meta = transform(meta))
    is VaultItem.Address -> copy(meta = transform(meta))
    is VaultItem.BankAccount -> copy(meta = transform(meta))
    is VaultItem.ApiKey -> copy(meta = transform(meta))
    is VaultItem.SshKey -> copy(meta = transform(meta))
}

fun VaultItem.withId(newId: String) = withMeta { it.copy(id = newId) }

fun VaultItem.withUpdatedAt(newUpdatedAt: Instant) = withMeta { it.copy(updatedAt = newUpdatedAt) }

fun VaultItem.withSharedStatus(shared: Boolean, shareRecipient: String?) =
    withMeta { it.copy(shared = shared, shareRecipient = shareRecipient) }

/// Replaces the tags with [tags], canonicalized ([normalizeTags]) — the same
/// rule the desktop applies on write.
fun VaultItem.withTags(tags: List<String>) = withMeta { it.copy(tags = normalizeTags(tags)) }

/// Sets or clears the folder; blank means "no folder".
fun VaultItem.withFolder(folder: String?) =
    withMeta { it.copy(folder = folder?.trim()?.takeIf(String::isNotEmpty)) }

/// Union of this item's tags with [other]'s, minus tags whose removal
/// records (from either side) are newer than the carrying copy's last edit;
/// the merged removal records ride along. Every other field — including the
/// single-valued folder — stays this item's. The sync merge calls this on
/// the copy that already won, so the folder decision was made by the
/// timestamp comparison and only the additive tags are merged
/// (`vela-sync-policy::merge_org_fields` on the desktop).
fun VaultItem.withMergedTags(other: VaultItem): VaultItem {
    val nowMs = System.currentTimeMillis()
    val removals = normalizeTagRemovals(meta.tagTombstones + other.meta.tagTombstones, nowMs)

    val localKeys = meta.tags.map { it.trim().lowercase() }.toSet()
    val remoteKeys = other.meta.tags.map { it.trim().lowercase() }.toSet()
    val localMs = meta.updatedAt.toEpochMilli()
    val remoteMs = other.meta.updatedAt.toEpochMilli()

    // Union preserving the first-seen spelling, then suppress removals.
    val byKey = LinkedHashMap<String, String>()
    (meta.tags + other.meta.tags).forEach { raw ->
        val trimmed = raw.trim()
        if (trimmed.isNotEmpty()) byKey.putIfAbsent(trimmed.lowercase(), trimmed)
    }
    val kept = byKey.filter { (key, _) ->
        val removal = removals.find { it.tag == key } ?: return@filter true
        val carriers = buildList {
            if (key in localKeys) add(localMs)
            if (key in remoteKeys) add(remoteMs)
        }
        val oldestCarrier = carriers.minOrNull() ?: return@filter false
        removal.deletedAt.toEpochMilli() < oldestCarrier
    }

    return withMeta {
        it.copy(tags = normalizeTags(kept.values), tagTombstones = removals)
    }
}

/// Records the tag removals this edit makes relative to [existing], and
/// clears the records of tags this edit (re-)adds — the Android twin of the
/// desktop's `with_tag_removals_recorded`.
fun VaultItem.withTagRemovalsRecorded(existing: VaultItem, now: Instant): VaultItem {
    val newKeys = meta.tags.map { it.trim().lowercase() }.toSet()
    val oldKeys = existing.meta.tags.map { it.trim().lowercase() }.toSet()
    val kept = meta.tagTombstones.filter { it.tag !in newKeys }
    val added = (oldKeys - newKeys).map { TagTombstone(it, now) }
    return withMeta {
        it.copy(tagTombstones = normalizeTagRemovals(kept + added, now.toEpochMilli()))
    }
}

/// How many previous passwords are kept per login (§1.3) — the desktop's cap.
const val MAX_PASSWORD_HISTORY: Int = 12

/// Records the previous password into the history when this edit changes a
/// login's password; the diff is against [existing] (the stored copy) and
/// the record is capped, newest first — the Android twin of the desktop's
/// `with_password_history_recorded`.
fun VaultItem.withPasswordHistoryRecorded(existing: VaultItem, now: Instant): VaultItem {
    val login = this as? VaultItem.Login ?: return this
    val existingLogin = existing as? VaultItem.Login ?: return this
    if (login.password == existingLogin.password || existingLogin.password.isEmpty()) {
        return this
    }
    val history = buildList {
        addAll(existingLogin.passwordHistory)
        add(0, PasswordHistoryEntry(existingLogin.password, now))
    }.take(MAX_PASSWORD_HISTORY)
    return login.copy(passwordHistory = history)
}

val VaultItem.url: String? get() = when (this) {
    is VaultItem.Login -> url
    is VaultItem.ApiKey -> url.ifEmpty { null }
    else -> null
}

val VaultItem.username: String? get() = when (this) {
    is VaultItem.Login -> username
    is VaultItem.Passkey -> userName.ifEmpty { userDisplayName.ifEmpty { null } }
    is VaultItem.ApiKey -> username.ifEmpty { null }
    is VaultItem.Address -> fullName.ifEmpty { null }
    is VaultItem.BankAccount -> holder.ifEmpty { null }
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
    is VaultItem.Passkey -> rpId
    // §1.3: no secret to display for an address; the copyable secret for the
    // API key / bank account; the public half for an SSH key.
    is VaultItem.Address -> fullName
    is VaultItem.BankAccount -> accountNumber
    is VaultItem.ApiKey -> apiKey
    is VaultItem.SshKey -> publicKey
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
    is VaultItem.Passkey -> rpId
    is VaultItem.Address -> fullName
    is VaultItem.BankAccount -> if (accountNumber.length >= 4) {
        "\u2022\u2022\u2022\u2022 ${accountNumber.takeLast(4)}"
    } else {
        "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
    }
    is VaultItem.ApiKey -> "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
    is VaultItem.SshKey -> publicKey
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
