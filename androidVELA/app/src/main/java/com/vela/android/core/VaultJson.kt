package com.vela.android.core

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

object VaultJson {
    fun encodeItem(item: VaultItem): ByteArray = item.toJson().toString().toByteArray(Charsets.UTF_8)

    fun decodeItem(bytes: ByteArray): VaultItem? = itemFromJson(JSONObject(bytes.toString(Charsets.UTF_8)))

    fun encode(store: VaultStore): ByteArray {
        val root = JSONObject()
        val items = JSONArray()
        store.items.forEach { item -> items.put(item.toJson()) }
        root.put("items", items)
        root.put("tombstones", JSONArray().also { tombstones ->
            store.tombstones.forEach { tombstones.put(it.toJson()) }
        })
        if (store.deletedItems.isNotEmpty()) {
            root.put("deleted_items", JSONArray().also { deleted ->
                store.deletedItems.forEach { entry ->
                    deleted.put(
                        JSONObject()
                            .put("item", entry.item.toJson())
                            .put("deleted_at", entry.deletedAt.toString())
                            .put("deleted_by", entry.deletedBy)
                    )
                }
            })
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun decode(bytes: ByteArray): VaultStore {
        if (bytes.isEmpty()) return VaultStore()
        val root = JSONObject(bytes.toString(Charsets.UTF_8))
        val itemsJson = root.optJSONArray("items") ?: JSONArray()
        val items = buildList {
            for (index in 0 until itemsJson.length()) {
                itemFromJson(itemsJson.getJSONObject(index))?.let(::add)
            }
        }
        val tombstonesJson = root.optJSONArray("tombstones") ?: JSONArray()
        val tombstones = buildList {
            for (index in 0 until tombstonesJson.length()) {
                add(tombstoneFromJson(tombstonesJson.getJSONObject(index)))
            }
        }
        // The trash (§1.2): optional (A-2) — written by desktop clients that
        // own delete/restore, carried through untouched here.
        val deletedJson = root.optJSONArray("deleted_items") ?: JSONArray()
        val deletedItems = buildList {
            for (index in 0 until deletedJson.length()) {
                val entry = deletedJson.getJSONObject(index)
                val item = entry.optJSONObject("item")?.let { itemFromJson(it) } ?: continue
                val deletedAt = runCatching {
                    Instant.parse(entry.optString("deleted_at"))
                }.getOrDefault(Instant.now())
                add(
                    DeletedItem(
                        item = item,
                        deletedAt = deletedAt,
                        deletedBy = entry.optNullableString("deleted_by"),
                    )
                )
            }
        }
        return VaultStore(items, tombstones, deletedItems)
    }

    private fun VaultItem.toJson(): JSONObject {
        val json = metaToJson(meta, JSONObject())

        when (this) {
            is VaultItem.Login -> {
                json
                    .put("item_type", "login")
                    .put("url", url)
                    .put("username", username)
                    .put("password", password)
                    .put("totp", totp)
                    .put("app_ids", JSONArray().also { array -> appIds.forEach { array.put(it) } })
                // §1.3: previous password values (newest first), only when
                // there is any — matching the desktop's skip-if-empty.
                if (passwordHistory.isNotEmpty()) {
                    json.put(
                        "password_history",
                        JSONArray().apply {
                            passwordHistory.forEach { entry ->
                                put(
                                    org.json.JSONObject()
                                        .put("password", entry.password)
                                        .put("changed_at", entry.changedAt.toString())
                                )
                            }
                        }
                    )
                }
            }

            is VaultItem.CreditCard -> json
                .put("item_type", "creditCard")
                .put("number", cardNumber)
                .put("exp", expiration)
                .put("cvv", cvv)
                .put("pin", pin)
                .put("cardholderName", cardholderName)

            is VaultItem.SecureNote -> json
                .put("item_type", "secureNote")
                .put("title", meta.name)
                .put("content", content)

            is VaultItem.FileBlob -> json
                .put("item_type", "fileBlob")
                .put("filename", fileName)
                .put("mime", mimeType)
                .put("chunks", JSONArray())
                .put("sizeBytes", sizeBytes)

            is VaultItem.BreachMonitor -> json
                .put("item_type", "breachMonitor")
                .put("email", email)
                .put("checkedAt", checkedAt?.toString())
                .put("breachCount", breachCount)
                .put("breaches", JSONArray().also { array ->
                    breaches.forEach { array.put(it.toJson()) }
                })

            // The private key is included when this device holds one (created
            // here, or synced from a device that did), so passkeys keep working
            // on every device. A metadata-only passkey encodes without the
            // field: the desktop treats a missing key as "restore the stored
            // one", so uploading a keyless item can never wipe a credential.
            is VaultItem.Passkey -> json
                .put("item_type", "passkey")
                .put("rp_id", rpId)
                .put("rp_name", rpName)
                .put("credential_id", credentialId)
                .put("user_handle", userHandle)
                .put("user_name", userName)
                .put("user_display_name", userDisplayName)
                .apply { if (privateKey.isNotEmpty()) put("private_key", privateKey) }
                .put("sign_count", signCount)

            // §1.3: snake_case keys to match the desktop's variant fields.
            is VaultItem.Address -> json
                .put("item_type", "address")
                .put("full_name", fullName)
                .put("street", street)
                .put("street_line2", streetLine2)
                .put("city", city)
                .put("state", state)
                .put("postal_code", postalCode)
                .put("country", country)
                .put("phone", phone)

            is VaultItem.BankAccount -> json
                .put("item_type", "bankAccount")
                .put("bank_name", bankName)
                .put("account_kind", accountKind)
                .put("holder", holder)
                .put("account_number", accountNumber)
                .put("routing_number", routingNumber)
                .put("iban", iban)
                .put("swift", swift)

            is VaultItem.ApiKey -> json
                .put("item_type", "apiKey")
                .put("url", url)
                .put("username", username)
                .put("api_key", apiKey)
                .put("expires", expires)

            is VaultItem.SshKey -> json
                .put("item_type", "sshKey")
                .put("kind", kind)
                .put("public_key", publicKey)
                .put("private_key", privateKey)
                .put("passphrase", passphrase)
                .put("comment", comment)
        }

        return json
    }

    private fun metaToJson(meta: VaultMeta, json: JSONObject): JSONObject {
        json
            .put("id", meta.id)
            .put("name", meta.name)
            .put("notes", meta.notes)
            .put("createdAt", meta.createdAt.toString())
            .put("updatedAt", meta.updatedAt.toString())
            .put("lastModifiedDevice", meta.lastModifiedDevice)
            .put("favorite", meta.favorite)
            // §1.1: written unconditionally (an empty list is meaningful), the
            // folder only when set — matching the desktop serde shape.
            .put("tags", org.json.JSONArray(meta.tags))
        if (meta.tagTombstones.isNotEmpty()) {
            json.put(
                "tagTombstones",
                org.json.JSONArray().apply {
                    meta.tagTombstones.forEach { removal ->
                        put(
                            org.json.JSONObject()
                                .put("tag", removal.tag)
                                .put("deleted_at", removal.deletedAt.toString())
                        )
                    }
                }
            )
        }
        // §1.3: user-defined extra fields (the desktop calls them
        // `customFields`; the inner `field_type` is snake_case there).
        if (meta.customFields.isNotEmpty()) {
            json.put(
                "customFields",
                org.json.JSONArray().apply {
                    meta.customFields.forEach { field ->
                        put(
                            org.json.JSONObject()
                                .put("label", field.label)
                                .put("value", field.value)
                                .put("field_type", if (field.fieldType == CustomFieldType.Hidden) "hidden" else "text")
                        )
                    }
                }
            )
        }
        if (meta.folder != null) {
            json.put("folder", meta.folder)
        }
        return json
            .put("shared", meta.shared)
            .put("shareRecipient", meta.shareRecipient)
    }

    private fun itemFromJson(json: JSONObject): VaultItem? {
        val meta = metaFromJson(json)

        return when (json.optString("item_type")) {
            "login" -> VaultItem.Login(
                meta = meta,
                url = json.optString("url"),
                username = json.optString("username"),
                password = json.optString("password"),
                totp = json.optNullableString("totp"),
                appIds = json.stringList("app_ids", "appIds"),
                passwordHistory = passwordHistoryFromJson(json),
            )

            "creditCard", "creditcard", "card" -> VaultItem.CreditCard(
                meta = meta,
                cardNumber = json.firstString("number", "card_number", "cardNumber")
                    .ifBlank { json.firstStringByKey { key -> key.contains("number", ignoreCase = true) } }
                    .ifBlank {
                        json.firstStringDeep { key ->
                            key.equals("number", ignoreCase = true) ||
                                key.equals("card_number", ignoreCase = true) ||
                                key.equals("cardNumber", ignoreCase = true)
                        }
                    },
                expiration = json.firstString("exp", "card_exp", "expiration", "expiry")
                    .ifBlank {
                        json.firstStringByKey { key ->
                            key.equals("exp", ignoreCase = true) ||
                                key.contains("expir", ignoreCase = true) ||
                                key.contains("expiry", ignoreCase = true)
                        }
                    }
                    .ifBlank {
                        json.firstStringDeep { key ->
                            key.equals("exp", ignoreCase = true) ||
                                key.contains("expir", ignoreCase = true) ||
                                key.contains("expiry", ignoreCase = true)
                        }
                    },
                cvv = json.firstString("cvv", "cvc", "security_code"),
                pin = json.optNullableString("pin"),
                cardholderName = json.firstString("cardholder_name", "cardholderName", "holder", "name_on_card"),
            )

            "paymentCard", "payment_card" -> VaultItem.CreditCard(
                meta = meta,
                cardNumber = json.firstStringDeep { key ->
                    key.equals("number", ignoreCase = true) ||
                        key.equals("card_number", ignoreCase = true) ||
                        key.equals("cardNumber", ignoreCase = true)
                },
                expiration = json.firstStringDeep { key ->
                    key.equals("exp", ignoreCase = true) ||
                        key.contains("expir", ignoreCase = true) ||
                        key.contains("expiry", ignoreCase = true)
                },
                cvv = json.firstStringDeep { key ->
                    key.equals("cvv", ignoreCase = true) ||
                        key.equals("cvc", ignoreCase = true) ||
                        key.equals("security_code", ignoreCase = true)
                },
                pin = json.firstStringDeep { key -> key.equals("pin", ignoreCase = true) }.ifBlank { null },
                cardholderName = json.firstStringDeep { key ->
                    key.equals("cardholder_name", ignoreCase = true) ||
                        key.equals("cardholderName", ignoreCase = true) ||
                        key.equals("name_on_card", ignoreCase = true)
                },
            )

            "secureNote" -> VaultItem.SecureNote(
                meta = meta,
                content = json.firstString("content", "secure_note_content", "notes"),
            )

            "breachMonitor", "breachmonitor" -> VaultItem.BreachMonitor(
                meta = meta,
                email = json.optString("email"),
                checkedAt = json.optNullableString("checked_at")?.let { runCatching { Instant.parse(it) }.getOrNull() },
                breachCount = json.optInt("breach_count", 0),
                breaches = json.optJSONArray("breaches")?.let { breachesJson ->
                    buildList {
                        for (index in 0 until breachesJson.length()) {
                            add(breachFromJson(breachesJson.getJSONObject(index)))
                        }
                    }
                }.orEmpty(),
            )

            "passkey" -> VaultItem.Passkey(
                meta = meta,
                rpId = json.optString("rp_id", json.optString("rpId")),
                rpName = json.optString("rp_name", json.optString("rpName")),
                credentialId = json.optString("credential_id", json.optString("credentialId")),
                userHandle = json.optString("user_handle", json.optString("userHandle")),
                userName = json.optString("user_name", json.optString("userName")),
                userDisplayName = json.optString("user_display_name", json.optString("userDisplayName")),
                privateKey = json.optString("private_key", json.optString("privateKey")),
                signCount = json.optLong("sign_count", json.optLong("signCount", 0)),
            )

            // §1.3 new item types: snake_case keys to match the desktop's
            // variant fields, with camelCase tolerated on read.
            "address" -> VaultItem.Address(
                meta = meta,
                fullName = json.optString("full_name", json.optString("fullName")),
                street = json.optString("street", json.optString("street_address")),
                streetLine2 = json.optString("street_line2", json.optString("streetLine2")),
                city = json.optString("city"),
                state = json.optString("state"),
                postalCode = json.optString("postal_code", json.optString("postalCode", json.optString("zip"))),
                country = json.optString("country"),
                phone = json.optString("phone"),
            )

            "bankAccount", "bankaccount" -> VaultItem.BankAccount(
                meta = meta,
                bankName = json.optString("bank_name", json.optString("bankName")),
                accountKind = json.optString("account_kind", json.optString("account_type", json.optString("accountKind"))),
                holder = json.optString("holder"),
                accountNumber = json.optString("account_number", json.optString("accountNumber")),
                routingNumber = json.optString("routing_number", json.optString("routingNumber")),
                iban = json.optString("iban"),
                swift = json.optString("swift"),
            )

            "apiKey", "apikey" -> VaultItem.ApiKey(
                meta = meta,
                url = json.optString("url", json.optString("base_url")),
                username = json.optString("username"),
                apiKey = json.optString("api_key", json.optString("apiKey")),
                expires = json.optNullableString("expires")
                    ?: json.optNullableString("expires_at"),
            )

            "sshKey", "sshkey", "ssh_key" -> VaultItem.SshKey(
                meta = meta,
                kind = json.optString("kind", json.optString("keyType", json.optString("key_type"))),
                publicKey = json.optString("public_key", json.optString("publicKey")),
                privateKey = json.optString("private_key", json.optString("privateKey")),
                passphrase = json.optString("passphrase"),
                comment = json.optString("comment"),
            )

            else -> null
        }
    }

    private fun metaFromJson(json: JSONObject): VaultMeta {
        val createdAt = Instant.parse(json.optString("created_at", json.optString("createdAt", Instant.now().toString())))
        val updatedAt = Instant.parse(json.optString("updated_at", json.optString("updatedAt", createdAt.toString())))
        return VaultMeta(
            id = json.getString("id"),
            name = json.optString("name", json.optString("title", "Untitled")),
            notes = json.optNullableString("notes"),
            createdAt = createdAt,
            updatedAt = updatedAt,
            lastModifiedDevice = json.optNullableString("last_modified_device")
                ?: json.optNullableString("lastModifiedDevice"),
            favorite = json.optBoolean("favorite", false),
            tags = json.stringList("tags"),
            tagTombstones = tagTombstonesFromJson(json),
            customFields = customFieldsFromJson(json),
            folder = json.optNullableString("folder")?.takeIf { it.isNotBlank() },
            shared = json.optBoolean("shared", false),
            shareRecipient = json.optNullableString("share_recipient")
                ?: json.optNullableString("shareRecipient"),
        )
    }

    /** Tag removal records, tolerant of both key spellings and of the
     *  desktop's inner `deleted_at` (this app's own `deletedAt` too). */
    private fun tagTombstonesFromJson(json: JSONObject): List<TagTombstone> {
        val array = json.optJSONArray("tagTombstones")
            ?: json.optJSONArray("tag_tombstones")
            ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val entry = array.getJSONObject(index)
                val deletedAt = entry.optNullableString("deleted_at")
                    ?: entry.optNullableString("deletedAt")
                    ?: continue
                val parsed = runCatching { Instant.parse(deletedAt) }.getOrNull() ?: continue
                add(TagTombstone(tag = entry.optString("tag"), deletedAt = parsed))
            }
        }
    }

    /** §1.3: previous password values, tolerant of the desktop's inner
     *  `password`/`changed_at` spellings. */
    private fun passwordHistoryFromJson(json: JSONObject): List<PasswordHistoryEntry> {
        val array = json.optJSONArray("password_history")
            ?: json.optJSONArray("passwordHistory")
            ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val entry = array.getJSONObject(index)
                val changedAt = entry.optNullableString("changed_at")
                    ?: entry.optNullableString("changedAt")
                    ?: continue
                val parsed = runCatching { Instant.parse(changedAt) }.getOrNull() ?: continue
                add(PasswordHistoryEntry(password = entry.optString("password"), changedAt = parsed))
            }
        }
    }

    /** §1.3: user-defined extra fields, tolerant of the desktop's
     *  `customFields`/`custom_fields` spellings. */
    private fun customFieldsFromJson(json: JSONObject): List<CustomField> {
        val array = json.optJSONArray("customFields")
            ?: json.optJSONArray("custom_fields")
            ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val entry = array.getJSONObject(index)
                val type = when (entry.optString("field_type", entry.optString("fieldType", "text"))) {
                    "hidden" -> CustomFieldType.Hidden
                    else -> CustomFieldType.Text
                }
                add(
                    CustomField(
                        label = entry.optString("label"),
                        value = entry.optString("value"),
                        fieldType = type,
                    )
                )
            }
        }
    }

    private fun BreachEntry.toJson(): JSONObject = JSONObject()
        .put("name", name)
        .put("title", title)
        .put("domain", domain)
        .put("breach_date", breachDate)
        .put("description", description)
        .put("data_classes", JSONArray().also { array -> dataClasses.forEach(array::put) })
        .put("is_verified", isVerified)
        .put("is_fabricated", isFabricated)
        .put("is_sensitive", isSensitive)
        .put("is_retired", isRetired)
        .put("is_spam_list", isSpamList)

    private fun Tombstone.toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("deleted_at", deletedAt.toString())
        .put("deleted_by", deletedBy)

    private fun tombstoneFromJson(json: JSONObject): Tombstone = Tombstone(
        id = json.getString("id"),
        deletedAt = runCatching { Instant.parse(json.optString("deleted_at")) }.getOrDefault(Instant.EPOCH),
        deletedBy = json.optNullableString("deleted_by")
    )

    private fun breachFromJson(json: JSONObject): BreachEntry = BreachEntry(
        name = json.optString("name"),
        title = json.optString("title", json.optString("Name")),
        domain = json.optString("domain"),
        breachDate = json.optString("breach_date"),
        description = json.optString("description"),
        dataClasses = json.optJSONArray("data_classes")?.let { array ->
            buildList {
                for (index in 0 until array.length()) {
                    add(array.optString(index))
                }
            }
        }.orEmpty(),
        isVerified = json.optBoolean("is_verified", false),
        isFabricated = json.optBoolean("is_fabricated", false),
        isSensitive = json.optBoolean("is_sensitive", false),
        isRetired = json.optBoolean("is_retired", false),
        isSpamList = json.optBoolean("is_spam_list", false)
    )

    private fun JSONObject.firstString(vararg names: String): String {
        for (name in names) {
            if (has(name) && !isNull(name)) {
                val value = optString(name)
                if (value.isNotEmpty()) return value
            }
        }
        return ""
    }

    /** First present string array among [names], as a list. */
    private fun JSONObject.stringList(vararg names: String): List<String> {
        for (name in names) {
            val array = optJSONArray(name) ?: continue
            return (0 until array.length())
                .mapNotNull { array.optString(it).takeIf { value -> value.isNotBlank() } }
        }
        return emptyList()
    }

    private fun JSONObject.firstStringByKey(predicate: (String) -> Boolean): String {
        val keys = keys()
        while (keys.hasNext()) {
            val key = keys.next()
            if (predicate(key) && has(key) && !isNull(key)) {
                val value = optString(key)
                if (value.isNotEmpty()) return value
            }
        }
        return ""
    }

    private fun JSONObject.firstStringDeep(predicate: (String) -> Boolean): String {
        firstStringByKey(predicate).takeIf { it.isNotEmpty() }?.let { return it }

        val keys = keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val nested = opt(key)
            val result = when (nested) {
                is JSONObject -> nested.firstStringDeep(predicate)
                is JSONArray -> nested.firstStringDeep(predicate)
                else -> ""
            }
            if (result.isNotEmpty()) return result
        }
        return ""
    }

    private fun JSONArray.firstStringDeep(predicate: (String) -> Boolean): String {
        for (index in 0 until length()) {
            val result = when (val nested = opt(index)) {
                is JSONObject -> nested.firstStringDeep(predicate)
                is JSONArray -> nested.firstStringDeep(predicate)
                else -> ""
            }
            if (result.isNotEmpty()) return result
        }
        return ""
    }

    private fun JSONObject.optNullableString(name: String): String? {
        if (!has(name) || isNull(name)) return null
        return optString(name).takeIf { it.isNotEmpty() }
    }
}
