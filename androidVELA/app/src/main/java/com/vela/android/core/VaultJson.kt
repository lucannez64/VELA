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
        return VaultStore(items, tombstones)
    }

    private fun VaultItem.toJson(): JSONObject {
        val json = metaToJson(meta, JSONObject())

        when (this) {
            is VaultItem.Login -> json
                .put("item_type", "login")
                .put("url", url)
                .put("username", username)
                .put("password", password)
                .put("totp", totp)

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
        }

        return json
    }

    private fun metaToJson(meta: VaultMeta, json: JSONObject): JSONObject = json
        .put("id", meta.id)
        .put("name", meta.name)
        .put("notes", meta.notes)
        .put("createdAt", meta.createdAt.toString())
        .put("updatedAt", meta.updatedAt.toString())
        .put("lastModifiedDevice", meta.lastModifiedDevice)
        .put("favorite", meta.favorite)
        .put("shared", meta.shared)
        .put("shareRecipient", meta.shareRecipient)

    private fun itemFromJson(json: JSONObject): VaultItem? {
        val meta = metaFromJson(json)

        return when (json.optString("item_type")) {
            "login" -> VaultItem.Login(
                meta = meta,
                url = json.optString("url"),
                username = json.optString("username"),
                password = json.optString("password"),
                totp = json.optNullableString("totp"),
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
            shared = json.optBoolean("shared", false),
            shareRecipient = json.optNullableString("share_recipient")
                ?: json.optNullableString("shareRecipient"),
        )
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
