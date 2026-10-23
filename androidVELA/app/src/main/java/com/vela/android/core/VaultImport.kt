package com.vela.android.core

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.UUID

/** Result of one import run, mirroring the desktop report. */
data class ImportReport(
    val source: String,
    val added: Int,
    val duplicates: Int,
    val skipped: Int,
    val preserved: Int,
    val converted: Int,
    val unsupported: List<String>,
) {
    /** One line suitable for the settings row. */
    fun summary(): String {
        val builder = StringBuilder()
        if (source.isNotEmpty()) builder.append(source).append(": ")
        builder.append("imported ").append(added)
        if (duplicates > 0) builder.append(", ").append(duplicates).append(" already in vault")
        if (preserved > 0) builder.append(", ").append(preserved).append(" with folders/tags/fields")
        if (converted > 0) builder.append(", ").append(converted).append(" converted to notes")
        if (skipped > 0) builder.append(", ").append(skipped).append(" item types skipped")
        if (unsupported.isNotEmpty()) builder.append(" · unsupported: ").append(unsupported.joinToString(", "))
        return builder.toString()
    }
}

/**
 * Shared parsing/mapping helpers for the Android file picker. Parsing happens
 * in Rust (`vela-import` through the JNI bridge); this file only maps the
 * neutral entry JSON onto the Android vault model.
 */
object VaultImport {
    fun parse(bytes: ByteArray): JSONObject =
        NativeVelaCore.parseImport(
            JSONObject().put("dataBase64", Base64.encodeToString(bytes, Base64.NO_WRAP)),
        )

    fun reportFrom(response: JSONObject, added: Int, duplicates: Int, preserved: Int, converted: Int): ImportReport {
        val unsupported = response.optJSONObject("unsupported")?.let { map ->
            map.keys().asSequence().map { key -> "$key ×${map.optInt(key)}" }.toList()
        } ?: emptyList()
        return ImportReport(
            source = response.optString("source"),
            added = added,
            duplicates = duplicates,
            skipped = response.optInt("skippedUnsupported"),
            preserved = preserved,
            converted = converted,
            unsupported = unsupported,
        )
    }

    fun loginKey(url: String, name: String, username: String): String =
        "${url.trim().lowercase(Locale.US)}|${name.trim().lowercase(Locale.US)}|${username.trim().lowercase(Locale.US)}"

    fun cardKey(number: String, name: String): String =
        "${number.filter(Char::isDigit).takeLast(4)}|${name.trim().lowercase(Locale.US)}"

    fun identityKey(name: String, notes: String): String =
        "${name.trim().lowercase(Locale.US)}|${notes.trim().lowercase(Locale.US)}"

    /** Custom field records the vault can hold; returns the records and how many were dropped. */
    fun customFieldRecords(entry: JSONObject): Pair<JSONArray, Int> {
        val fields = entry.optJSONArray("fields") ?: return JSONArray() to 0
        val records = JSONArray()
        var dropped = 0
        for (index in 0 until fields.length()) {
            val field = fields.optJSONObject(index) ?: continue
            val label = field.optString("label").trim()
            if (label.isEmpty()) { dropped++; continue }
            val kind = when (field.optString("kind")) {
                "concealed" -> "concealed"
                "boolean" -> "boolean"
                else -> "text"
            }
            val raw = field.opt("value")
            val value = when (kind) {
                "boolean" -> (raw == true || raw?.toString()?.lowercase(Locale.US) in listOf("true", "1", "yes"))
                else -> raw?.toString() ?: ""
            }
            records.put(
                JSONObject()
                    .put("id", UUID.randomUUID().toString())
                    .put("label", label)
                    .put("type", kind)
                    .put("value", value),
            )
        }
        return records to dropped
    }

    fun additionalUrlRecords(entry: JSONObject): JSONArray {
        val urls = entry.optJSONArray("extraUrls") ?: return JSONArray()
        val records = JSONArray()
        for (index in 0 until urls.length()) {
            val url = urls.optString(index).trim()
            if (url.isEmpty()) continue
            records.put(
                JSONObject()
                    .put("id", UUID.randomUUID().toString())
                    .put("url", url)
                    .put("match", "exact"),
            )
        }
        return records
    }

    fun identityDetails(entry: JSONObject): JSONObject? {
        val identity = entry.optJSONObject("identity") ?: return null
        val details = JSONObject()
        fun put(key: String, value: String) { if (value.isNotBlank()) details.put(key, value) }
        put("middleName", identity.optString("middle"))
        put("email", identity.optString("email"))
        put("phone", identity.optString("phone"))
        put("company", identity.optString("company"))
        put("jobTitle", identity.optString("jobTitle"))
        val addresses = identity.optJSONArray("addresses")
        if (addresses != null && addresses.length() > 0) {
            val records = JSONArray()
            for (index in 0 until addresses.length()) {
                val address = addresses.optJSONObject(index) ?: continue
                val joined = listOf("line1", "city", "postal").any { address.optString(it).isNotBlank() }
                if (!joined) continue
                records.put(
                    JSONObject()
                        .put("id", UUID.randomUUID().toString())
                        .put("label", address.optString("label"))
                        .put("line1", address.optString("line1"))
                        .put("line2", address.optString("line2"))
                        .put("city", address.optString("city"))
                        .put("region", address.optString("region"))
                        .put("postalCode", address.optString("postal"))
                        .put("countryCode", address.optString("country")),
                )
            }
            if (records.length() > 0) details.put("addresses", records)
        }
        return details.takeIf { it.length() > 0 }
    }

    /** Rich metadata for an entry once folders/tags have been resolved. */
    fun richJson(entry: JSONObject, folderId: String?, tagIds: List<String>, droppedFields: Int): JSONObject {
        val rich = JSONObject()
        if (!folderId.isNullOrEmpty()) rich.put("folderId", folderId)
        if (tagIds.isNotEmpty()) rich.put("tagIds", JSONArray(tagIds))
        val (fields, _) = customFieldRecords(entry)
        if (fields.length() > 0) rich.put("customFields", fields)
        val urls = additionalUrlRecords(entry)
        if (urls.length() > 0) rich.put("additionalUrls", urls)
        identityDetails(entry)?.let { rich.put("identityDetails", it) }
        return rich
    }

    /** Everything a schema-1 vault cannot hold, as notes the user can still read. */
    fun foldIntoNotes(entry: JSONObject): String {
        val lines = mutableListOf<String>()
        entry.optString("folder").takeIf { it.isNotBlank() }?.let { lines += "Folder: $it" }
        val tags = entry.optJSONArray("tags")
        if (tags != null && tags.length() > 0) {
            lines += "Tags: " + (0 until tags.length()).joinToString(", ") { tags.optString(it) }
        }
        val (fields, _) = customFieldRecords(entry)
        if (fields.length() > 0) {
            lines += "Custom fields:"
            for (index in 0 until fields.length()) {
                val field = fields.optJSONObject(index) ?: continue
                lines += "  ${field.optString("label")}: ${field.opt("value")}"
            }
        }
        val urls = entry.optJSONArray("extraUrls")
        if (urls != null && urls.length() > 0) {
            lines += "Additional websites:"
            for (index in 0 until urls.length()) lines += "  ${urls.optString(index)}"
        }
        if (entry.optString("kind") == "identity") {
            val identity = entry.optJSONObject("identity")
            if (identity != null) {
                val details = mutableListOf<String>()
                listOf("email" to "Email", "phone" to "Phone", "company" to "Company", "jobTitle" to "Job title")
                    .forEach { (key, label) ->
                        identity.optString(key).takeIf { it.isNotBlank() }?.let { details += "  $label: $it" }
                    }
                val addresses = identity.optJSONArray("addresses")
                if (addresses != null) {
                    for (index in 0 until addresses.length()) {
                        val address = addresses.optJSONObject(index) ?: continue
                        val joined = listOf("line1", "line2", "city", "region", "postal", "country")
                            .map { address.optString(it) }.filter { it.isNotBlank() }.joinToString(", ")
                        if (joined.isNotBlank()) details += "  Address: $joined"
                    }
                }
                if (details.isNotEmpty()) {
                    lines += "Identity:"
                    lines += details
                }
            }
        }
        return lines.joinToString("\n")
    }
}
