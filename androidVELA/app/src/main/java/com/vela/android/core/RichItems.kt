package com.vela.android.core

import org.json.JSONArray
import org.json.JSONObject

/** Immutable JSON records retain fields introduced by newer clients. */
data class RichData(val fields: PreservedJson = PreservedJson()) {
    fun json(): JSONObject = JSONObject().apply { fields.values.forEach { (k,v) -> put(k, org.json.JSONTokener(v).nextValue()) } }
    val folderId: String get() = json().stringOrEmpty("folderId")
    val tagIds: List<String> get() = json().optJSONArray("tagIds").strings()
    val customFields: List<String> get() = json().optJSONArray("customFields").records()
    val additionalUrls: List<String> get() = json().optJSONArray("additionalUrls").records()
    val identity: JSONObject get() = json().optJSONObject("identityDetails") ?: JSONObject()
    val hasData: Boolean get() = folderId.isNotEmpty() || tagIds.isNotEmpty() || customFields.isNotEmpty() || additionalUrls.isNotEmpty() || json().has("identityDetails")
    fun set(key: String, value: Any): RichData = from(json().put(key,value))
    fun setRecords(key: String, records: List<String>) = set(key, JSONArray().apply { records.forEach { put(JSONObject(it)) } })
    override fun toString() = "RichData([REDACTED])"
    companion object { fun from(json: JSONObject) = RichData(json.preserved()) }
}
fun JSONObject.stringOrEmpty(key: String): String = if (isNull(key)) "" else optString(key, "")
fun JSONObject.preserved() = PreservedJson(keys().asSequence().associateWith { key -> JSONArray().put(get(key)).toString().let { it.substring(1,it.length-1) } })
fun JSONArray?.records(): List<String> = if (this == null) emptyList() else (0 until length()).map { getJSONObject(it).toString() }
fun JSONArray?.strings(): List<String> = if (this == null) emptyList() else (0 until length()).map { getString(it) }

/** The envelope's three organization arrays; credentials never enter this object. */
data class VaultOrganization(val enabled: Boolean = false, val data: PreservedJson = PreservedJson()) {
    fun json() = RichData(data).json()
    val folders: List<String> get() = json().optJSONArray("folders").records()
    val tags: List<String> get() = json().optJSONArray("tags").records()
    fun folderPath(id: String): String {
        val byId = folders.map(::JSONObject).associateBy { it.getString("id") }
        val parts = mutableListOf<String>(); val seen = mutableSetOf<String>(); var cursor = id
        while (cursor.isNotEmpty() && seen.add(cursor) && parts.size < 16) {
            val record = byId[cursor] ?: break
            parts.add(0, record.getString("name")); cursor = record.stringOrEmpty("parentId")
        }
        return parts.joinToString(" / ")
    }
    fun containsFolder(id: String) = folders.any { JSONObject(it).optString("id") == id }
    fun containsTag(id: String) = tags.any { JSONObject(it).optString("id") == id }
    fun tagName(id: String) = tags.map(::JSONObject).firstOrNull { it.optString("id") == id }?.optString("name") ?: ""
    fun mutate(action: JSONObject, device: String): VaultOrganization = copy(data = NativeVelaCore.richItems(JSONObject()
        .put("operation","mutate").put("organization",json()).put("deviceId",device).put("action",action)).preserved())
    fun validate(rich: RichData, old: RichData = RichData()) {
        NativeVelaCore.richItems(JSONObject().put("operation","validate").put("organization",json()).put("rich",rich.json()).put("old",old.json()))
    }
    fun repair(rich: RichData): RichData = RichData.from(NativeVelaCore.richItems(JSONObject().put("operation","repair").put("organization",json()).put("rich",rich.json())))
    companion object {
        fun merge(local: VaultOrganization, remote: VaultOrganization): VaultOrganization {
            if (!local.enabled && !remote.enabled) return local
            return VaultOrganization(true, NativeVelaCore.richItems(JSONObject().put("operation","merge").put("organization",local.json()).put("other",remote.json())).preserved())
        }
    }
}
val VaultItem.rich: RichData get() = RichData(meta.richFields)
fun VaultItem.withRich(rich: RichData): VaultItem = withMeta { it.copy(richFields = rich.fields) }
