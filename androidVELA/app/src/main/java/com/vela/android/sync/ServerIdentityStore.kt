package com.vela.android.sync

import android.content.Context
import com.vela.android.core.NativeVelaCore
import org.json.JSONObject

data class ServerIdentity(
    val userId: String?,
    val deviceId: String?,
    val hybridEkB64: String,
    val hybridVkB64: String,
    val hybridSkB64: String,
    val shareEkB64: String = "",
    val shareDkB64: String = ""
)

class ServerIdentityStore(context: Context) {
    private val prefs = context.getSharedPreferences("vela_server_identity", Context.MODE_PRIVATE)

    fun load(): ServerIdentity? {
        val json = prefs.getString(KEY_IDENTITY_JSON, null) ?: return null
        return runCatching { fromJson(JSONObject(json)) }.getOrNull()
    }

    fun getOrCreate(): ServerIdentity {
        load()?.let { return it }
        val json = NativeVelaCore.generateServerIdentityJson()
            ?: error("Native VELA bridge cannot generate server identity")
        val identity = fromJson(JSONObject(json))
        save(identity)
        return identity
    }

    fun save(identity: ServerIdentity) {
        prefs.edit().putString(KEY_IDENTITY_JSON, identity.toJson().toString()).apply()
    }

    private fun fromJson(json: JSONObject): ServerIdentity {
        return ServerIdentity(
            userId = json.optString("user_id").takeIf { it.isNotBlank() },
            deviceId = json.optString("device_id").takeIf { it.isNotBlank() },
            hybridEkB64 = json.getString("hybrid_ek_b64"),
            hybridVkB64 = json.getString("hybrid_vk_b64"),
            hybridSkB64 = json.getString("hybrid_sk_b64"),
            shareEkB64 = json.optString("share_ek_b64"),
            shareDkB64 = json.optString("share_dk_b64")
        )
    }

    private fun ServerIdentity.toJson(): JSONObject {
        return JSONObject()
            .put("user_id", userId)
            .put("device_id", deviceId)
            .put("hybrid_ek_b64", hybridEkB64)
            .put("hybrid_vk_b64", hybridVkB64)
            .put("hybrid_sk_b64", hybridSkB64)
            .put("share_ek_b64", shareEkB64)
            .put("share_dk_b64", shareDkB64)
    }

    companion object {
        private const val KEY_IDENTITY_JSON = "identity_json"
    }
}
