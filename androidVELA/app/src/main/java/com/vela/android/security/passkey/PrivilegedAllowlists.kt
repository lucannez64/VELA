package com.vela.android.security.passkey

import org.json.JSONArray
import org.json.JSONObject

/**
 * The union of the shipped "may speak for an origin" lists, in the single
 * JSON document [CallingAppInfo.getOrigin] parses.
 *
 * Google's list covers the Chrome family and the Mozilla releases Google
 * carries; the community list covers the forks Google does not (IronFox,
 * Cromite, Iceraven, …); the VELA list covers browsers verified by hand.
 * The autofill side already trusts exactly this union — see
 * [com.vela.android.autofill.BrowserAllowlist] for the curation policy — so
 * the passkey provider answering origin assertions with a narrower set was
 * an inconsistency, not a safety margin: the same browser, same
 * certificate, same question, different answer.
 *
 * Entries are kept verbatim — androidx itself decides which signature
 * `build` types apply to the running device — and packages appearing in
 * several sources simply accumulate, which its matcher treats additively.
 * A source that fails to parse is skipped, never fatal: a ceremony must
 * still honor Google's list if a fork's file went missing.
 */
internal object PrivilegedAllowlists {

    /** The merge itself; null only when no source was parseable at all. */
    fun merge(bodies: List<String>): String? {
        val apps = JSONArray()
        var parsedAny = false
        for (body in bodies) {
            val source = runCatching { JSONObject(body).optJSONArray("apps") }.getOrNull() ?: continue
            parsedAny = true
            for (index in 0 until source.length()) {
                (source.optJSONObject(index) ?: continue).let { apps.put(it) }
            }
        }
        if (!parsedAny) return null
        return JSONObject().put("apps", apps).toString()
    }
}
