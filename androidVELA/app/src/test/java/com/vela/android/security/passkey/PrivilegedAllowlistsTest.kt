package com.vela.android.security.passkey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The allowlist union the passkey provider answers origin assertions with. */
class PrivilegedAllowlistsTest {

    private fun app(pkg: String, fingerprint: String, build: String = "release") =
        JSONObject()
            .put(
                "info",
                JSONObject()
                    .put("package_name", pkg)
                    .put(
                        "signatures",
                        JSONArray().put(
                            JSONObject()
                                .put("build", build)
                                .put("cert_fingerprint_sha256", fingerprint),
                        ),
                    ),
            )
            .put("type", "android")

    private fun body(vararg apps: JSONObject) =
        JSONObject().put("apps", JSONArray().apply { apps.forEach { put(it) } }).toString()

    @Test
    fun `the merge unions the shipped sources verbatim`() {
        val google = body(
            app("com.android.chrome", "F0:FD:6C"),
            app("org.mozilla.firefox", "A7:8B:62"),
        )
        val community = body(
            app("org.ironfoxoss.ironfox", "C5:E2:91:B5:A5:71:F9:C8:CD:9A:97:99:C2:C9:4E:02:EC:97:03:94:88:93:F2:CA:75:6D:67:B9:42:04:F9:04"),
        )

        val merged = JSONObject(
            PrivilegedAllowlists.merge(listOf(google, community))!!,
        )
        val apps = merged.getJSONArray("apps")

        assertEquals(3, apps.length())
        val packages = (0 until apps.length()).map { apps.getJSONObject(it).getJSONObject("info").getString("package_name") }
        assertTrue("com.android.chrome" in packages)
        assertTrue("org.mozilla.firefox" in packages)
        assertTrue("org.ironfoxoss.ironfox" in packages)
    }

    @Test
    fun `entries keep their build field so androidx can filter per device`() {
        val userdebug = app("org.mozilla.fenix.debug", "BD:AE:82", build = "userdebug")
        val merged = JSONObject(PrivilegedAllowlists.merge(listOf(body(userdebug)))!!)
        val signature = merged.getJSONArray("apps").getJSONObject(0)
            .getJSONObject("info").getJSONArray("signatures").getJSONObject(0)
        assertEquals("userdebug", signature.getString("build"))
    }

    @Test
    fun `an unparseable source is skipped instead of fatal`() {
        val google = body(app("com.android.chrome", "F0:FD:6C"))
        val merged = PrivilegedAllowlists.merge(listOf("not json", google))!!

        assertEquals(1, JSONObject(merged).getJSONArray("apps").length())
    }

    @Test
    fun `no parseable source means no allowlist`() {
        assertNull(PrivilegedAllowlists.merge(emptyList()))
        assertNull(PrivilegedAllowlists.merge(listOf("{", "garbage")))
    }
}
