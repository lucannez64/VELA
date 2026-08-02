package com.vela.android.autofill

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The browser allowlist, checked against the JSON we actually ship.
 *
 * Trusting a browser's `webDomain` is a real grant, so the parse has to be
 * strict about what counts as an entry — an entry that loses its fingerprint
 * would silently become name-only trust.
 */
class BrowserAllowlistTest {

    private fun asset(name: String): String =
        File("src/main/assets/$name").readText()

    private val shipped: Map<String, Set<String>> by lazy {
        BrowserAllowlist.parse(asset("privileged_browsers_google.json")) +
            BrowserAllowlist.parse(asset("privileged_browsers_community.json")) +
            BrowserAllowlist.parse(asset("privileged_browsers_vela.json"))
    }

    // ── The shipped data ───────────────────────────────────────────────────

    @Test
    fun `the shipped lists cover the mainstream browsers`() {
        for (pkg in listOf(
            "com.android.chrome",
            "org.mozilla.firefox",
            "com.brave.browser",
            "com.duckduckgo.mobile.android",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.sec.android.app.sbrowser",
            "com.vivaldi.browser",
        )) {
            assertTrue("$pkg should be pinned", shipped.containsKey(pkg))
        }
    }

    @Test
    fun `the community list adds the privacy forks google does not name`() {
        val community = BrowserAllowlist.parse(asset("privileged_browsers_community.json"))
        assertTrue(community.containsKey("org.ironfoxoss.ironfox"))
        assertTrue(community.containsKey("org.cromite.cromite"))
        assertTrue(community.containsKey("org.mozilla.fennec_fdroid"))
    }

    @Test
    fun `every shipped entry carries at least one fingerprint`() {
        assertTrue("expected a substantial list, got ${shipped.size}", shipped.size >= 70)
        for ((pkg, fingerprints) in shipped) {
            assertTrue("$pkg has no fingerprint", fingerprints.isNotEmpty())
            for (fingerprint in fingerprints) {
                assertEquals(
                    "$pkg fingerprint is not a SHA-256: $fingerprint",
                    95, // 32 bytes as AB:CD:… → 32*2 + 31 separators
                    fingerprint.length,
                )
                assertEquals(fingerprint, fingerprint.uppercase())
            }
        }
    }

    @Test
    fun `packages are lowercase so lookups can find them`() {
        // isTrustedBrowser lowercases the incoming package before the lookup.
        for (pkg in shipped.keys) {
            assertEquals("$pkg must be lowercase to be looked up", pkg.lowercase(), pkg)
        }
    }

    @Test
    fun `the browsers we verified ourselves are pinned`() {
        // Certificates taken from the vendor's own APK; see the provenance
        // recorded against each entry in privileged_browsers_vela.json (#125).
        val vela = BrowserAllowlist.parse(asset("privileged_browsers_vela.json"))
        assertEquals(
            setOf("20:06:1F:04:5E:73:7C:67:37:5C:17:79:4C:FE:DB:43:6A:03:CE:C6:BA:CB:7C:B9:F9:66:42:20:5C:A2:CE:C8"),
            vela["org.torproject.torbrowser"],
        )
        assertEquals(
            setOf("82:9B:93:0E:91:9C:D5:6C:9A:67:61:7C:31:2E:3B:42:5A:38:89:4B:92:9E:73:5C:3D:39:1D:9C:51:B9:E4:C0"),
            vela["com.kiwibrowser.browser"],
        )
    }

    @Test
    fun `the browsers still without a fingerprint get no trust at all`() {
        // There is no name-only tier: a package name is the thing A-2 is about.
        // These are real browsers no list names, so they are simply absent — and
        // absent means untrusted, with the cost that passwords saved in them are
        // filed under the package rather than the site. Move one out of here the
        // moment its certificate can be verified.
        for (pkg in listOf(
            "com.ecosia.android",
            "com.opera.gx",
            "com.ucmobile.intl",
        )) {
            assertFalse("$pkg is pinned now — update this test", shipped.containsKey(pkg))
        }
    }

    // ── Parsing ────────────────────────────────────────────────────────────

    @Test
    fun `an entry without a fingerprint is not an entry`() {
        // Otherwise it would quietly degrade to trusting the package name.
        val json = """
            {"apps":[{"type":"android","info":{"package_name":"com.example.browser","signatures":[]}}]}
        """.trimIndent()
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse(json))
    }

    @Test
    fun `non-android entries are ignored`() {
        val json = """
            {"apps":[{"type":"web","info":{"package_name":"com.example.browser",
              "signatures":[{"cert_fingerprint_sha256":"AA:BB"}]}}]}
        """.trimIndent()
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse(json))
    }

    @Test
    fun `all fingerprints for a package are kept`() {
        // Chrome ships release and userdebug keys; matching either is correct.
        val json = """
            {"apps":[{"type":"android","info":{"package_name":"com.example.browser","signatures":[
              {"build":"release","cert_fingerprint_sha256":"aa:bb"},
              {"build":"userdebug","cert_fingerprint_sha256":"cc:dd"}]}}]}
        """.trimIndent()
        assertEquals(mapOf("com.example.browser" to setOf("AA:BB", "CC:DD")), BrowserAllowlist.parse(json))
    }

    @Test
    fun `package names are normalised for lookup`() {
        val json = """
            {"apps":[{"type":"android","info":{"package_name":"COM.Example.Browser",
              "signatures":[{"cert_fingerprint_sha256":"aa:bb"}]}}]}
        """.trimIndent()
        assertTrue(BrowserAllowlist.parse(json).containsKey("com.example.browser"))
    }

    @Test
    fun `malformed documents yield no trust`() {
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse(""))
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse("not json"))
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse("{}"))
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse("""{"apps":[]}"""))
        assertEquals(emptyMap<String, Set<String>>(), BrowserAllowlist.parse("""{"apps":[{}]}"""))
        assertEquals(
            emptyMap<String, Set<String>>(),
            BrowserAllowlist.parse("""{"apps":[{"type":"android"}]}"""),
        )
    }
}
