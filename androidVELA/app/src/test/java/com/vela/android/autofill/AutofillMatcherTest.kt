package com.vela.android.autofill

import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rules that decide where a saved password may be sent (audit A-2).
 *
 * Every case here is really the same question: what vouched for this pairing?
 */
class AutofillMatcherTest {

    private fun login(
        name: String,
        url: String,
        appIds: List<String> = emptyList(),
    ): VaultItem.Login {
        val now = Instant.parse("2026-01-01T00:00:00Z")
        return VaultItem.Login(
            meta = VaultMeta(name = name, createdAt = now, updatedAt = now),
            url = url,
            username = "user@example.com",
            password = "hunter2",
            appIds = appIds,
        )
    }

    private val paypal = login("PayPal", "https://paypal.com")
    private val bank = login("Bank", "https://bank.example")
    private val vault = listOf(paypal, bank)

    // ── The attack the finding describes ───────────────────────────────────

    @Test
    fun `package name is not turned into a domain`() {
        // com.paypal.evil is publishable by anyone on a third-party store. The
        // old `com.<x>` -> `<x>.com` rule handed it PayPal's password.
        assertEquals(emptyList<VaultItem.Login>(), AutofillMatcher.match(vault, null, "com.paypal.evil"))
        assertEquals(emptyList<VaultItem.Login>(), AutofillMatcher.match(vault, null, "com.bank.impostor"))
    }

    @Test
    fun `a non-browser app cannot claim a domain`() {
        // Any app may call ViewStructure.setWebDomain("paypal.com").
        val result = AutofillMatcher.match(vault, "paypal.com", "com.evil.app")
        assertEquals(emptyList<VaultItem.Login>(), result)
    }

    @Test
    fun `an unknown app gets nothing rather than everything`() {
        assertEquals(emptyList<VaultItem.Login>(), AutofillMatcher.match(vault, null, "com.unknown.app"))
    }

    @Test
    fun `a request that identifies nothing gets nothing`() {
        assertEquals(emptyList<VaultItem.Login>(), AutofillMatcher.match(vault, null, null))
        assertEquals(emptyList<VaultItem.Login>(), AutofillMatcher.match(vault, "", ""))
    }

    // ── What is allowed, and why ───────────────────────────────────────────

    @Test
    fun `a browser is believed about the site it is showing`() {
        assertEquals(listOf(paypal), AutofillMatcher.match(vault, "paypal.com", "com.android.chrome"))
        assertEquals(listOf(paypal), AutofillMatcher.match(vault, "https://www.paypal.com/signin", "org.mozilla.firefox"))
    }

    @Test
    fun `a browser showing another site does not get this login`() {
        assertEquals(emptyList<VaultItem.Login>(), AutofillMatcher.match(vault, "evil.example", "com.android.chrome"))
    }

    @Test
    fun `a link the user made is honoured offline`() {
        val linked = login("Uber", "https://uber.com", listOf("androidapp://com.ubercab"))
        assertEquals(listOf(linked), AutofillMatcher.match(listOf(linked) + vault, null, "com.ubercab"))
    }

    @Test
    fun `a link only matches the package it names`() {
        val linked = login("Uber", "https://uber.com", listOf("androidapp://com.ubercab"))
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(listOf(linked), null, "com.ubercab.evil"),
        )
    }

    @Test
    fun `the curated list covers well-known apps`() {
        val instagram = login("Instagram", "https://instagram.com")
        assertEquals(
            listOf(instagram),
            AutofillMatcher.match(listOf(instagram) + vault, null, "com.instagram.android"),
        )
    }

    @Test
    fun `a login saved from an app before links existed still matches`() {
        // Older saves used the package name as the URL. That is the user's own
        // data, not an inference, so it keeps working.
        val legacy = login("Some App", "com.some.app")
        assertEquals(listOf(legacy), AutofillMatcher.match(listOf(legacy) + vault, null, "com.some.app"))
    }

    // ── Digital Asset Links ────────────────────────────────────────────────

    @Test
    fun `a site that vouches for the app unlocks its login`() {
        val result = AutofillMatcher.match(vault, null, "com.bank.official") { domain, pkg ->
            domain == "bank.example" && pkg == "com.bank.official"
        }
        assertEquals(listOf(bank), result)
    }

    @Test
    fun `asset links let a WebView app justify the domain it claims`() {
        // Not on the curated list and not a browser: the only thing standing
        // behind the claim is the site's own statement.
        val result = AutofillMatcher.match(vault, "bank.example", "com.bank.official") { domain, pkg ->
            domain == "bank.example" && pkg == "com.bank.official"
        }
        assertEquals(listOf(bank), result)
    }

    @Test
    fun `a site vouching for one app says nothing about another`() {
        val result = AutofillMatcher.match(vault, "bank.example", "com.evil.app") { domain, pkg ->
            domain == "bank.example" && pkg == "com.bank.official"
        }
        assertEquals(emptyList<VaultItem.Login>(), result)
    }

    @Test
    fun `local matches are answered without touching the network`() {
        var lookups = 0
        val linked = login("Uber", "https://uber.com", listOf("androidapp://com.ubercab"))
        AutofillMatcher.match(listOf(linked), null, "com.ubercab") { _, _ -> lookups++; false }
        assertEquals(0, lookups)
    }

    @Test
    fun `asset link lookups are capped per request`() {
        val many = (1..50).map { login("Site $it", "https://site$it.example") }
        var lookups = 0
        AutofillMatcher.match(many, null, "com.some.app") { _, _ -> lookups++; false }
        assertTrue("expected a bounded number of lookups, got $lookups", lookups in 1..8)
    }

    // ── Domain matching ────────────────────────────────────────────────────

    @Test
    fun `subdomains match the registered site but not the reverse`() {
        assertTrue(AutofillMatcher.domainsMatch("login.paypal.com", "paypal.com"))
        assertFalse(AutofillMatcher.domainsMatch("paypal.com", "login.paypal.com"))
    }

    @Test
    fun `a lookalike suffix does not match`() {
        assertFalse(AutofillMatcher.domainsMatch("evilpaypal.com", "paypal.com"))
        assertFalse(AutofillMatcher.domainsMatch("paypal.com.evil.example", "paypal.com"))
    }

    @Test
    fun `ip addresses only match exactly`() {
        assertTrue(AutofillMatcher.domainsMatch("10.0.0.1", "10.0.0.1"))
        assertFalse(AutofillMatcher.domainsMatch("10.0.0.1", "0.0.1"))
    }

    @Test
    fun `blank urls match nothing`() {
        assertFalse(AutofillMatcher.domainsMatch("paypal.com", ""))
        assertFalse(AutofillMatcher.domainsMatch("", "paypal.com"))
    }

    // ── Browser allowlist ──────────────────────────────────────────────────

    @Test
    fun `browser allowlist is exact`() {
        assertTrue(AppAssociations.isBrowser("com.android.chrome"))
        assertTrue(AppAssociations.isBrowser("COM.ANDROID.CHROME"))
        assertFalse(AppAssociations.isBrowser("com.android.chrome.evil"))
        assertFalse(AppAssociations.isBrowser("com.evil.chrome"))
        assertFalse(AppAssociations.isBrowser(null))
    }

    @Test
    fun `app uris round trip`() {
        assertEquals("androidapp://com.ubercab", AppAssociations.appUri("com.ubercab"))
        assertEquals("com.ubercab", AppAssociations.packageFromUri("androidapp://com.ubercab"))
        assertEquals(null, AppAssociations.packageFromUri("https://uber.com"))
        assertEquals(null, AppAssociations.packageFromUri("androidapp://"))
    }
}
