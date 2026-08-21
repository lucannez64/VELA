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

    /** Stands in for [BrowserAllowlist], which checks signing certificates. */
    private val browsers: (String) -> Boolean =
        { it == "com.android.chrome" || it == "org.mozilla.firefox" }

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
        val result = AutofillMatcher.match(vault, "paypal.com", "com.evil.app", browsers)
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
        assertEquals(listOf(paypal), AutofillMatcher.match(vault, "paypal.com", "com.android.chrome", browsers))
        assertEquals(
            listOf(paypal),
            AutofillMatcher.match(vault, "https://www.paypal.com/signin", "org.mozilla.firefox", browsers),
        )
    }

    @Test
    fun `a browser showing another site does not get this login`() {
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(vault, "evil.example", "com.android.chrome", browsers),
        )
    }

    @Test
    fun `a link the user made is honoured offline`() {
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app"))
        assertEquals(listOf(linked), AutofillMatcher.match(listOf(linked) + vault, null, "com.acme.app"))
    }

    @Test
    fun `a link only matches the package it names`() {
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app"))
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(listOf(linked), null, "com.acme.app.evil"),
        )
    }

    @Test
    fun `the curated list is only a hint - the site must still vouch`() {
        val instagram = login("Instagram", "https://instagram.com")
        // Default verifyAssetLinks answers "no": the curated package name alone
        // must not unlock anything (an impostor can occupy any package name).
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(listOf(instagram) + vault, null, "com.instagram.android"),
        )
    }

    @Test
    fun `a curated app gets its site's login once the site vouches for it`() {
        val instagram = login("Instagram", "https://instagram.com")
        assertEquals(
            listOf(instagram),
            AutofillMatcher.match(
                listOf(instagram) + vault, null, "com.instagram.android",
            ) { domain, pkg ->
                domain == "instagram.com" && pkg == "com.instagram.android"
            },
        )
    }

    @Test
    fun `a login saved from an app before links existed still matches`() {
        // Older saves used the package name as the URL. That is the user's own
        // data, not an inference, so it keeps working.
        val legacy = login("Some App", "com.some.app")
        assertEquals(listOf(legacy), AutofillMatcher.match(listOf(legacy) + vault, null, "com.some.app"))
    }

    // ── Pinned links ───────────────────────────────────────────────────────

    private val cert = "AB:CD:" + "00:".repeat(29) + "FF"
    private val otherCert = "FF:EE:" + "11:".repeat(29) + "00"

    @Test
    fun `a pinned link matches only while the app keeps that signing key`() {
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app?cert=$cert"))
        val vault = listOf(linked)

        assertEquals(
            listOf(linked),
            AutofillMatcher.match(vault, null, "com.acme.app", browsers, { setOf(cert) }),
        )
        // Same package, someone else's key — an app that changed hands, or a
        // rebuild by an impostor.
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(vault, null, "com.acme.app", browsers, { setOf(otherCert) }),
        )
    }

    @Test
    fun `a pinned link fails closed when signatures cannot be read`() {
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app?cert=$cert"))
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(listOf(linked), null, "com.acme.app"),
        )
    }

    @Test
    fun `an unpinned link still matches on the package alone`() {
        // The older format, and the deliberate choice for an app the user runs
        // from a different store. It must keep working.
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app"))
        assertEquals(
            listOf(linked),
            AutofillMatcher.match(listOf(linked), null, "com.acme.app", browsers, { setOf(otherCert) }),
        )
    }

    @Test
    fun `a pinned link is matched case-insensitively on the fingerprint`() {
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app?cert=$cert"))
        assertEquals(
            listOf(linked),
            AutofillMatcher.match(listOf(linked), null, "com.acme.app", browsers, { setOf(cert.lowercase()) }),
        )
    }

    @Test
    fun `link parsing round-trips both forms`() {
        assertEquals("androidapp://com.acme.app", AppAssociations.appUri("com.acme.app"))
        assertEquals(
            "androidapp://com.acme.app?cert=$cert",
            AppAssociations.appUri("com.acme.app", cert),
        )
        assertEquals("com.acme.app", AppAssociations.packageFromUri("androidapp://com.acme.app?cert=$cert"))
        assertEquals(cert, AppAssociations.certFromUri("androidapp://com.acme.app?cert=$cert"))
        assertEquals(null, AppAssociations.certFromUri("androidapp://com.acme.app"))
    }

    @Test
    fun `linkGrants is the whole rule in one place`() {
        assertTrue(AutofillMatcher.linkGrants("androidapp://com.a", "com.a", emptySet()))
        assertFalse(AutofillMatcher.linkGrants("androidapp://com.a", "com.b", emptySet()))
        assertFalse(AutofillMatcher.linkGrants("https://uber.com", "com.a", emptySet()))
        assertTrue(AutofillMatcher.linkGrants("androidapp://com.a?cert=$cert", "com.a", setOf(cert)))
        assertFalse(AutofillMatcher.linkGrants("androidapp://com.a?cert=$cert", "com.a", setOf(otherCert)))
        assertFalse(AutofillMatcher.linkGrants("androidapp://com.a?cert=$cert", "com.a", emptySet()))
    }

    // ── Digital Asset Links ────────────────────────────────────────────────

    @Test
    fun `a site that vouches for the app unlocks its login`() {
        val result = AutofillMatcher.match(vault, null, "com.bank.official", browsers, { emptySet() }) { domain, pkg ->
            domain == "bank.example" && pkg == "com.bank.official"
        }
        assertEquals(listOf(bank), result)
    }

    @Test
    fun `asset links let a WebView app justify the domain it claims`() {
        // Not on the curated list and not a browser: the only thing standing
        // behind the claim is the site's own statement.
        val result = AutofillMatcher.match(vault, "bank.example", "com.bank.official", browsers, { emptySet() }) { domain, pkg ->
            domain == "bank.example" && pkg == "com.bank.official"
        }
        assertEquals(listOf(bank), result)
    }

    @Test
    fun `a site vouching for one app says nothing about another`() {
        val result = AutofillMatcher.match(vault, "bank.example", "com.evil.app", browsers, { emptySet() }) { domain, pkg ->
            domain == "bank.example" && pkg == "com.bank.official"
        }
        assertEquals(emptyList<VaultItem.Login>(), result)
    }

    @Test
    fun `local matches are answered without touching the network`() {
        var lookups = 0
        val linked = login("Acme", "https://acme.example", listOf("androidapp://com.acme.app"))
        AutofillMatcher.match(listOf(linked), null, "com.acme.app", browsers, { emptySet() }) { _, _ -> lookups++; false }
        assertEquals(0, lookups)
    }

    @Test
    fun `asset link lookups are capped per request`() {
        val many = (1..50).map { login("Site $it", "https://site$it.example") }
        var lookups = 0
        AutofillMatcher.match(many, null, "com.some.app", browsers, { emptySet() }) { _, _ -> lookups++; false }
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

    // ── Browser trust ──────────────────────────────────────────────────────

    @Test
    fun `an app that only looks like a browser is not one`() {
        // BrowserAllowlist answers this by signing certificate, so an impostor
        // named com.android.chrome fails there and arrives here as "not a browser".
        val impostor: (String) -> Boolean = { false }
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(vault, "paypal.com", "com.android.chrome", impostor),
        )
    }

    @Test
    fun `browser trust is never granted by omission`() {
        // The default must be "not a browser": a caller that forgets to supply
        // the check must not thereby believe every claimed domain.
        assertEquals(
            emptyList<VaultItem.Login>(),
            AutofillMatcher.match(vault, "paypal.com", "com.android.chrome"),
        )
    }

    @Test
    fun `app uris round trip`() {
        assertEquals("androidapp://com.acme.app", AppAssociations.appUri("com.acme.app"))
        assertEquals("com.acme.app", AppAssociations.packageFromUri("androidapp://com.acme.app"))
        assertEquals(null, AppAssociations.packageFromUri("https://uber.com"))
        assertEquals(null, AppAssociations.packageFromUri("androidapp://"))
    }
}
