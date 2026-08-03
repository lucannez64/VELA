package com.vela.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A browser the user vouched for is trusted the same way an app link is: by
 * package *and* by the certificate it carried when they vouched (#125).
 *
 * The store itself needs a Context, so what is exercised here is the rule that
 * decides whether a pin still holds — which is the part that must not be wrong.
 */
class TrustedBrowserPinningTest {

    private val pinnedCert = "AB:CD:" + "00:".repeat(29) + "FF"
    private val otherCert = "FF:EE:" + "11:".repeat(29) + "00"

    /** The comparison `TrustedBrowsers.isTrusted` makes, in isolation. */
    private fun pinHolds(pinned: String?, installed: Set<String>): Boolean {
        val expected = pinned ?: return false
        return installed.any { AppSignatures.normalize(it) == expected }
    }

    @Test
    fun a_pin_holds_only_while_the_key_is_the_same() {
        assertTrue(pinHolds(pinnedCert, setOf(pinnedCert)))
        // Re-signed by someone else — an app that changed hands, or an impostor
        // sideloaded under the same package name.
        assertFalse(pinHolds(pinnedCert, setOf(otherCert)))
    }

    @Test
    fun a_browser_that_was_never_trusted_is_not_trusted() {
        assertFalse(pinHolds(null, setOf(pinnedCert)))
    }

    @Test
    fun a_pin_fails_closed_when_no_signature_can_be_read() {
        // An uninstalled or unreadable package must not satisfy a pin.
        assertFalse(pinHolds(pinnedCert, emptySet()))
    }

    @Test
    fun fingerprint_formatting_does_not_decide_trust() {
        assertTrue(pinHolds(pinnedCert, setOf(pinnedCert.lowercase())))
        assertTrue(pinHolds(pinnedCert, setOf(" $pinnedCert ")))
    }

    @Test
    fun an_unreadable_signature_yields_no_pin_to_store() {
        // What `trust()` records: the first normalised fingerprint, or nothing.
        // Storing a package name with no fingerprint would recreate exactly the
        // name-only trust this whole area exists to remove.
        assertNull(emptySet<String>().firstNotNullOfOrNull { AppSignatures.normalize(it) })
        assertEquals(
            pinnedCert,
            setOf(pinnedCert.lowercase()).firstNotNullOfOrNull { AppSignatures.normalize(it) },
        )
    }
}
