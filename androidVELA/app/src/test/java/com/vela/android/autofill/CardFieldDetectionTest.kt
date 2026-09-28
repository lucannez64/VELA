package com.vela.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The payment-field heuristics must claim real card inputs without stealing
 * ordinary login fields — a false positive here would offer a card (and its
 * secrets) where only a username belongs.
 */
class CardFieldDetectionTest {

    @Test
    fun `card number fields are recognised`() {
        assertEquals(CardField.Number, cardFieldKindOf("cc-number", null, null, null, null))
        assertEquals(CardField.Number, cardFieldKindOf(null, "cardNumber", null, null, null))
        assertEquals(CardField.Number, cardFieldKindOf(null, null, "cc-number", null, null))
        assertEquals(CardField.Number, cardFieldKindOf(null, null, null, "Card number", null))
        assertEquals(CardField.Number, cardFieldKindOf(null, "numero-carte", null, null, null))
    }

    @Test
    fun `expiry shapes are distinguished`() {
        assertEquals(CardField.Expiry, cardFieldKindOf("cc-exp", null, null, null, null))
        assertEquals(CardField.ExpMonth, cardFieldKindOf("cc-exp-month", null, null, null, null))
        assertEquals(CardField.ExpYear, cardFieldKindOf("cc-exp-year", null, null, null, null))
    }

    @Test
    fun `cvv and cardholder are recognised`() {
        assertEquals(CardField.Cvv, cardFieldKindOf("card-cvc", null, null, null, null))
        assertEquals(CardField.Cvv, cardFieldKindOf(null, null, null, "Security code", null))
        assertEquals(CardField.Name, cardFieldKindOf("cc-name", null, null, null, null))
        assertEquals(CardField.Name, cardFieldKindOf(null, "nameOnCard", null, null, null))
    }

    @Test
    fun `login fields are not claimed`() {
        assertNull(cardFieldKindOf("username", null, null, null, null))
        assertNull(cardFieldKindOf("email", null, null, null, null))
        assertNull(cardFieldKindOf("password", null, null, null, null))
        assertNull(cardFieldKindOf("current-password", null, null, null, null))
        assertNull(cardFieldKindOf(null, "user-name", null, null, null))
        assertNull(cardFieldKindOf(null, "name", null, null, null))
        // A generic "account holder name" is not a card field — only an explicit
        // cardholder signal is.
        assertNull(cardFieldKindOf(null, "accountHolderName", null, null, null))
    }

    @Test
    fun `empty signals are not a card`() {
        assertNull(cardFieldKindOf(null, null, null, null, null))
        assertNull(cardFieldKindOf("   ", null, null, null, null))
    }
}
