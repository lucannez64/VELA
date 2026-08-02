package com.vela.android.core

import org.junit.Assert.assertEquals
import org.junit.Test

class VaultJsonTest {
    @Test
    fun decodesDesktopCreditCardKeys() {
        val json = """
            {
              "items": [
                {
                  "item_type": "creditCard",
                  "id": "card-1",
                  "name": "Personal card",
                  "number": "4242424242424242",
                  "exp": "12/30",
                  "cvv": "123",
                  "pin": "9876",
                  "cardholder_name": "Ada Lovelace",
                  "created_at": "2026-01-01T00:00:00Z",
                  "updated_at": "2026-01-02T00:00:00Z",
                  "last_modified_device": null,
                  "favorite": false,
                  "shared": false,
                  "share_recipient": null
                }
              ],
              "tombstones": []
            }
        """.trimIndent()

        val item = VaultJson.decode(json.toByteArray()).items.single() as VaultItem.CreditCard

        assertEquals("4242424242424242", item.cardNumber)
        assertEquals("12/30", item.expiration)
        assertEquals("123", item.cvv)
        assertEquals("9876", item.pin)
        assertEquals("Ada Lovelace", item.cardholderName)
    }

    @Test
    fun `app associations survive a round trip`() {
        val now = java.time.Instant.parse("2026-01-01T00:00:00Z")
        val login = VaultItem.Login(
            meta = VaultMeta(id = "login-1", name = "Uber", createdAt = now, updatedAt = now),
            url = "https://uber.com",
            username = "ada",
            password = "hunter2",
            appIds = listOf("androidapp://com.ubercab"),
        )

        val decoded = VaultJson.decode(VaultJson.encode(VaultStore(listOf(login))))
            .items.single() as VaultItem.Login

        assertEquals(listOf("androidapp://com.ubercab"), decoded.appIds)
    }

    @Test
    fun `a login written before app links decodes with none`() {
        val json = """
            {"items":[{"item_type":"login","id":"login-1","name":"Old",
              "url":"https://example.com","username":"ada","password":"hunter2",
              "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],
             "tombstones":[]}
        """.trimIndent()

        val item = VaultJson.decode(json.toByteArray()).items.single() as VaultItem.Login

        assertEquals(emptyList<String>(), item.appIds)
    }
}
