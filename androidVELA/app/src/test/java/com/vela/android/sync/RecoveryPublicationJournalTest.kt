package com.vela.android.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class RecoveryPublicationJournalTest {
    private fun generated() = RecoveryPublicationJournal(
        accountId = "account-1",
        keyEpoch = 7,
        splitId = "0f8fad5b-d9cb-469f-a165-70867728950e",
        cloudShareB64 = "cloud",
        serverShareB64 = "server",
        trustedContactShareB64 = "contact",
        possessionHashB64 = "cG9zc2Vzc2lvbg==",
    )

    @Test
    fun journalRoundTripPreservesTheExactSplitAndProgress() {
        val expected = generated().copy(
            serverStaged = true,
            cloudCandidateDurable = true,
            serverFinalized = true,
        )
        assertEquals(expected, RecoveryPublicationJournal.fromJson(expected.toJson()))
    }

    @Test
    fun preM18JournalsWithoutAPossessionHashStillLoad() {
        val legacy = generated().copy(possessionHashB64 = "").let { journal ->
            // Strip the M18 field the way a pre-M18 journal would lack it.
            val json = journal.toJson()
            json.remove("possession_hash_b64")
            RecoveryPublicationJournal.fromJson(json)
        }
        assertEquals("", legacy.possessionHashB64)
    }

    @Test(expected = IllegalArgumentException::class)
    fun activeCloudWithoutServerFinalizationIsRejected() {
        val malformed = generated().toJson()
            .put("cloud_active", true)
            .put("server_finalized", false)
        RecoveryPublicationJournal.fromJson(JSONObject(malformed.toString()))
    }

    @Test
    fun generatedJournalHasNoExternalProgress() {
        val journal = generated()
        assertFalse(journal.serverStaged)
        assertFalse(journal.cloudCandidateDurable)
        assertFalse(journal.serverFinalized)
        assertFalse(journal.cloudActive)
    }
}
