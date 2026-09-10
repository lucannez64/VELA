package com.vela.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultEventStreamParserTest {

    @Test
    fun `frames split across reads stay buffered until their blank line`() {
        val parser = SseFrameParser()
        assertTrue(parser.push("event: hello\ndata: {\"rev").isEmpty())
        assertEquals(
            listOf("{\"revision\":1}"),
            parser.push("ision\":1}\n\n")
        )
    }

    @Test
    fun `crlf comments and multi-line data parse`() {
        val parser = SseFrameParser()
        assertEquals(
            listOf("a\nb"),
            parser.push(": keep-alive\r\ndata: a\r\ndata: b\r\n\r\n")
        )
    }

    @Test
    fun `own writes and control frames do not request a sync`() {
        val me = "11111111-1111-1111-1111-111111111111"
        val other = "22222222-2222-2222-2222-222222222222"
        assertFalse(
            eventRequestsSync(
                "{\"revision\":7,\"writer\":\"$me\",\"epoch\":1,\"kind\":\"chunk\"}", me
            )
        )
        assertTrue(
            eventRequestsSync(
                "{\"revision\":8,\"writer\":\"$other\",\"epoch\":1,\"kind\":\"chunk\"}", me
            )
        )
        // Epoch commit and lagged resync frames name no useful writer.
        assertTrue(eventRequestsSync("{\"kind\":\"epoch\"}", me))
        assertTrue(eventRequestsSync("{\"kind\":\"lagged\"}", me))
        // Opening hello: no kind, no writer -- informational only.
        assertFalse(eventRequestsSync("{\"revision\":4,\"epoch\":1}", me))
    }

    @Test
    fun `unparseable payloads sync conservatively`() {
        assertTrue(eventRequestsSync("not json", "device"))
    }

    @Test
    fun `parse event maps the server payload`() {
        val event = VaultEventStream.parseEvent(
            "{\"revision\":12,\"writer\":\"abc\",\"epoch\":3,\"kind\":\"oram\"}"
        )
        assertEquals(12L, event?.revision)
        assertEquals("abc", event?.writer)
        assertEquals(3L, event?.epoch)
        assertEquals("oram", event?.kind)

        assertNull(VaultEventStream.parseEvent("not json"))
    }
}
