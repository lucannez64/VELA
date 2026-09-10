package com.vela.android.sync

import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

/** One decoded server vault-change event. */
internal data class VaultEvent(
    val writer: String?,
    val kind: String?,
    val epoch: Long?,
    val revision: Long?
)

/**
 * Incremental `text/event-stream` frame parser. Feed it decoded chunks; it
 * returns the `data:` payload of every completed event. Only `data` fields
 * matter here — event names are advisory.
 *
 * Split out from the networking so it can be unit-tested without a socket;
 * every payload this server sends is ASCII, so a multibyte character split
 * across reads cannot corrupt one.
 */
internal class SseFrameParser {
    private val line = StringBuilder()
    private val data = StringBuilder()

    fun push(chunk: String): List<String> {
        val events = mutableListOf<String>()
        for (c in chunk) {
            if (c != '\n') {
                line.append(c)
                continue
            }
            var text = line.toString()
            if (text.endsWith("\r")) text = text.dropLast(1)
            line.setLength(0)
            if (text.isEmpty()) {
                // A blank line dispatches the event accumulated so far.
                if (data.isNotEmpty()) {
                    events.add(data.toString())
                    data.setLength(0)
                }
            } else if (text.startsWith("data:")) {
                if (data.isNotEmpty()) data.append('\n')
                data.append(text.removePrefix("data:").removePrefix(" "))
            }
            // "event:", "id:", "retry:" and ": comment" lines are not needed.
        }
        return events
    }
}

/**
 * Whether an event payload asks this device to sync. The opening `hello` has
 * no `kind`; a change written by this device is already on the server; a
 * `resync` frame (epoch commit / lagged subscriber) syncs conservatively.
 */
internal fun eventRequestsSync(payload: String, deviceId: String): Boolean =
    runCatching {
        val json = JSONObject(payload)
        if (!json.has("kind")) return@runCatching false
        val writer = json.optString("writer", "")
        writer.isEmpty() || writer != deviceId
    }.getOrDefault(true)

/**
 * Foreground-only `GET /vault/events` client.
 *
 * Blocking by design: callers run it on `Dispatchers.IO` and cancel its
 * coroutine. Reads are bounded by [READ_TIMEOUT_MS] (= longer than the
 * server's 15s keep-alive), so cancellation is noticed within that window even
 * though a blocked socket read is not interruptible on Android.
 */
internal object VaultEventStream {
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 45_000

    /**
     * Follow the stream until [isCancelled] or the connection ends. Returns
     * normally when the caller cancels; throws on connect/read failure so the
     * caller can back off and reconnect. `onEvent` fires only for events that
     * request a sync.
     */
    fun follow(
        serverUrl: String,
        token: String,
        deviceId: String,
        isCancelled: () -> Boolean,
        onEvent: (VaultEvent) -> Unit,
        onNewToken: (String) -> Unit
    ) {
        val connection = (URL("$serverUrl/vault/events").openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            setRequestProperty("Accept", "text/event-stream")
            setRequestProperty("Authorization", "Bearer $token")
        }
        try {
            val code = connection.responseCode
            connection.getHeaderField("X-New-Token")
                ?.takeIf { it.isNotBlank() }
                ?.let(onNewToken)
            if (code !in 200..299) error("Event stream refused with HTTP $code")

            val parser = SseFrameParser()
            BufferedReader(InputStreamReader(connection.inputStream, Charsets.UTF_8)).use { reader ->
                val buffer = CharArray(4096)
                while (!isCancelled()) {
                    val read = reader.read(buffer)
                    if (read < 0) return
                    for (payload in parser.push(String(buffer, 0, read))) {
                        val event = parseEvent(payload) ?: continue
                        if (eventRequestsSync(payload, deviceId)) onEvent(event)
                    }
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    internal fun parseEvent(payload: String): VaultEvent? = runCatching {
        val json = JSONObject(payload)
        VaultEvent(
            writer = json.optString("writer", "").ifEmpty { null },
            kind = json.optString("kind", "").ifEmpty { null },
            epoch = json.optLong("epoch", 0L).takeIf { it > 0 },
            revision = json.optLong("revision", 0L)
        )
    }.getOrNull()
}
