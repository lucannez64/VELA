package com.vela.autofilleval.lab

import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.EditText
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * The native-app twin of lib/beacon.js: reports what each field holds, plus
 * its on-screen rectangle (screen pixels) so the UiAutomator runner can tap it.
 * Same wire format as the web beacon, so the server scores both the same way.
 */
class Reporter(
    private val server: String,
    private val run: String,
    private val page: String,
    private val fields: Map<String, EditText>,
) {
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val history = mutableMapOf<String, MutableSet<String>>()
    private val firstChange = mutableMapOf<String, Long>()
    private val t0 = System.currentTimeMillis()
    private var lastSig = ""
    private var stopped = false

    fun start() {
        val tick = object : Runnable {
            override fun run() {
                if (stopped) return
                report(force = false)
                main.postDelayed(this, 250)
            }
        }
        main.post(tick)
        main.postDelayed(object : Runnable {
            override fun run() { if (!stopped) { report(force = true); main.postDelayed(this, 3000) } }
        }, 3000)
    }

    fun stop() { stopped = true; report(force = true) }

    private fun isPassword(e: EditText): Boolean {
        val v = e.inputType and InputType.TYPE_MASK_VARIATION
        return v == InputType.TYPE_TEXT_VARIATION_PASSWORD || v == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            v == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD || v == InputType.TYPE_NUMBER_VARIATION_PASSWORD
    }

    fun snapshot(): JSONObject {
        val out = JSONObject()
        val loc = IntArray(2)
        for ((id, e) in fields) {
            val value = e.text?.toString() ?: ""
            e.getLocationOnScreen(loc)
            if (value.isNotEmpty()) {
                history.getOrPut(id) { mutableSetOf() }.add(value)
                firstChange.putIfAbsent(id, System.currentTimeMillis() - t0)
            }
            out.put(id, JSONObject()
                .put("value", value)
                .put("tag", "input")
                .put("type", if (isPassword(e)) "password" else "text")
                .put("name", id).put("id", id)
                .put("autocomplete", e.autofillHints?.joinToString(" ") ?: "")
                .put("placeholder", e.hint?.toString() ?: "")
                .put("visible", e.isShown)
                .put("rect", JSONObject().put("x", loc[0]).put("y", loc[1]).put("w", e.width).put("h", e.height)))
        }
        val hist = JSONObject()
        for ((k, v) in history) hist.put(k, JSONArray(v.toList()))
        return JSONObject()
            .put("run", run).put("page", page).put("url", "app://lab/$page")
            .put("ts", System.currentTimeMillis())
            .put("fields", out).put("history", hist)
            .put("firstChangeMs", JSONObject(firstChange as Map<*, *>))
            .put("frames", JSONArray())
            .put("screenCoords", true)
            .put("viewport", JSONObject().put("innerWidth", 0).put("devicePixelRatio", 1))
    }

    private fun report(force: Boolean) {
        val snap = snapshot()
        val sig = snap.getJSONObject("fields").toString()
        if (!force && sig == lastSig) return
        lastSig = sig
        val body = snap.toString()
        io.execute {
            runCatching {
                val c = URL("$server/__eval/report").openConnection() as HttpURLConnection
                c.requestMethod = "POST"
                c.doOutput = true
                c.setRequestProperty("content-type", "application/json")
                c.connectTimeout = 3000
                c.outputStream.use { it.write(body.toByteArray()) }
                c.responseCode
                c.disconnect()
            }
        }
    }
}

/** Blocking GET, off the main thread. */
fun httpGet(url: String): String {
    val c = URL(url).openConnection() as HttpURLConnection
    c.connectTimeout = 5000
    c.readTimeout = 10000
    return c.inputStream.bufferedReader().use { it.readText() }.also { c.disconnect() }
}
