package com.vela.autofilleval.lab

import android.content.Context
import android.content.Intent
import android.graphics.Rect
import android.net.Uri
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import java.net.HttpURLConnection
import java.net.URL
import java.util.regex.Pattern

/**
 * Android autofill eval: drives the system autofill UI (inline suggestions or
 * the dropdown) with VELA as the autofill service, in
 *   - native   the lab app's own views (an "app")
 *   - webview  a fixture page inside the lab app's WebView (an "app" hosting web)
 *   - chrome, firefox, samsung, brave, edge, duckduckgo  (browsers)
 * against the fixture corpus, the native forms, live sites and live apps.
 *
 * Instrumentation args (all optional):
 *   server   eval server as seen from the device   (http://10.0.2.2:8080)
 *   runId    groups results                         (android-<time>)
 *   surfaces comma list, see above                  (native,webview,chrome)
 *   tier     fixture | live | live-app              (fixture)
 *   only     comma list of scenario ids
 *   limit    max scenarios per surface
 *   httpsPort port of the fixture HTTPS server      (8443)
 *   unlock   none | finger  — answer VELA's biometric prompt via the host
 *
 * Results land in the server's results/<runId>/results.jsonl; nothing is
 * asserted here, so one failing site never stops the sweep.
 */
@RunWith(AndroidJUnit4::class)
class AutofillEvalTest {
    private val instr = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()
    private val device = UiDevice.getInstance(instr)
    private val ctx: Context = instr.context
    private val server = args.getString("server") ?: "http://10.0.2.2:8080"
    private val runId = args.getString("runId") ?: "android-${System.currentTimeMillis()}"
    private val surfaces = (args.getString("surfaces") ?: "native,webview,chrome").split(",")
    private val tier = args.getString("tier") ?: "fixture"
    private val only = args.getString("only")?.split(",")?.toSet()
    private val limit = args.getString("limit")?.toIntOrNull() ?: Int.MAX_VALUE
    private val httpsPort = args.getString("httpsPort") ?: "8443"
    private val unlock = args.getString("unlock") ?: "none"

    private val browsers = mapOf(
        "chrome" to "com.android.chrome",
        "firefox" to "org.mozilla.firefox",
        "samsung" to "com.sec.android.app.sbrowser",
        "brave" to "com.brave.browser",
        "edge" to "com.microsoft.emmx",
        "duckduckgo" to "com.duckduckgo.mobile.android",
    )
    private val labPkg = "com.vela.autofilleval.lab"

    @Test
    fun sweep() {
        for (surface in surfaces) {
            when {
                tier == "live" && surface in browsers -> liveSites(surface)
                tier == "live-app" -> liveApps()
                surface == "native" -> scenarios("native").forEach { runScenario(surface, it, native = true) }
                surface == "webview" || surface in browsers -> scenarios("fixture").forEach { runScenario(surface, it, native = false) }
            }
        }
    }

    // ── Fixture + native scenarios ──────────────────────────────────────────

    private fun scenarios(tierName: String): List<JSONObject> {
        val arr = JSONArray(get("/__eval/scenarios?tier=$tierName&scheme=https&port=$httpsPort"))
        return (0 until arr.length()).map { arr.getJSONObject(it) }
            .filter { only == null || it.getString("id") in only }
            .take(limit)
    }

    private fun runScenario(surface: String, sc: JSONObject, native: Boolean) {
        val id = sc.getString("id")
        val mode = "suggestion"
        val run = "$runId.android-$surface.$mode.$id"
        val choose = sc.optJSONObject("choose")
        var offered: Boolean? = null
        var error: String? = null
        var interactions = 0
        val t0 = SystemClock.uptimeMillis()
        try {
            launch(surface, sc, run, native)
            if (!waitForReport(run, id, 20_000)) throw IllegalStateException("page never reported (host mapping / CA / network?)")
            SystemClock.sleep(600L + sc.optLong("settleMs", 0))
            val steps = sc.getJSONArray("steps")
            for (i in 0 until steps.length()) {
                val step = steps.getJSONObject(i)
                when {
                    step.has("wait") -> SystemClock.sleep(step.getLong("wait"))
                    step.has("click") -> { tapField(run, id, step.getString("click"), surface, native); interactions++ }
                    step.has("generate") -> {
                        tapField(run, id, step.getString("generate"), surface, native); interactions++
                        val gen = device.wait(Until.findObject(By.text(Pattern.compile("(?i).*(generate|suggest).*password.*"))), 4000)
                        offered = gen != null
                        if (gen != null) { gen.click(); interactions++ }
                    }
                    step.has("fill") -> {
                        tapField(run, id, step.getString("fill"), surface, native); interactions++
                        val r = pickSuggestion(choose)
                        interactions += r.second
                        offered = (offered == true) || r.first
                    }
                }
                SystemClock.sleep(500)
            }
            SystemClock.sleep(1500)
        } catch (e: Throwable) {
            error = (e.message ?: e.toString()).lineSequence().first()
        }
        val score = post("/__eval/result", JSONObject()
            .put("runId", runId).put("run", run).put("tier", if (native) "native" else "fixture").put("scenarioId", id)
            .put("surface", "android-$surface").put("platform", "android").put("client", clientName(surface)).put("mode", mode)
            .put("offered", offered ?: JSONObject.NULL).put("interactions", interactions)
            .put("durationMs", SystemClock.uptimeMillis() - t0).put("error", error ?: JSONObject.NULL))
        println("AUTOFILL_EVAL android-$surface $id -> $score")
        dismiss()
    }

    private fun launch(surface: String, sc: JSONObject, run: String, native: Boolean) {
        val intent = when {
            native -> Intent().setClassName(labPkg, "$labPkg.LabActivity")
                .putExtra("server", server).putExtra("run", run).putExtra("form", sc.getString("id"))
            surface == "webview" -> Intent().setClassName(labPkg, "$labPkg.WebLabActivity")
                .putExtra("url", withRun(sc.getString("url"), run))
            else -> Intent(Intent.ACTION_VIEW, Uri.parse(withRun(sc.getString("url"), run)))
                .setPackage(browsers.getValue(surface))
                // Reuse one tab per browser instead of piling up hundreds.
                .putExtra("com.android.browser.application_id", "vela-autofill-eval")
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        ctx.startActivity(intent)
        device.waitForIdle(3000)
    }

    /**
     * Tap the field with this key. Its rectangle comes from the page's beacon
     * (CSS px inside the web content) or the lab app's reporter (screen px).
     */
    private fun tapField(run: String, mainPage: String, key: String, surface: String, native: Boolean) {
        val pages = JSONObject(get("/__eval/state?run=${enc(run)}"))
        val pageKey = if (key.contains("#")) key.substringBefore("#") else mainPage
        val fieldKey = if (key.contains("#")) key.substringAfter("#") else key
        val snap = pages.optJSONObject(pageKey) ?: throw IllegalStateException("no report for $pageKey")
        val field = snap.getJSONObject("fields").optJSONObject(fieldKey) ?: throw IllegalStateException("no field $key")
        val r = field.getJSONObject("rect")
        var cx = r.getDouble("x") + r.getDouble("w") / 2
        var cy = r.getDouble("y") + r.getDouble("h") / 2
        if (native || snap.optBoolean("screenCoords")) {
            device.click(cx.toInt(), cy.toInt())
            return
        }
        // A field inside an iframe: add the iframe's offset in the main page.
        val main = pages.getJSONObject(mainPage)
        if (pageKey != mainPage) {
            val path = pageKey.substringBefore(":")
            val frames = main.getJSONArray("frames")
            val fr = (0 until frames.length()).map { frames.getJSONObject(it) }
                .firstOrNull { it.getString("src").contains("/$path.html") && (!pageKey.contains(":") || it.getString("src").contains(pageKey.substringAfter(":"))) }
                ?: throw IllegalStateException("iframe for $pageKey not found")
            cx += fr.getJSONObject("rect").getDouble("x")
            cy += fr.getJSONObject("rect").getDouble("y")
        }
        val content = webContentBounds(surface) ?: throw IllegalStateException("web content view not found")
        val scale = content.width().toDouble() / main.getJSONObject("viewport").getDouble("innerWidth")
        val x = content.left + cx * scale
        val y = content.top + cy * scale
        if (y > content.bottom - 10) {
            // Below the fold: scroll the page a screen up and re-read positions.
            device.swipe(content.centerX(), content.bottom - 50, content.centerX(), content.top + 50, 20)
            SystemClock.sleep(600)
            return tapField(run, mainPage, key, surface, native)
        }
        device.click(x.toInt(), y.toInt())
    }

    private fun webContentBounds(surface: String): Rect? {
        val byClass = device.findObject(By.clazz("android.webkit.WebView"))
        if (byClass != null) return byClass.visibleBounds
        val fallback = mapOf(
            "chrome" to "com.android.chrome:id/compositor_view_holder",
            "firefox" to "org.mozilla.firefox:id/engineView",
            "samsung" to "com.sec.android.app.sbrowser:id/content_layout",
        )[surface] ?: return null
        return device.findObject(By.res(fallback))?.visibleBounds
    }

    /**
     * Find VELA's suggestion (inline chip or dropdown row) for [choose] and tap
     * it. Handles the locked case ("Unlock VELA") once. Returns (offered, taps).
     */
    private fun pickSuggestion(choose: JSONObject?): Pair<Boolean, Int> {
        var taps = 0
        val wanted = listOfNotNull(choose?.optString("text")?.takeIf { it.isNotEmpty() }, choose?.optString("name")?.takeIf { it.isNotEmpty() })
        fun find(): UiObject2? {
            for (w in wanted) device.findObject(By.textContains(w).clickable(true))?.let { return it }
            for (w in wanted) device.findObject(By.textContains(w))?.let { return clickableAncestor(it) }
            return null
        }
        val deadline = SystemClock.uptimeMillis() + 6000
        var hit: UiObject2? = null
        while (hit == null && SystemClock.uptimeMillis() < deadline) {
            hit = find()
            if (hit == null) {
                val locked = device.findObject(By.text("Unlock VELA"))
                if (locked != null) {
                    clickableAncestor(locked).click(); taps++
                    if (unlock == "finger") { SystemClock.sleep(1500); post("/__eval/host/android-finger", JSONObject()) }
                    device.wait(Until.gone(By.pkg("com.vela.android")), 15_000)
                    SystemClock.sleep(1000)
                }
                SystemClock.sleep(300)
            }
        }
        if (hit == null) return false to taps
        hit.click(); taps++
        return true to taps
    }

    private fun clickableAncestor(o: UiObject2): UiObject2 {
        var cur: UiObject2? = o
        while (cur != null && !cur.isClickable) cur = cur.parent
        return cur ?: o
    }

    // ── Live sites and live apps (no ground truth; oracle scoring) ──────────

    private fun liveSites(surface: String) {
        val arr = JSONArray(get("/__eval/scenarios?tier=live"))
        val sites = (0 until arr.length()).map { arr.getJSONObject(it) }.filter { only == null || it.getString("id") in only }.take(limit)
        for (site in sites) {
            val t0 = SystemClock.uptimeMillis()
            var error: String? = null
            var offered: Boolean? = null
            var reachable = true
            var frames = JSONArray()
            try {
                ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(site.getString("url"))).setPackage(browsers.getValue(surface))
                    .putExtra("com.android.browser.application_id", "vela-autofill-eval")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                SystemClock.sleep(7000)
                val anchor = liveAnchor(site.getString("kind"))
                if (anchor == null) reachable = false
                else {
                    anchor.click()
                    offered = pickSuggestion(JSONObject().put("text", "vela.eval@example.org")).first
                    SystemClock.sleep(1500)
                }
                frames = readVisibleFields()
            } catch (e: Throwable) { error = e.message; reachable = false }
            post("/__eval/result", JSONObject().put("runId", runId).put("tier", "live").put("scenarioId", site.getString("id"))
                .put("surface", "android-$surface").put("platform", "android").put("client", clientName(surface)).put("mode", "suggestion")
                .put("offered", offered ?: JSONObject.NULL).put("reachable", reachable).put("frames", frames)
                .put("durationMs", SystemClock.uptimeMillis() - t0).put("error", error ?: JSONObject.NULL))
            dismiss()
        }
    }

    private fun liveApps() {
        val arr = JSONArray(get("/__eval/scenarios?tier=live-app"))
        val apps = (0 until arr.length()).map { arr.getJSONObject(it) }.filter { only == null || it.getString("id") in only }.take(limit)
        val pm = ctx.packageManager
        for (app in apps) {
            val pkg = app.getString("android")
            val launch = pm.getLaunchIntentForPackage(pkg)
            if (launch == null) { println("AUTOFILL_EVAL skip ${app.getString("id")}: $pkg not installed"); continue }
            val t0 = SystemClock.uptimeMillis()
            var reachable = true
            var offered: Boolean? = null
            var error: String? = null
            var frames = JSONArray()
            try {
                ctx.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                device.wait(Until.hasObject(By.pkg(pkg).depth(0)), 10_000)
                SystemClock.sleep(3000)
                val steps = app.getJSONArray("toLogin")
                for (i in 0 until steps.length()) {
                    device.wait(Until.findObject(By.text(Pattern.compile("(?i)" + Pattern.quote(steps.getString(i))))), 6000)?.click()
                    SystemClock.sleep(2000)
                }
                val anchor = liveAnchor("login")
                if (anchor == null) reachable = false
                else {
                    anchor.click()
                    offered = pickSuggestion(JSONObject().put("text", "vela.eval@example.org")).first
                    SystemClock.sleep(1500)
                }
                frames = readVisibleFields()
            } catch (e: Throwable) { error = e.message; reachable = false }
            post("/__eval/result", JSONObject().put("runId", runId).put("tier", "live-app").put("scenarioId", app.getString("id"))
                .put("surface", "android-app").put("platform", "android").put("client", pkg).put("mode", "suggestion")
                .put("offered", offered ?: JSONObject.NULL).put("reachable", reachable).put("frames", frames)
                .put("durationMs", SystemClock.uptimeMillis() - t0).put("error", error ?: JSONObject.NULL))
            device.pressHome()
        }
    }

    private fun editTexts(): List<UiObject2> = device.findObjects(By.clazz("android.widget.EditText")).filter { it.visibleBounds.height() > 10 }

    /** UiObject2 exposes no password flag; masked text or a password-ish name/label is the signal. */
    private fun isPw(o: UiObject2): Boolean {
        val t = o.text ?: ""
        return (t.isNotEmpty() && t.all { it == '•' || it == '●' || it == '*' }) ||
            Regex("(?i)pass|pwd|mot.?de.?passe|kennwort").containsMatchIn("${o.resourceName ?: ""} ${o.contentDescription ?: ""}")
    }

    private fun liveAnchor(kind: String): UiObject2? {
        val fields = editTexts()
        if (fields.isEmpty()) return null
        val text = { o: UiObject2 -> "${o.resourceName ?: ""} ${o.text ?: ""} ${o.contentDescription ?: ""}".lowercase() }
        return when (kind) {
            "card" -> fields.firstOrNull { text(it).contains("card") }
            "email" -> fields.firstOrNull { text(it).contains("mail") }
            "signup" -> fields.firstOrNull { isPw(it) }
            "identity" -> fields.firstOrNull { Regex("name|address|zip|postal").containsMatchIn(text(it)) }
            else -> fields.firstOrNull { !isPw(it) && Regex("user|mail|login|phone|identif").containsMatchIn(text(it)) }
                ?: fields.firstOrNull { isPw(it) } ?: fields.first()
        } ?: fields.first()
    }

    /**
     * Field values as accessibility exposes them. Password fields come back
     * masked; a masked value of the live password's length is taken as the
     * live password (the only thing VELA could have put there in this run).
     */
    private fun readVisibleFields(): JSONArray {
        val live = "Live-Eval-Only-9g}pw"
        val out = JSONArray()
        for (o in editTexts()) {
            var v = o.text ?: ""
            val pw = isPw(o)
            if (pw && v.isNotEmpty() && v.all { it == '•' || it == '*' || it == '●' }) v = if (v.length == live.length) live else ""
            out.put(JSONObject().put("value", v).put("type", if (pw) "password" else "text")
                .put("name", o.resourceName ?: "").put("label", o.contentDescription ?: "")
                .put("visible", true).put("frame", "main"))
        }
        return JSONArray().put(JSONObject().put("url", "").put("fields", out))
    }

    // ── Plumbing ────────────────────────────────────────────────────────────

    private fun waitForReport(run: String, page: String, timeoutMs: Long): Boolean {
        val end = SystemClock.uptimeMillis() + timeoutMs
        while (SystemClock.uptimeMillis() < end) {
            if (runCatching { get("/__eval/state?run=${enc(run)}&page=${enc(page)}") }.getOrNull()?.trim()?.startsWith("{") == true) return true
            SystemClock.sleep(400)
        }
        return false
    }

    private fun dismiss() {
        device.pressBack(); device.pressBack(); device.pressHome()
        SystemClock.sleep(500)
    }

    private fun clientName(surface: String) = browsers[surface] ?: if (surface == "webview") "android-webview" else labPkg
    private fun withRun(url: String, run: String) = url + (if (url.contains("?")) "&" else "?") + "run=" + enc(run)
    private fun enc(s: String) = Uri.encode(s)

    private fun get(path: String): String {
        val c = URL(server + path).openConnection() as HttpURLConnection
        c.connectTimeout = 5000; c.readTimeout = 15000
        return c.inputStream.bufferedReader().use { it.readText() }.also { c.disconnect() }
    }

    private fun post(path: String, body: JSONObject): String = runCatching {
        val c = URL(server + path).openConnection() as HttpURLConnection
        c.requestMethod = "POST"; c.doOutput = true
        c.setRequestProperty("content-type", "application/json")
        c.connectTimeout = 5000; c.readTimeout = 30000
        c.outputStream.use { it.write(body.toString().toByteArray()) }
        val text = (if (c.responseCode < 400) c.inputStream else c.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
        c.disconnect(); text
    }.getOrElse { "post failed: ${it.message}" }

}
