package com.vela.autofilleval.lab

import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Renders one form from corpus/native-forms.json as real Android views.
 *
 * Extras: server (http://10.0.2.2:8080), run, form (form id).
 * Without extras it lists the forms, for poking at by hand.
 */
class LabActivity : AppCompatActivity() {
    private var reporter: Reporter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val server = intent.getStringExtra("server") ?: "http://10.0.2.2:8080"
        val run = intent.getStringExtra("run") ?: "manual"
        val formId = intent.getStringExtra("form")
        val status = TextView(this).apply { text = "Loading forms from $server…"; setPadding(32, 32, 32, 32) }
        setContentView(status)
        thread {
            val forms = runCatching { JSONArray(httpGet("$server/__eval/scenarios?tier=native")) }
                .getOrElse { e -> runOnUiThread { status.text = "Cannot reach $server: ${e.message}" }; return@thread }
            runOnUiThread {
                val form = (0 until forms.length()).map { forms.getJSONObject(it) }.firstOrNull { it.getString("id") == formId }
                if (form == null) showIndex(forms, server) else showForm(form, server, run)
            }
        }
    }

    private fun showIndex(forms: JSONArray, server: String) {
        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 32, 32, 32) }
        for (i in 0 until forms.length()) {
            val f = forms.getJSONObject(i)
            list.addView(Button(this).apply {
                text = "${f.getString("id")} (${f.getString("kind")})"
                setOnClickListener {
                    startActivity(intent.setClass(this@LabActivity, LabActivity::class.java)
                        .putExtra("server", server).putExtra("run", "manual").putExtra("form", f.getString("id")))
                }
            })
        }
        setContentView(ScrollView(this).apply { addView(list) })
    }

    private fun showForm(form: JSONObject, server: String, run: String) {
        title = form.getString("id")
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 40, 40, 40) }
        val views = linkedMapOf<String, EditText>()
        val fields = form.getJSONArray("fields")
        for (i in 0 until fields.length()) {
            val spec = fields.getJSONObject(i)
            val id = spec.getString("id")
            val android = spec.optJSONObject("android") ?: JSONObject()
            val label = spec.optString("label")
            if (label.isNotEmpty()) col.addView(TextView(this).apply { text = label })
            val edit = EditText(this).apply {
                this.id = resources.getIdentifier(id, "id", packageName).takeIf { it != 0 } ?: View.generateViewId()
                hint = spec.optString("placeholder").ifEmpty { null }
                inputType = inputTypeOf(android.optString("inputType", "text"))
                android.optJSONArray("autofillHints")?.let { h -> setAutofillHints(*Array(h.length()) { h.getString(it) }) }
                if (android.optString("importantForAutofill") == "no") importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            }
            col.addView(edit)
            views[id] = edit
        }
        col.addView(Button(this).apply { text = "Continue" })
        setContentView(ScrollView(this).apply { addView(col) })
        reporter = Reporter(server, run, form.getString("id"), views).also { it.start() }
    }

    override fun onDestroy() {
        reporter?.stop()
        super.onDestroy()
    }

    private fun inputTypeOf(name: String): Int = when (name) {
        "textPassword" -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        "numberPassword" -> InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        "textEmailAddress" -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        "textPersonName" -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PERSON_NAME
        "number" -> InputType.TYPE_CLASS_NUMBER
        "phone" -> InputType.TYPE_CLASS_PHONE
        else -> InputType.TYPE_CLASS_TEXT
    }
}
