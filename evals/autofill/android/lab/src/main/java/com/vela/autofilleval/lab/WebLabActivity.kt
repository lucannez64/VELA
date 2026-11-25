package com.vela.autofilleval.lab

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

/**
 * A plain in-app WebView on a fixture page: the "login inside an app" case
 * (OAuth screens, embedded checkouts). The page's own beacon reports fields.
 * Extra: url.
 */
class WebLabActivity : AppCompatActivity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            webViewClient = WebViewClient()
        }
        setContentView(web)
        web.loadUrl(intent.getStringExtra("url") ?: "http://10.0.2.2:8080/")
    }
}
