package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.MainActivity
import com.vela.android.core.VelaRepositories
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class TtlOption(val label: String, val secs: Long)

private val TTL_OPTIONS = listOf(
    TtlOption("30 min", 30 * 60),
    TtlOption("1 hour", 60 * 60),
    TtlOption("8 hours", 8 * 60 * 60),
    TtlOption("24 hours", 24 * 60 * 60),
)

/**
 * Approve a browser's temporary, revocable web access to this vault
 * (EPHEMERAL_WEB_ACCESS_DESIGN.md). Scan the code shown by the web page, pick a
 * duration, and approve. Read-only is the default; read-write is behind an
 * explicit "I trust this device" toggle.
 */
@Composable
fun WebAccessScreen(onBack: () -> Unit) {
    val activity = LocalContext.current as? MainActivity
    val scope = rememberCoroutineScope()

    var qrJson by remember { mutableStateOf<String?>(null) }
    var mode by remember { mutableStateOf("ro") }
    var showAdvanced by remember { mutableStateOf(false) }
    var ttlSecs by remember { mutableStateOf(TTL_OPTIONS[0].secs) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
    ) {
        ScreenHeader("Web Access", onBack)

        Spacer(Modifier.height(8.dp))
        Text(
            "Temporarily open this vault in a browser — no install, no permanent device. " +
                "Access expires automatically and can be revoked any time.",
            color = VelaColors.TextSecondary,
            fontSize = 14.sp,
        )

        Spacer(Modifier.height(24.dp))

        VelaButton(
            text = if (qrJson == null) "Scan web access code" else "Code scanned ✓ — rescan",
            onClick = {
                if (activity == null) {
                    error = "Unable to open the QR scanner"
                } else {
                    activity.launchQrScanner("Scan the code from the web page") { contents ->
                        if (contents.isNullOrBlank()) {
                            status = "Scan cancelled"
                        } else {
                            qrJson = contents.trim()
                            status = "Code scanned"
                            error = null
                        }
                    }
                }
            },
            style = VelaButtonStyle.Surface,
            icon = Icons.Filled.QrCodeScanner,
            enabled = !busy,
        )

        Spacer(Modifier.height(24.dp))

        Text("Duration", color = VelaColors.TextMuted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TTL_OPTIONS.forEach { opt ->
                VelaButton(
                    text = opt.label,
                    onClick = { ttlSecs = opt.secs },
                    style = if (ttlSecs == opt.secs) VelaButtonStyle.Gradient else VelaButtonStyle.Surface,
                    fullWidth = false,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                )
            }
        }

        Spacer(Modifier.height(24.dp))

        if (!showAdvanced) {
            VelaButton(
                text = "Advanced — I trust this device",
                onClick = { showAdvanced = true },
                style = VelaButtonStyle.TextOnly,
                enabled = !busy,
            )
        } else {
            Text("Mode", color = VelaColors.TextMuted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                VelaButton(
                    text = "Read-only",
                    onClick = { mode = "ro" },
                    style = if (mode == "ro") VelaButtonStyle.Gradient else VelaButtonStyle.Surface,
                    fullWidth = false,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                )
                VelaButton(
                    text = "Read & write",
                    onClick = { mode = "rw" },
                    style = if (mode == "rw") VelaButtonStyle.Gradient else VelaButtonStyle.Surface,
                    fullWidth = false,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                )
            }
            if (mode == "rw") {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Read & write sends this device's master key to the browser for the session. " +
                        "Only use it on a device you trust.",
                    color = VelaColors.ErrorRed,
                    fontSize = 12.sp,
                )
            }
        }

        Spacer(Modifier.height(24.dp))

        error?.let {
            StatusBadge(text = it, backgroundColor = VelaColors.ErrorRedBg, textColor = VelaColors.ErrorRed)
            Spacer(Modifier.height(8.dp))
        }
        status?.let {
            if (error == null) {
                Text(it, color = VelaColors.TextMuted, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
            }
        }

        VelaButton(
            text = if (busy) "Approving…" else "Approve",
            onClick = {
                val code = qrJson
                if (code == null) {
                    error = "Scan the web access code first"
                    return@VelaButton
                }
                busy = true
                error = null
                val chosenMode = mode
                val chosenTtl = ttlSecs
                scope.launch(Dispatchers.IO) {
                    runCatching { VelaRepositories.sharing.grantWebAccess(code, chosenMode, chosenTtl) }
                        .onSuccess {
                            withContext(Dispatchers.Main) {
                                busy = false
                                status = "Web access granted"
                                onBack()
                            }
                        }
                        .onFailure { e ->
                            withContext(Dispatchers.Main) {
                                busy = false
                                error = e.message ?: "Could not grant web access"
                            }
                        }
                }
            },
            style = VelaButtonStyle.Gradient,
            icon = Icons.Filled.Public,
            enabled = !busy && qrJson != null,
        )
    }
}
