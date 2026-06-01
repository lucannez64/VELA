package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DevicesOther
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.MainActivity
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.theme.VelaColors

@Composable
fun EnrollDeviceScreen(
    errorMessage: String?,
    isEnrolling: Boolean,
    isEnrolled: Boolean,
    onEnroll: (serverUrl: String, enrollmentCode: String) -> Unit,
    onProtectBiometric: () -> Unit,
    onProtectPassword: (String) -> Unit,
    onBack: () -> Unit
) {
    val activity = LocalContext.current as? MainActivity
    var serverUrl by remember { mutableStateOf("") }
    var enrollmentCode by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var showPasswordSetup by remember { mutableStateOf(false) }
    var scannedParts by remember { mutableStateOf<Map<Int, String>>(emptyMap()) }
    var scannedTotal by remember { mutableStateOf<Int?>(null) }
    var scanMessage by remember { mutableStateOf<String?>(null) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
    ) {
        Box(
            modifier = Modifier
                .size(280.dp)
                .offset(x = (-40).dp, y = (-40).dp)
                .blur(100.dp)
                .background(VelaColors.Violet.copy(alpha = 0.06f), CircleShape)
        )
        Box(
            modifier = Modifier
                .size(240.dp)
                .offset(x = 200.dp, y = 100.dp)
                .blur(80.dp)
                .background(VelaColors.Green.copy(alpha = 0.05f), CircleShape)
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(Modifier.weight(1f))

            Icon(
                Icons.Filled.DevicesOther, null,
                modifier = Modifier.size(48.dp),
                tint = VelaColors.Violet
            )

            Spacer(Modifier.height(24.dp))

            Text(
                "Enroll Device",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(Modifier.height(8.dp))

            val subtitle = when {
                isEnrolling -> "Registering with server..."
                isEnrolled && !showPasswordSetup -> "Vault downloaded. Secure it locally."
                isEnrolled && showPasswordSetup -> "Create a strong fallback password"
                else -> "Link this device to your existing vault"
            }

            Text(
                subtitle,
                color = VelaColors.TextSecondary,
                fontSize = 15.sp,
                textAlign = TextAlign.Center
            )

            Spacer(Modifier.height(8.dp))

            if (errorMessage != null) {
                StatusBadge(
                    text = errorMessage,
                    backgroundColor = VelaColors.ErrorRedBg,
                    textColor = VelaColors.ErrorRed
                )
                Spacer(Modifier.height(8.dp))
            }

            Spacer(Modifier.weight(1f))

            if (isEnrolled) {
                if (!showPasswordSetup) {
                    VelaButton(
                        text = "Secure with Biometric",
                        onClick = onProtectBiometric,
                        style = VelaButtonStyle.Gradient,
                        icon = Icons.Filled.Fingerprint
                    )

                    Spacer(Modifier.height(16.dp))

                    VelaButton(
                        text = "Secure with Password",
                        onClick = { showPasswordSetup = true },
                        style = VelaButtonStyle.Surface,
                        icon = Icons.Filled.Key
                    )

                    Spacer(Modifier.height(16.dp))

                    VelaButton(
                        text = "Back",
                        onClick = onBack,
                        style = VelaButtonStyle.TextOnly
                    )
                } else {
                    VelaTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = "Master Password",
                        isPassword = true,
                        placeholder = "8+ characters"
                    )

                    Spacer(Modifier.height(20.dp))

                    VelaButton(
                        text = "Create Password Vault",
                        onClick = {
                            if (password.length >= 8) onProtectPassword(password)
                        },
                        style = VelaButtonStyle.Gradient,
                        enabled = password.length >= 8,
                        icon = Icons.Filled.Lock
                    )

                    Spacer(Modifier.height(12.dp))

                    VelaButton(
                        text = "Back",
                        onClick = { showPasswordSetup = false },
                        style = VelaButtonStyle.TextOnly
                    )
                }
            } else {
                VelaTextField(
                    value = serverUrl,
                    onValueChange = { serverUrl = it },
                    label = "Server URL",
                    placeholder = "https://your-server.com",
                    enabled = !isEnrolling
                )

                Spacer(Modifier.height(16.dp))

                VelaTextField(
                    value = enrollmentCode,
                    onValueChange = { enrollmentCode = it },
                    label = "Enrollment Code",
                    isPassword = true,
                    placeholder = "From your primary device",
                    enabled = !isEnrolling
                )

                scanMessage?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = VelaColors.TextMuted, fontSize = 12.sp, textAlign = TextAlign.Center)
                }

                Spacer(Modifier.height(14.dp))

                VelaButton(
                    text = scannedTotal?.let { total ->
                        "Scan QR (${scannedParts.size}/$total)"
                    } ?: "Scan QR Code",
                    onClick = {
                        if (activity == null) {
                            scanMessage = "Unable to open QR scanner"
                        } else {
                            activity.launchQrScanner("Scan VELA enrollment QR") { contents ->
                                if (contents.isNullOrBlank()) {
                                    scanMessage = "Scan cancelled"
                                } else {
                                    val parsed = parseEnrollmentQr(contents)
                                    if (parsed == null) {
                                        enrollmentCode = contents.trim()
                                        scanMessage = "Enrollment code scanned"
                                    } else {
                                        scannedTotal = parsed.total
                                        scannedParts = scannedParts + (parsed.index to parsed.payload)
                                        val count = (scannedParts + (parsed.index to parsed.payload)).size
                                        scanMessage = "Scanned QR part $count of ${parsed.total}"
                                        if (count == parsed.total) {
                                            enrollmentCode = (1..parsed.total).joinToString("") { part ->
                                                (scannedParts + (parsed.index to parsed.payload))[part].orEmpty()
                                            }
                                            scanMessage = "Enrollment QR complete"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    style = VelaButtonStyle.Surface,
                    enabled = !isEnrolling,
                    icon = Icons.Filled.QrCodeScanner
                )

                Spacer(Modifier.height(24.dp))

                VelaButton(
                    text = if (isEnrolling) "Enrolling..." else "Enroll",
                    onClick = {
                        if (enrollmentCode.isNotBlank()) {
                            onEnroll(serverUrl.trim(), enrollmentCode.trim())
                        }
                    },
                    style = VelaButtonStyle.Gradient,
                    enabled = enrollmentCode.isNotBlank() && !isEnrolling,
                    icon = Icons.Filled.DevicesOther
                )

                Spacer(Modifier.height(12.dp))

                VelaButton(
                    text = "Back",
                    onClick = onBack,
                    style = VelaButtonStyle.TextOnly
                )
            }

            Spacer(Modifier.weight(1f))

            Row(
                modifier = Modifier.padding(bottom = 16.dp),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Outlined.Lock, null, modifier = Modifier.size(12.dp), tint = VelaColors.TextMuted)
                Spacer(Modifier.width(6.dp))
                Text(
                    "Encrypted locally · Optional server sync",
                    fontSize = 11.sp,
                    color = VelaColors.TextMuted
                )
            }
        }
    }
}

private data class EnrollmentQrPart(
    val index: Int,
    val total: Int,
    val payload: String
)

private fun parseEnrollmentQr(value: String): EnrollmentQrPart? {
    val prefix = "VELA-ENROLL:"
    if (!value.startsWith(prefix)) return null
    val rest = value.removePrefix(prefix)
    val firstColon = rest.indexOf(':')
    if (firstColon <= 0) return null
    val range = rest.substring(0, firstColon)
    val slash = range.indexOf('/')
    if (slash <= 0) return null
    val index = range.substring(0, slash).toIntOrNull() ?: return null
    val total = range.substring(slash + 1).toIntOrNull() ?: return null
    val payload = rest.substring(firstColon + 1)
    if (index !in 1..total || payload.isEmpty()) return null
    return EnrollmentQrPart(index, total, payload)
}
