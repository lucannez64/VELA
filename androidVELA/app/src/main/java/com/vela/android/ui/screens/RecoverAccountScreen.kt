package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import com.vela.android.security.GoogleDriveRecoveryBackup
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Recover an account on a brand-new device when every enrolled device has
 * been lost (SPEC.md §4.3) — reconstructs the RMS from Share 1 (pasted from
 * wherever the user stored it during recovery setup) + Share 2 (released by
 * the server after a WebAuthn security-key assertion), registers this
 * device, and pulls the vault down. Mirrors `EnrollDeviceScreen`'s two-phase
 * shape: enter recovery details, then secure the recovered vault locally.
 */
@Composable
fun RecoverAccountScreen(
    errorMessage: String?,
    isRecovering: Boolean,
    isRecovered: Boolean,
    onRecover: (serverUrl: String, userId: String, share1B64: String, deviceName: String) -> Unit,
    onProtectBiometric: () -> Unit,
    onProtectPassword: (String) -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val scope = rememberCoroutineScope()

    var serverUrl by remember { mutableStateOf("") }
    var userId by remember { mutableStateOf("") }
    var share1 by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var showPasswordSetup by remember { mutableStateOf(false) }
    var isFetchingFromDrive by remember { mutableStateOf(false) }
    var driveError by remember { mutableStateOf<String?>(null) }

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
                .background(VelaColors.Teal.copy(alpha = 0.06f), CircleShape)
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
                Icons.Filled.Restore, null,
                modifier = Modifier.size(48.dp),
                tint = VelaColors.Teal
            )

            Spacer(Modifier.height(24.dp))

            Text("Recover Account", fontSize = 28.sp, fontWeight = FontWeight.Bold)

            Spacer(Modifier.height(8.dp))

            val subtitle = when {
                isRecovering -> "Reconstructing your vault key..."
                isRecovered && !showPasswordSetup -> "Vault downloaded. Secure it locally."
                isRecovered && showPasswordSetup -> "Create a strong fallback password"
                else -> "Every device lost? Rebuild your vault key from its recovery shares."
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

            if (isRecovered) {
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
                        onClick = { if (password.length >= 8) onProtectPassword(password) },
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
                    enabled = !isRecovering
                )

                Spacer(Modifier.height(16.dp))

                VelaButton(
                    text = if (isFetchingFromDrive) "Checking Google Drive..." else "Fetch Share 1 from Google Drive",
                    onClick = {
                        val currentActivity = activity
                        if (currentActivity == null) {
                            driveError = "Unable to access this activity"
                            return@VelaButton
                        }
                        isFetchingFromDrive = true
                        driveError = null
                        scope.launch(Dispatchers.IO) {
                            try {
                                val driveBackup = GoogleDriveRecoveryBackup(currentActivity)
                                val token = driveBackup.getAccessToken { intentSender ->
                                    currentActivity.awaitDriveConsent(intentSender)
                                }
                                val backup = driveBackup.download(token)
                                withContext(Dispatchers.Main) {
                                    if (backup != null) {
                                        userId = backup.userId
                                        share1 = backup.shareB64
                                    } else {
                                        driveError = "No recovery backup found on this Google account"
                                    }
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    driveError = e.message ?: "Google Drive fetch failed"
                                }
                            } finally {
                                withContext(Dispatchers.Main) { isFetchingFromDrive = false }
                            }
                        }
                    },
                    style = VelaButtonStyle.Surface,
                    enabled = !isRecovering && !isFetchingFromDrive,
                    icon = Icons.Filled.CloudDownload
                )

                if (driveError != null) {
                    Spacer(Modifier.height(8.dp))
                    StatusBadge(
                        text = driveError!!,
                        backgroundColor = VelaColors.ErrorRedBg,
                        textColor = VelaColors.ErrorRed
                    )
                }

                Spacer(Modifier.height(16.dp))

                VelaTextField(
                    value = userId,
                    onValueChange = { userId = it },
                    label = "Account ID (UUID)",
                    enabled = !isRecovering
                )

                Spacer(Modifier.height(16.dp))

                VelaTextField(
                    value = share1,
                    onValueChange = { share1 = it },
                    label = "Recovery Share 1",
                    placeholder = "From Google Drive, or paste it manually",
                    enabled = !isRecovering
                )

                Spacer(Modifier.height(16.dp))

                VelaTextField(
                    value = deviceName,
                    onValueChange = { deviceName = it },
                    label = "Device name (optional)",
                    enabled = !isRecovering
                )

                Spacer(Modifier.height(8.dp))

                Text(
                    "You'll be asked to verify with the security key you registered for recovery.",
                    color = VelaColors.TextMuted,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center
                )

                Spacer(Modifier.height(20.dp))

                VelaButton(
                    text = if (isRecovering) "Recovering..." else "Recover Account",
                    onClick = {
                        if (userId.isNotBlank() && share1.isNotBlank()) {
                            onRecover(serverUrl.trim(), userId.trim(), share1.trim(), deviceName.trim())
                        }
                    },
                    style = VelaButtonStyle.Gradient,
                    enabled = userId.isNotBlank() && share1.isNotBlank() && !isRecovering,
                    icon = Icons.Filled.Restore
                )

                Spacer(Modifier.height(12.dp))

                VelaButton(
                    text = "Back",
                    onClick = onBack,
                    style = VelaButtonStyle.TextOnly,
                    enabled = !isRecovering
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
