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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.MainActivity
import com.vela.android.core.VelaRepositories
import com.vela.android.security.GoogleDriveRecoveryBackup
import com.vela.android.security.WebAuthnCeremony
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Recovery setup (SPEC.md §4.3): split the RMS into a 2-of-3 Shamir scheme,
 * register a WebAuthn recovery passkey (a physical security key, independent
 * of this device's biometrics), deliver Share 2 to the server gated behind
 * that passkey, and back Share 1 up to the user's Google Drive appDataFolder
 * (hidden, per-app storage — see `GoogleDriveRecoveryBackup`). Share 3 is
 * shown here for the user to hand to a trusted contact — there's no
 * automated channel for that one.
 */
@Composable
fun RecoverySetupScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val scope = rememberCoroutineScope()

    var isSettingUp by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var trustedContactShare by remember { mutableStateOf<String?>(null) }
    var cloudBackupDone by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp)
    ) {
        Spacer(Modifier.height(24.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
            }
            Spacer(Modifier.width(4.dp))
            Text("Recovery setup", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(16.dp))

        VelaCard {
            Text(
                "Configure recovery so you can restore this vault if every device is lost: Share 1 backs up " +
                    "to your Google Drive automatically, Share 2 goes to a security key you register now, " +
                    "and Share 3 is yours to hand to a trusted contact.",
                fontSize = 13.sp,
                color = VelaColors.TextSecondary
            )
            Spacer(Modifier.height(16.dp))

            if (errorMessage != null) {
                StatusBadge(
                    text = errorMessage!!,
                    backgroundColor = VelaColors.ErrorRedBg,
                    textColor = VelaColors.ErrorRed
                )
                Spacer(Modifier.height(12.dp))
            }

            if (trustedContactShare == null) {
                VelaButton(
                    text = if (isSettingUp) "Setting up..." else "Set up recovery (2-of-3)",
                    onClick = {
                        val currentActivity = activity
                        if (currentActivity == null) {
                            errorMessage = "Unable to access this activity"
                            return@VelaButton
                        }
                        isSettingUp = true
                        errorMessage = null
                        scope.launch(Dispatchers.IO) {
                            try {
                                val ceremony = WebAuthnCeremony(context)
                                val (share1, share3) = VelaRepositories.sync.setupRecovery { options ->
                                    ceremony.register(options)
                                }.let { it[0] to it[1] }

                                val userId = VelaRepositories.serverIdentity.load()?.userId
                                    ?: error("Register with the server before setting up recovery")
                                val driveBackup = GoogleDriveRecoveryBackup(currentActivity)
                                val token = driveBackup.getAccessToken { intentSender ->
                                    currentActivity.awaitDriveConsent(intentSender)
                                }
                                driveBackup.upload(token, userId, share1)

                                withContext(Dispatchers.Main) {
                                    cloudBackupDone = true
                                    trustedContactShare = share3
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    errorMessage = e.message ?: "Recovery setup failed"
                                }
                            } finally {
                                withContext(Dispatchers.Main) { isSettingUp = false }
                            }
                        }
                    },
                    style = VelaButtonStyle.Gradient,
                    enabled = !isSettingUp,
                    icon = Icons.Filled.Key
                )
            } else {
                Text(
                    if (cloudBackupDone) {
                        "Share 1 backed up to Google Drive, recovery passkey registered, and Share 2 delivered " +
                            "to the server. Store this last share somewhere safe:"
                    } else {
                        "Recovery passkey registered and Share 2 delivered to the server. " +
                            "Store this last share somewhere safe:"
                    },
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = VelaColors.TextPrimary
                )
                Spacer(Modifier.height(12.dp))
                Text("Share 3 (trusted contact)", fontSize = 12.sp, color = VelaColors.TextMuted)
                Text(
                    trustedContactShare!!,
                    fontSize = 12.sp,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)
                )
            }
        }
    }
}
