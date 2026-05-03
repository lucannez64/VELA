package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.theme.VelaColors

@Composable
fun UnlockScreen(
    hasBiometricVault: Boolean,
    hasPasswordVault: Boolean,
    onUnlockBiometric: () -> Unit,
    onUnlockPassword: (String) -> Unit
) {
    var password by remember { mutableStateOf("") }
    var showPasswordUnlock by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
    ) {
        // Violet ambient glow
        Box(
            modifier = Modifier
                .size(320.dp)
                .align(Alignment.Center)
                .offset(y = (-40).dp)
                .blur(120.dp)
                .background(VelaColors.Violet.copy(alpha = 0.06f), CircleShape)
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(Modifier.weight(1f))

            // Shield lock icon
            Box(
                modifier = Modifier
                    .size(88.dp)
                    .background(VelaColors.SurfaceLow, CircleShape)
                    .border(2.dp, VelaColors.Outline.copy(alpha = 0.2f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Filled.Shield, null,
                    modifier = Modifier.size(44.dp),
                    tint = VelaColors.Green
                )
            }

            Spacer(Modifier.height(28.dp))

            Text(
                "Vault Locked",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(Modifier.height(8.dp))

            Text(
                "Authenticate to unlock your vault",
                color = VelaColors.TextSecondary,
                fontSize = 16.sp,
                textAlign = TextAlign.Center
            )

            Spacer(Modifier.weight(1f))

            if (!showPasswordUnlock) {
                if (hasBiometricVault) {
                    VelaButton(
                        text = "Unlock with Biometric",
                        onClick = onUnlockBiometric,
                        style = VelaButtonStyle.Gradient,
                        icon = Icons.Filled.Fingerprint
                    )

                    Spacer(Modifier.height(16.dp))
                }

                if (hasPasswordVault) {
                    VelaButton(
                        text = "Unlock with Password",
                        onClick = { showPasswordUnlock = true },
                        style = VelaButtonStyle.Surface,
                        icon = Icons.Filled.Lock
                    )
                } else if (!hasBiometricVault) {
                    Text(
                        "No vault found. Please create one first.",
                        color = VelaColors.WarningAmber,
                        fontSize = 14.sp
                    )
                }
            } else {
                VelaTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = "Master Password",
                    isPassword = true
                )

                Spacer(Modifier.height(20.dp))

                VelaButton(
                    text = "Unlock",
                    onClick = {
                        if (password.isNotBlank()) onUnlockPassword(password)
                    },
                    style = VelaButtonStyle.Gradient,
                    enabled = password.isNotBlank(),
                    icon = Icons.Filled.Lock
                )

                Spacer(Modifier.height(12.dp))

                VelaButton(
                    text = "Back",
                    onClick = {
                        showPasswordUnlock = false
                        password = ""
                    },
                    style = VelaButtonStyle.TextOnly
                )
            }

            Spacer(Modifier.weight(1f))
        }
    }
}
