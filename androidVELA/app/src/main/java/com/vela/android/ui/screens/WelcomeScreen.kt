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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Shield
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.theme.VelaColors

@Composable
fun WelcomeScreen(
    onCreateBiometricVault: () -> Unit,
    onCreatePasswordVault: (String) -> Unit,
    onNavigateToEnroll: () -> Unit,
    onNavigateToRecover: () -> Unit
) {
    var password by remember { mutableStateOf("") }
    var showPasswordSetup by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
    ) {
        // Ambient glow decorations
        Box(
            modifier = Modifier
                .size(280.dp)
                .offset(x = (-40).dp, y = (-40).dp)
                .blur(100.dp)
                .background(VelaColors.Green.copy(alpha = 0.06f), CircleShape)
        )
        Box(
            modifier = Modifier
                .size(240.dp)
                .offset(x = 200.dp, y = 100.dp)
                .blur(80.dp)
                .background(VelaColors.Violet.copy(alpha = 0.05f), CircleShape)
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(Modifier.weight(1f))

            // Hero icon
            Box(
                modifier = Modifier
                    .size(80.dp)
                    .clip(RoundedCornerShape(20.dp))
                    .background(VelaColors.Green.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Filled.Shield, null,
                    modifier = Modifier.size(40.dp),
                    tint = VelaColors.Green
                )
            }

            Spacer(Modifier.height(32.dp))

            Text(
                "VELA",
                fontSize = 40.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 3.sp
            )

            Spacer(Modifier.height(8.dp))

            StatusBadge(
                text = "Zero-Knowledge Security",
                backgroundColor = VelaColors.Teal.copy(alpha = 0.12f),
                textColor = VelaColors.Teal
            )

            Spacer(Modifier.height(24.dp))

            Text(
                if (showPasswordSetup) "Create a strong fallback password\nto protect your vault" else "Your vault stays local-first.\nNo server required to get started.",
                color = VelaColors.TextSecondary,
                fontSize = 15.sp,
                textAlign = TextAlign.Center,
                lineHeight = 22.sp
            )

            Spacer(Modifier.weight(1f))

            if (!showPasswordSetup) {
                VelaButton(
                    text = "Create with Biometric",
                    onClick = onCreateBiometricVault,
                    style = VelaButtonStyle.Gradient,
                    icon = Icons.Filled.Fingerprint
                )

                Spacer(Modifier.height(16.dp))

                VelaButton(
                    text = "Create with Password",
                    onClick = { showPasswordSetup = true },
                    style = VelaButtonStyle.Surface,
                    icon = Icons.Filled.Key
                )

                Spacer(Modifier.height(24.dp))

                VelaButton(
                    text = "Enroll as Secondary Device",
                    onClick = onNavigateToEnroll,
                    style = VelaButtonStyle.TextOnly,
                    icon = Icons.Filled.Add
                )

                Spacer(Modifier.height(8.dp))

                VelaButton(
                    text = "Recover My Account",
                    onClick = onNavigateToRecover,
                    style = VelaButtonStyle.TextOnly,
                    icon = Icons.Filled.Restore
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
                        if (password.length >= 8) onCreatePasswordVault(password)
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
