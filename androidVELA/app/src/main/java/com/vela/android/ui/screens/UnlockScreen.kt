package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.components.*
import com.vela.android.ui.theme.*

/**
 * Lock screen, mirroring the desktop Instrument gate: a sunrise hero with the
 * vault promise, then one card holding the device-unlock action and the master
 * password fallback. Every state is reachable by scrolling on small phones.
 */
@Composable
fun UnlockScreen(hasBiometricVault: Boolean, hasPasswordVault: Boolean,
    onUnlockBiometric: () -> Unit, onUnlockPassword: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    var usePassword by remember { mutableStateOf(!hasBiometricVault && hasPasswordVault) }
    val unlockLabel = if (usePassword) "Enter your master password to continue." else "Confirm with your device to continue."

    Column(
        Modifier.fillMaxSize().background(VelaColors.SurfaceBase).imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp).padding(top = 4.dp, bottom = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(Modifier.arrive(0)) { InstrumentBrand(trailingLabel = "Vault locked") }

        SunrisePanel(Modifier.fillMaxWidth().height(224.dp).arrive(1, 14.dp)) {
            Column(Modifier.fillMaxSize().padding(22.dp), verticalArrangement = Arrangement.SpaceBetween) {
                InstrumentLabel("01 / Your vault", color = Color(0xFFB2ACC3))
                Column {
                    Text("Your keys.\nOnly yours.", fontFamily = InstrumentDisplay, fontSize = 30.sp, lineHeight = 34.sp,
                        letterSpacing = (-1).sp, fontWeight = FontWeight.Medium, color = Color(0xFFF3F2EF))
                    Spacer(Modifier.height(10.dp))
                    InstrumentFine("Your vault is sealed. Unlock it on this device to pick up where you left off.",
                        size = 11.sp, color = Color(0xD9E6DDF5))
                }
                InstrumentLabel("Encrypted on this device", color = Color(0xB3E6DDF5))
            }
        }

        Spacer(Modifier.height(18.dp))

        Column(
            Modifier.fillMaxWidth().arrive(2)
                .instrumentPanel(24.dp, Ink.line, Ink.panel).padding(20.dp),
        ) {
            Box(
                Modifier.size(52.dp).background(Ink.panel2, RoundedCornerShape(16.dp))
                    .border(1.dp, Ink.line, RoundedCornerShape(16.dp)),
                contentAlignment = Alignment.Center,
            ) { InstrumentIcon(InstrumentIcons.Lock, 24.dp, VelaColors.Violet) }
            Spacer(Modifier.height(16.dp))
            InstrumentLabel("02 / Locked")
            Spacer(Modifier.height(10.dp))
            Text("Welcome back.", fontFamily = InstrumentDisplay, fontSize = 32.sp, lineHeight = 36.sp,
                letterSpacing = (-1.2).sp, fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
            Spacer(Modifier.height(8.dp))
            InstrumentFine(unlockLabel)
            Spacer(Modifier.height(20.dp))

            if (usePassword) {
                VelaTextField(password, { password = it }, label = "Master password", isPassword = true)
                Spacer(Modifier.height(14.dp))
                InstrumentPill(
                    "Unlock vault",
                    { val entered = password; password = ""; onUnlockPassword(entered) },
                    Modifier.fillMaxWidth(), icon = InstrumentIcons.Lock, style = PillStyle.Primary,
                    enabled = password.isNotBlank(),
                )
                if (hasBiometricVault) {
                    Spacer(Modifier.height(10.dp))
                    TextAction("Use biometrics instead") { password = ""; usePassword = false }
                }
            } else {
                if (hasBiometricVault) {
                    InstrumentPill("Unlock with biometrics", onUnlockBiometric,
                        Modifier.fillMaxWidth(), icon = InstrumentIcons.Fingerprint, style = PillStyle.Primary)
                    if (hasPasswordVault) Spacer(Modifier.height(10.dp))
                }
                if (hasPasswordVault) {
                    InstrumentPill("Use master password", { usePassword = true },
                        Modifier.fillMaxWidth(), icon = InstrumentIcons.Key, iconTrailing = true)
                }
            }

            Spacer(Modifier.height(20.dp))
            HorizontalDivider(color = Ink.line)
            Spacer(Modifier.height(14.dp))
            InstrumentLabel("Local unlock / end-to-end encrypted", color = Ink.faint)
        }

        InstrumentFine("Your keys stay on your devices.",
            Modifier.padding(top = 24.dp), size = 9.sp, align = TextAlign.Center)
    }
}
