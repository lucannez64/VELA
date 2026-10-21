package com.vela.android.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.components.*
import com.vela.android.ui.theme.*

/** Lock screen, per the Instrument reference: halo, large biometric key, password fallback. */
@Composable
fun UnlockScreen(hasBiometricVault: Boolean, hasPasswordVault: Boolean,
    onUnlockBiometric: () -> Unit, onUnlockPassword: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    var usePassword by remember { mutableStateOf(!hasBiometricVault && hasPasswordVault) }
    val reduced = rememberReducedMotion()
    val glow = rememberInfiniteTransition(label = "bio")
    val ring by glow.animateFloat(0f, if (reduced) 0f else 1f, infiniteRepeatable(tween(1800, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "ring")
    Column(
        Modifier.fillMaxSize().background(VelaColors.SurfaceBase).imePadding().verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp).padding(top = 10.dp, bottom = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(Modifier.arrive(0)) { InstrumentBrand(trailingLabel = "Vault locked") }
        LockOrbit(Modifier.padding(horizontal = 0.dp).padding(bottom = 22.dp).arrive(1, 16.dp)) {
            InstrumentIcon(InstrumentIcons.Lock, 42.dp, VelaColors.Violet)
        }
        Column(Modifier.padding(top = 22.dp).arrive(2), horizontalAlignment = Alignment.CenterHorizontally) {
            InstrumentLabel("Your private space")
            Spacer(Modifier.height(14.dp))
            Text("Still yours.", fontFamily = InstrumentDisplay, fontSize = 34.sp, lineHeight = 37.sp, letterSpacing = (-1.5).sp,
                fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
            InstrumentFine("Your vault is locked.\nOpen it with your device or master password.",
                Modifier.padding(top = 15.dp, bottom = 25.dp).widthIn(max = 240.dp), align = TextAlign.Center)
        }
        AnimatedContent(usePassword, Modifier.arrive(3), transitionSpec = { fadeIn(tween(220)) togetherWith fadeOut(tween(150)) }, label = "unlock") { typing ->
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (typing) {
                    com.vela.android.ui.components.VelaTextField(password, { password = it }, label = "Master password", isPassword = true)
                    Spacer(Modifier.height(18.dp))
                    InstrumentPill("Unlock vault", { val entered = password; password = ""; onUnlockPassword(entered) },
                        Modifier.fillMaxWidth(), icon = InstrumentIcons.Lock, style = PillStyle.Primary, enabled = password.isNotBlank())
                    if (hasBiometricVault) {
                        Spacer(Modifier.height(10.dp))
                        TextAction("Use biometrics instead") { password = ""; usePassword = false }
                    }
                } else {
                    if (hasBiometricVault) {
                        val shape = RoundedCornerShape(25.dp)
                        Box(
                            Modifier.size(72.dp).graphicsLayer { val s = 1f + .03f * ring; scaleX = s; scaleY = s }
                                .background(Ink.panel, shape).border(1.dp, VelaColors.Violet.copy(alpha = .6f + .4f * ring), shape)
                                .instrumentClick(onClick = onUnlockBiometric).semantics { contentDescription = "Unlock with biometrics" },
                            contentAlignment = Alignment.Center,
                        ) { InstrumentIcon(InstrumentIcons.Fingerprint, 34.dp, VelaColors.Violet) }
                        Spacer(Modifier.height(12.dp))
                        InstrumentFine("Touch to unlock", size = 10.sp)
                    }
                    if (hasPasswordVault) InstrumentPill("Use master password", { usePassword = true },
                        Modifier.fillMaxWidth().padding(top = 24.dp), icon = InstrumentIcons.Key, iconTrailing = true)
                }
            }
        }
        InstrumentFine("Your keys stay on your devices.", Modifier.padding(top = 30.dp), size = 9.sp)
    }
}
