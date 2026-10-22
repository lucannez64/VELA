package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.components.*
import com.vela.android.ui.theme.*

@Composable
fun WelcomeScreen(onCreateBiometricVault: () -> Unit, onCreatePasswordVault: (String) -> Unit,
    onNavigateToEnroll: () -> Unit, onNavigateToRecover: () -> Unit) {
    var setup by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).imePadding().verticalScroll(rememberScrollState()).padding(24.dp)) {
        InstrumentBrand()
        SunrisePanel {
            Column(Modifier.padding(24.dp)) {
                Text("ONE VAULT. ONLY YOURS.", fontFamily = InstrumentMono, fontSize = 10.sp, color = androidx.compose.ui.graphics.Color(0xFFB2ACC3))
                Spacer(Modifier.height(24.dp))
                Text("A little peace\nof mind.", fontFamily = InstrumentDisplay, fontSize = 38.sp, lineHeight = 42.sp, color = androidx.compose.ui.graphics.Color(0xFFF3F2EF))
                Spacer(Modifier.height(60.dp))
                Text("Your passwords, cards and keys.\nA place that belongs to you.", color = androidx.compose.ui.graphics.Color(0xFFE6DDF5), fontSize = 13.sp, lineHeight = 20.sp)
            }
        }
        Spacer(Modifier.height(28.dp))
        if (setup) {
            InstrumentHeading("GET STARTED", "Your keys. Your vault.", "Create a master password to protect your local vault.")
            Spacer(Modifier.height(20.dp))
            VelaTextField(password, { password = it }, label = "Master password", isPassword = true, placeholder = "8+ characters")
            Spacer(Modifier.height(18.dp))
            VelaButton("Create password vault", { val entered = password; password = ""; onCreatePasswordVault(entered) }, enabled = password.length >= 8, icon = Icons.Outlined.Lock)
            VelaButton("Back", { password = ""; setup = false }, style = VelaButtonStyle.TextOnly)
        } else {
            VelaButton("Create with biometrics", onCreateBiometricVault, icon = Icons.Outlined.Fingerprint)
            Spacer(Modifier.height(12.dp))
            VelaButton("Create with password", { setup = true }, style = VelaButtonStyle.Surface, icon = Icons.Outlined.Key)
            Spacer(Modifier.height(16.dp))
            VelaButton("Join an existing account", onNavigateToEnroll, style = VelaButtonStyle.TextOnly, icon = Icons.Outlined.Devices)
            VelaButton("Recover my account", onNavigateToRecover, style = VelaButtonStyle.TextOnly, icon = Icons.Outlined.Restore)
        }
        Spacer(Modifier.height(24.dp))
        InstrumentLabel("LOCAL FIRST · OPTIONAL SERVER SYNC")
    }
}
