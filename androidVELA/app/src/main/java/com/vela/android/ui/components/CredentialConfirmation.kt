package com.vela.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.*

/** Presentation only. The caller owns origin validation and approval/verification. */
@Composable
fun CredentialConfirmation(title: String, relyingParty: String, account: String, detail: String,
    error: String? = null, busy: Boolean = false, approveEnabled: Boolean = true,
    showActions: Boolean = true, approveLabel: String = "Continue", onApprove: () -> Unit,
    onCancel: () -> Unit) {
    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).safeDrawingPadding().imePadding().padding(horizontal = 20.dp)) {
        Box(Modifier.padding(top = 10.dp).arrive(0)) { InstrumentBrand(trailingLabel = "Passkey") }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
            LockOrbit(Modifier.arrive(1, 16.dp)) { InstrumentIcon(InstrumentIcons.Fingerprint, 42.dp, VelaColors.Violet) }
            Spacer(Modifier.height(22.dp))
            Column(Modifier.arrive(2), horizontalAlignment = Alignment.CenterHorizontally) {
                InstrumentLabel("VELA / Passkey")
                Spacer(Modifier.height(14.dp))
                Text(title, fontFamily = InstrumentDisplay, fontSize = 28.sp, lineHeight = 31.sp, letterSpacing = (-1.1).sp,
                    fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary, textAlign = TextAlign.Center)
            }
            Spacer(Modifier.height(22.dp))
            Column(Modifier.arrive(3).fillMaxWidth().instrumentPanel(17.dp, Ink.line, Ink.panel).padding(horizontal = 15.dp, vertical = 14.dp)) {
                InstrumentLabel("Requested by", size = 8.sp, color = Ink.faint)
                Text(relyingParty, Modifier.padding(top = 9.dp), fontFamily = InstrumentMono, fontSize = 15.sp, color = VelaColors.TextPrimary)
                if (account.isNotBlank()) Text(account, Modifier.padding(top = 6.dp), fontSize = 12.sp, color = VelaColors.TextMuted)
                InstrumentFine(detail, Modifier.padding(top = 12.dp), size = 10.sp)
            }
            if (error != null) Text(error, Modifier.padding(top = 16.dp), color = Ink.red, fontSize = 12.sp, textAlign = TextAlign.Center)
            if (busy) { Spacer(Modifier.height(20.dp)); CircularProgressIndicator(Modifier.size(26.dp), color = VelaColors.Violet, strokeWidth = 2.dp) }
            Spacer(Modifier.height(20.dp))
        }
        if (showActions) Column(Modifier.padding(bottom = 16.dp).arrive(4), horizontalAlignment = Alignment.CenterHorizontally) {
            InstrumentPill(approveLabel, onApprove, Modifier.fillMaxWidth(), icon = InstrumentIcons.Fingerprint, style = PillStyle.Primary, enabled = approveEnabled)
            Spacer(Modifier.height(6.dp))
            TextAction("Cancel", onCancel)
        }
    }
}
