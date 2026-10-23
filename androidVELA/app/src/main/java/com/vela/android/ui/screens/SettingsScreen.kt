package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.ManageSearch
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.sync.SyncSettings
import com.vela.android.sync.SyncState
import com.vela.android.ui.components.*
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaCardStyle
import com.vela.android.ui.components.VelaListItem
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.components.SegmentedControl
import com.vela.android.ui.components.TrustedBrowsersSection
import com.vela.android.ui.components.VelaSwitch
import com.vela.android.core.VelaRepositories
import com.vela.android.sync.SyncSettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.vela.android.ui.theme.VelaColors
import com.vela.android.ui.theme.VelaThemes

@Composable
fun SettingsScreen(
    serverUrl: String,
    syncSettings: SyncSettings,
    syncState: SyncState,
    userId: String?,
    onOpenDevices: () -> Unit,
    onOpenAuditLog: () -> Unit,
    onOpenBreachMonitor: () -> Unit,
    onOpenRecoverySetup: () -> Unit,
    onUpdateSyncServer: (String, String) -> Unit,
    onUpdateSyncPreferences: (Boolean, Int) -> Unit,
    onSyncNow: () -> Unit,
    onResolveConflictUseLocal: () -> Unit,
    onResolveConflictUseRemote: () -> Unit,
    onOpenAutofillSettings: () -> Unit,
    onOpenPasskeyProviderSettings: () -> Unit,
    onLock: () -> Unit,
    onReset: () -> Unit,
    autoLockMinutes: Int,
    clipboardClearSeconds: Int,
    onUpdateAutoLockMinutes: (Int) -> Unit,
    onUpdateClipboardClearSeconds: (Int) -> Unit,
    themeSetting: String,
    onThemeChange: (String) -> Unit,
    onBack: (() -> Unit)? = null,
    biometricUnlockEnabled: Boolean? = null
) {
    var choice by remember { mutableStateOf<String?>(null) }
    var editUrl by remember(serverUrl) { mutableStateOf(serverUrl) }
    var syncOnStartup by remember(syncSettings.syncOnStartup) { mutableStateOf(syncSettings.syncOnStartup) }
    var backgroundSyncMinutes by remember(syncSettings.backgroundSyncMinutes) { mutableStateOf(syncSettings.backgroundSyncMinutes) }
    val context = LocalContext.current
    val importScope = rememberCoroutineScope()
    var importing by remember { mutableStateOf(false) }
    var importStatus by remember { mutableStateOf<String?>(null) }
    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            importing = true
            importStatus = "Reading the export…"
            importScope.launch {
                val outcome = withContext(Dispatchers.IO) {
                    runCatching {
                        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                            ?: error("Could not read the selected file")
                        VelaRepositories.vault.importVaultBytes(bytes)
                    }
                }
                importing = false
                importStatus = outcome.fold(
                    onSuccess = { it.summary() },
                    onFailure = { "Import failed: ${it.message ?: "unknown error"}" },
                )
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase),
        contentAlignment = Alignment.TopCenter
    ) {
        LazyColumn(
            modifier = Modifier
                .widthIn(max = 720.dp)
                .fillMaxHeight()
                .imePadding(),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 8.dp)
        ) {
        item {
            if (onBack != null) BackHead("THIS DEVICE / SETTINGS", onBack)
            Spacer(Modifier.height(20.dp))
            com.vela.android.ui.components.InstrumentHeading("07 / PREFERENCES", "Make it yours.", "Your preferences, your devices, your keys.")
        }

        item {
            SectionHeader("Appearance")
            Spacer(Modifier.height(14.dp))
            val themes = VelaThemes.ALL + VelaThemes.Meta(VelaThemes.SYSTEM, "System", "Follow device", false,
                listOf(0xFF0B0B10, 0xFFF7F6F2, 0xFFA28AFF))
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                themes.chunked(2).forEach { pair ->
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        pair.forEach { meta -> ThemeTile(meta, themeSetting == meta.id, { onThemeChange(meta.id) }, Modifier.weight(1f)) }
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
        item {
            SectionHeader("Security")
            Spacer(Modifier.height(14.dp))
            InstrumentGroup {
                if (biometricUnlockEnabled != null) {
                    InstrumentControlRow("Unlock with biometrics") {
                        InstrumentTag(if (biometricUnlockEnabled) "Enabled" else "Not configured")
                    }
                    GroupDivider()
                }
                InstrumentMenuRow(null, "Auto-lock", "$autoLockMinutes minutes") { choice = "lock" }
                GroupDivider()
                InstrumentMenuRow(null, "Clear clipboard", "$clipboardClearSeconds seconds") { choice = "clipboard" }
                GroupDivider()
                InstrumentMenuRow(InstrumentIcons.Lock, "Lock vault", onClick = onLock)
            }
            Spacer(Modifier.height(12.dp))
        }
        item {
            SectionHeader("Trusted browsers")
            Spacer(Modifier.height(14.dp))
            VelaCard { TrustedBrowsersSection() }
            Spacer(Modifier.height(24.dp))
        }
        // Account
        item {
            SectionHeader("Account")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                if (userId != null) {
                    val clipboard = LocalClipboardManager.current
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Person, null, tint = VelaColors.TextSecondary, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text("User ID", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = VelaColors.TextPrimary)
                                Text(userId, fontSize = 12.sp, color = VelaColors.TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                        IconButton(onClick = { clipboard.setText(AnnotatedString(userId)) }) {
                            Icon(Icons.Filled.ContentCopy, "Copy user ID", tint = VelaColors.TextSecondary, modifier = Modifier.size(18.dp))
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                }
                VelaListItem(title = "Devices", subtitle = "View and revoke devices with vault access", icon = Icons.Filled.Devices, onClick = onOpenDevices)
                Spacer(Modifier.height(12.dp))
                VelaListItem(title = "Activity Log", subtitle = "Review Android vault activity", icon = Icons.Filled.ManageSearch, onClick = onOpenAuditLog)
                Spacer(Modifier.height(12.dp))
                VelaListItem(title = "Breach Monitor", subtitle = "Check monitored emails and exposed passwords", icon = Icons.Filled.Warning, onClick = onOpenBreachMonitor)
                Spacer(Modifier.height(12.dp))
                VelaListItem(title = "Recovery setup", subtitle = "Restore this vault if every device is lost", icon = Icons.Filled.Key, onClick = onOpenRecoverySetup)
            }
            Spacer(Modifier.height(24.dp))
        }

        // Autofill
        item {
            SectionHeader("Autofill")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                VelaListItem(title = "Enable VELA Autofill", subtitle = "Set VELA as system autofill provider", icon = Icons.Filled.Fingerprint, onClick = onOpenAutofillSettings)
            }
            Spacer(Modifier.height(24.dp))
        }

        // Passkeys
        item {
            SectionHeader("Passkeys")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                VelaListItem(
                    title = "Use VELA for passkeys system-wide",
                    subtitle = "Serve your passkeys to any browser or app (Android 14+)",
                    icon = Icons.Filled.Fingerprint,
                    onClick = onOpenPasskeyProviderSettings,
                )
            }
            Spacer(Modifier.height(24.dp))
        }

        // Server Sync
        item {
            SectionHeader("Server Sync")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                VelaTextField(value = editUrl, onValueChange = { editUrl = it }, label = "Server URL", placeholder = "https://your-server.com")
                val urlProblem = SyncSettingsStore.serverUrlProblem(editUrl)
                if (urlProblem != null) {
                    Text(
                        urlProblem,
                        color = VelaColors.WarningAmber,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
                Spacer(Modifier.height(16.dp))
                Row {
                    VelaButton(text = "Save", onClick = { onUpdateSyncServer(editUrl, "") }, style = VelaButtonStyle.Primary, fullWidth = false, enabled = urlProblem == null, modifier = Modifier.weight(1f))
                    Spacer(Modifier.width(10.dp))
                    VelaButton(
                        text = if (syncState.syncing) "Syncing..." else "Sync Now",
                        onClick = onSyncNow,
                        style = VelaButtonStyle.Surface,
                        fullWidth = false,
                        icon = if (syncState.syncing) Icons.Outlined.Sync else Icons.Filled.Sync,
                        enabled = serverUrl.isNotBlank() && !syncState.syncing,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(16.dp))
                ToggleRow(
                    title = "Sync on startup",
                    subtitle = "Automatically sync when vault is unlocked",
                    on = syncOnStartup,
                    onToggle = {
                        syncOnStartup = !syncOnStartup
                        onUpdateSyncPreferences(syncOnStartup, backgroundSyncMinutes)
                    }
                )

                Spacer(Modifier.height(16.dp))
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text("Background sync", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = VelaColors.TextPrimary)
                    Spacer(Modifier.height(2.dp))
                    Text("Periodically sync while vault is unlocked", fontSize = 12.sp, color = VelaColors.TextMuted)
                    Spacer(Modifier.height(10.dp))
                    SegmentedControl(
                        options = listOf(1 to "1m", 5 to "5m", 15 to "15m", 30 to "30m"),
                        selected = backgroundSyncMinutes,
                        onSelect = {
                            backgroundSyncMinutes = it
                            onUpdateSyncPreferences(syncOnStartup, it)
                        }
                    )
                }

                if (syncState.lastSyncedAt != null) {
                    Spacer(Modifier.height(10.dp))
                    Text("Last synced: ${syncState.lastSyncedAt}", color = VelaColors.TextMuted, fontSize = 12.sp)
                }
                syncState.error?.let {
                    Spacer(Modifier.height(8.dp))
                    VelaCard(style = VelaCardStyle.Error) { Text(it, color = VelaColors.ErrorRed, fontSize = 13.sp) }
                }
                syncState.conflict?.let {
                    Spacer(Modifier.height(8.dp))
                    VelaCard(style = VelaCardStyle.Error) {
                        Text(it, color = VelaColors.ErrorRed, fontSize = 13.sp)
                        if (syncState.canResolveConflict) {
                            Spacer(Modifier.height(12.dp))
                            Row {
                                VelaButton(text = "Keep Android", onClick = onResolveConflictUseLocal, style = VelaButtonStyle.Destructive, fullWidth = false, enabled = !syncState.syncing, modifier = Modifier.weight(1f))
                                Spacer(Modifier.width(10.dp))
                                VelaButton(text = "Use Server", onClick = onResolveConflictUseRemote, style = VelaButtonStyle.Surface, fullWidth = false, enabled = !syncState.syncing, modifier = Modifier.weight(1f))
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }

        item {
            SectionHeader("Import")
            Spacer(Modifier.height(12.dp))
            VelaListItem(
                title = "Import vault",
                subtitle = "Bitwarden, 1Password (.1pif/.1pux), KeePass, browsers or Proton Pass",
                icon = Icons.Filled.FileDownload,
                onClick = {
                    if (!importing) {
                        importPicker.launch(arrayOf(
                            "application/json", "text/csv", "text/plain",
                            "application/zip", "application/octet-stream", "*/*",
                        ))
                    }
                },
            )
            importStatus?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = VelaColors.TextMuted, fontSize = 12.sp, lineHeight = 17.sp)
            }
            Spacer(Modifier.height(24.dp))
        }

        item {
            SectionHeader("Local security")
            Spacer(Modifier.height(12.dp))
            VelaButton("Reset local security", onReset, style = VelaButtonStyle.Destructive)
            Spacer(Modifier.height(24.dp))
        }
        // About
        item {
            SectionHeader("About")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Version", color = VelaColors.TextSecondary, fontSize = 14.sp)
                    Text("0.1.0", fontSize = 14.sp)
                }
                Spacer(Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Min SDK", color = VelaColors.TextSecondary, fontSize = 14.sp)
                    Text("26 (Android 8)", fontSize = 14.sp)
                }
            }
            Spacer(Modifier.height(40.dp))
        }
        }
        val autoLockOptions = listOf(1, 5, 15, 30)
        val clipboardOptions = listOf(5, 15, 30, 60)
        ChoiceSheet(choice != null, if (choice == "lock") "Auto-lock" else "Clear clipboard",
            if (choice == "lock") autoLockOptions.map { "$it minutes" } else clipboardOptions.map { "$it seconds" },
            if (choice == "lock") "$autoLockMinutes minutes" else "$clipboardClearSeconds seconds",
            { choice = null }) { selected ->
                val value = selected.substringBefore(' ').toInt()
                if (choice == "lock") onUpdateAutoLockMinutes(value) else onUpdateClipboardClearSeconds(value)
                choice = null
            }
    }
}

@Composable
private fun ThemeTile(meta: VelaThemes.Meta, selected: Boolean, onSelect: () -> Unit, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(22.dp)
    Column(modifier.heightIn(min = 96.dp).clip(shape).background(Ink.panel)
        .border(if (selected) 2.dp else 1.dp, if (selected) VelaColors.Violet else Ink.line2, shape)
        .instrumentClick(onClick = onSelect).padding(14.dp), verticalArrangement = Arrangement.Center) {
        Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
            val swatches = if (meta.swatches.size >= 4) listOf(meta.swatches[0], meta.swatches[3], meta.swatches[2]) else meta.swatches
            swatches.take(3).forEach { swatch -> Box(Modifier.size(14.dp).clip(RoundedCornerShape(5.dp)).background(Color(swatch))) }
        }
        Spacer(Modifier.height(12.dp))
        Text(meta.label, fontSize = 12.sp, lineHeight = 17.sp, color = VelaColors.TextPrimary)
    }
}

@Composable
private fun ToggleRow(title: String, subtitle: String, on: Boolean, onToggle: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = VelaColors.TextPrimary)
            Spacer(Modifier.height(2.dp))
            Text(subtitle, fontSize = 12.sp, color = VelaColors.TextMuted)
        }
        Spacer(Modifier.width(16.dp))
        InstrumentToggle(on, { onToggle() }, title)
    }
}

@Composable
private fun SectionHeader(title: String) {
    com.vela.android.ui.components.InstrumentLabel(title)
}
