package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Devices
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.sync.SyncSettings
import com.vela.android.sync.SyncState
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaCardStyle
import com.vela.android.ui.components.VelaListItem
import com.vela.android.ui.components.VelaTextField
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
    onLock: () -> Unit,
    onReset: () -> Unit,
    autoLockMinutes: Int,
    onUpdateAutoLockMinutes: (Int) -> Unit,
    themeSetting: String,
    onThemeChange: (String) -> Unit
) {
    var editUrl by remember(serverUrl) { mutableStateOf(serverUrl) }
    var syncOnStartup by remember(syncSettings.syncOnStartup) { mutableStateOf(syncSettings.syncOnStartup) }
    var backgroundSyncMinutes by remember(syncSettings.backgroundSyncMinutes) { mutableStateOf(syncSettings.backgroundSyncMinutes) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 20.dp, vertical = 8.dp)
    ) {
        item {
            Spacer(Modifier.height(16.dp))
            Text("Settings", fontSize = 28.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            Spacer(Modifier.height(4.dp))
            Text("Vault, security and appearance", color = VelaColors.TextMuted, fontSize = 14.sp)
            Spacer(Modifier.height(24.dp))
        }

        // Appearance — placed first because it's the most visible UX control.
        item {
            SectionHeader("Appearance")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                Text(
                    "Theme",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = VelaColors.TextPrimary
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    "Pick a look — VELA, Macchiato, Gruvbox or Latte (light). Use System to follow your device.",
                    fontSize = 12.sp,
                    color = VelaColors.TextMuted
                )
                Spacer(Modifier.height(16.dp))

                ThemeOptionRow(
                    id = VelaThemes.SYSTEM,
                    label = "System",
                    description = "Follow device light/dark",
                    swatches = listOf(0xFF121416, 0xFFEFF1F5, 0xFF73DB9A, 0xFF8B5CF6),
                    selected = themeSetting == VelaThemes.SYSTEM,
                    onSelect = onThemeChange,
                    leadingIcon = Icons.Filled.Smartphone
                )
                Spacer(Modifier.height(10.dp))
                VelaThemes.ALL.forEach { meta ->
                    ThemeOptionRow(
                        id = meta.id,
                        label = meta.label,
                        description = meta.description,
                        swatches = meta.swatches,
                        selected = themeSetting == meta.id,
                        onSelect = onThemeChange
                    )
                    Spacer(Modifier.height(10.dp))
                }
            }
            Spacer(Modifier.height(24.dp))
        }

        // Security
        item {
            SectionHeader("Security")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                VelaListItem(
                    title = "Lock Vault",
                    subtitle = "Clear memory and require re-authentication",
                    icon = Icons.Filled.Lock,
                    onClick = onLock
                )
                Spacer(Modifier.height(12.dp))
                VelaListItem(
                    title = "Reset Local Security",
                    subtitle = "Delete encrypted vault and keystore keys",
                    icon = Icons.Filled.DeleteForever,
                    onClick = onReset
                )
                Spacer(Modifier.height(16.dp))
                SegmentedAutoLock(autoLockMinutes, onUpdateAutoLockMinutes)
            }
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

        // Server Sync
        item {
            SectionHeader("Server Sync")
            Spacer(Modifier.height(12.dp))
            VelaCard {
                VelaTextField(value = editUrl, onValueChange = { editUrl = it }, label = "Server URL", placeholder = "https://your-server.com")
                Spacer(Modifier.height(16.dp))
                Row {
                    VelaButton(text = "Save", onClick = { onUpdateSyncServer(editUrl, "") }, style = VelaButtonStyle.Primary, fullWidth = false, modifier = Modifier.weight(1f))
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
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Background sync", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = VelaColors.TextPrimary)
                        Text("Periodically sync while vault is unlocked", fontSize = 12.sp, color = VelaColors.TextMuted)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        listOf(1, 5, 15, 30).forEach { minutes ->
                            VelaButton(
                                text = "${minutes}m",
                                onClick = {
                                    backgroundSyncMinutes = minutes
                                    onUpdateSyncPreferences(syncOnStartup, backgroundSyncMinutes)
                                },
                                style = if (backgroundSyncMinutes == minutes) VelaButtonStyle.Primary else VelaButtonStyle.Surface,
                                fullWidth = false
                            )
                            if (minutes != 30) Spacer(Modifier.width(6.dp))
                        }
                    }
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
}

@Composable
private fun ThemeOptionRow(
    id: String,
    label: String,
    description: String,
    swatches: List<Long>,
    selected: Boolean,
    onSelect: (String) -> Unit,
    leadingIcon: androidx.compose.ui.graphics.vector.ImageVector? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) VelaColors.Green.copy(alpha = 0.10f) else VelaColors.SurfaceHigh)
            .then(
                if (selected) Modifier.border(1.dp, VelaColors.Green.copy(alpha = 0.5f), RoundedCornerShape(14.dp))
                else Modifier
            )
            .clickable { onSelect(id) }
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        SwatchPill(swatches)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                leadingIcon?.let {
                    Icon(it, null, modifier = Modifier.size(15.dp), tint = VelaColors.TextSecondary)
                    Spacer(Modifier.width(6.dp))
                }
                Text(label, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = VelaColors.TextPrimary)
            }
            Text(description, fontSize = 11.sp, color = VelaColors.TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (selected) {
            Icon(Icons.Filled.Check, "Selected", modifier = Modifier.size(18.dp), tint = VelaColors.Green)
        }
    }
}

@Composable
private fun SwatchPill(swatches: List<Long>) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(VelaColors.SurfaceDarkest)
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp)
    ) {
        swatches.take(4).forEach { argb ->
            Box(
                modifier = Modifier
                    .size(14.dp)
                    .clip(CircleShape)
                    .background(Color(argb))
            )
        }
    }
}

@Composable
private fun SegmentedAutoLock(autoLockMinutes: Int, onUpdateAutoLockMinutes: (Int) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text("Auto-lock", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = VelaColors.TextPrimary)
            Text("Lock the vault after this long backgrounded", fontSize = 12.sp, color = VelaColors.TextMuted)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            listOf(1, 5, 15, 30).forEach { minutes ->
                VelaButton(
                    text = "${minutes}m",
                    onClick = { onUpdateAutoLockMinutes(minutes) },
                    style = if (autoLockMinutes == minutes) VelaButtonStyle.Primary else VelaButtonStyle.Surface,
                    fullWidth = false
                )
                if (minutes != 30) Spacer(Modifier.width(6.dp))
            }
        }
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
            Text(subtitle, fontSize = 12.sp, color = VelaColors.TextMuted)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (on) "On" else "Off", fontSize = 13.sp, color = if (on) VelaColors.Green else VelaColors.TextMuted)
            Spacer(Modifier.width(8.dp))
            VelaButton(
                text = if (on) "Disable" else "Enable",
                onClick = onToggle,
                style = if (on) VelaButtonStyle.Surface else VelaButtonStyle.Primary,
                fullWidth = false
            )
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            title.uppercase(),
            color = VelaColors.TextMuted,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 2.5.sp
        )
    }
}
