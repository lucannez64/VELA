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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.VelaRepositories
import com.vela.android.sync.DeviceInfo
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun DevicesScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var devices by remember { mutableStateOf<List<DeviceInfo>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var hideRevoked by remember { mutableStateOf(false) }

    val displayDevices = remember(devices, hideRevoked) {
        devices
            .filter { !hideRevoked || !it.revoked }
            .sortedWith(
                compareBy<DeviceInfo> {
                    when {
                        it.pending -> 0
                        it.revoked -> 2
                        else -> 1
                    }
                }.thenByDescending { it.createdAt }
            )
    }

    fun load() {
        loading = true
        error = null
        scope.launch(Dispatchers.IO) {
            runCatching {
                VelaRepositories.sync.withAuthenticatedClient { client, token ->
                    client.getDevices(token).first
                }
            }.onSuccess { result ->
                withContext(Dispatchers.Main) { devices = result }
            }.onFailure { e ->
                withContext(Dispatchers.Main) { error = e.message ?: "Failed to load devices" }
            }
            withContext(Dispatchers.Main) { loading = false }
        }
    }

    LaunchedEffect(Unit) { load() }

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).padding(20.dp)) {
        ScreenHeader("My Devices", onBack, trailing = {
            VelaButton("Refresh", { load() }, style = VelaButtonStyle.Surface, icon = Icons.Filled.Refresh, fullWidth = false, enabled = !loading)
        })
        error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, color = VelaColors.ErrorRed, fontSize = 13.sp)
        }
        Spacer(Modifier.height(16.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "${displayDevices.size} device${if (displayDevices.size != 1) "s" else ""}",
                color = VelaColors.TextMuted,
                fontSize = 13.sp
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Hide revoked", color = VelaColors.TextMuted, fontSize = 13.sp)
                Spacer(Modifier.padding(4.dp))
                Switch(
                    checked = hideRevoked,
                    onCheckedChange = { hideRevoked = it },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = VelaColors.Green,
                        checkedTrackColor = VelaColors.Green.copy(alpha = 0.5f)
                    )
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(displayDevices, key = { it.id }) { device ->
                VelaCard {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (device.deviceType.contains("android", true) || device.deviceType.contains("mobile", true)) Icons.Filled.PhoneAndroid else Icons.Filled.Computer,
                            null,
                            tint = VelaColors.Green
                        )
                        Spacer(Modifier.padding(8.dp))
                        Column(Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(device.name, fontWeight = FontWeight.SemiBold)
                                if (device.pending) {
                                    Spacer(Modifier.padding(4.dp))
                                    StatusBadge("pending")
                                }
                                if (device.revoked) {
                                    Spacer(Modifier.padding(4.dp))
                                    StatusBadge("revoked")
                                }
                            }
                            Text("Last active: ${device.lastActive ?: "Never"}", color = VelaColors.TextMuted, fontSize = 12.sp)
                            Text("Enrolled: ${device.createdAt}", color = VelaColors.TextMuted, fontSize = 12.sp)
                        }
                        if (!device.revoked) {
                            VelaButton(
                                text = "Revoke",
                                onClick = {
                                    scope.launch(Dispatchers.IO) {
                                        runCatching {
                                            VelaRepositories.sync.withAuthenticatedClient { client, token ->
                                                client.revokeDevice(token, device.id)
                                            }
                                            VelaRepositories.audit.record("device_revoked", device.id.take(8))
                                        }
                                        withContext(Dispatchers.Main) { load() }
                                    }
                                },
                                style = VelaButtonStyle.Destructive,
                                fullWidth = false
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun ScreenHeader(title: String, onBack: () -> Unit, trailing: @Composable (() -> Unit)? = null) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Column {
            Text(title, fontSize = 28.sp, fontWeight = FontWeight.Bold)
            Text("Desktop parity", color = VelaColors.TextMuted, fontSize = 12.sp)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            trailing?.invoke()
            VelaButton("Back", onBack, style = VelaButtonStyle.Surface, fullWidth = false)
        }
    }
}
