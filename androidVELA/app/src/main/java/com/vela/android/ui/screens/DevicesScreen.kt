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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.VelaRepositories
import com.vela.android.sync.AndroidVelaApiClient
import com.vela.android.sync.DeviceInfo
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaSwitch
import com.vela.android.ui.components.VelaTopBar
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun DevicesScreen(onBack: () -> Unit, onWebAccess: () -> Unit = {}) {
    val scope = rememberCoroutineScope()
    var devices by remember { mutableStateOf<List<DeviceInfo>>(emptyList()) }
    var webSessions by remember { mutableStateOf<List<AndroidVelaApiClient.WebSessionInfo>>(emptyList()) }
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
                    val deviceList = client.getDevices(token).first
                    val sessionList = runCatching { client.listWebSessions(token) }.getOrDefault(emptyList())
                    deviceList to sessionList
                }
            }.onSuccess { (deviceList, sessionList) ->
                withContext(Dispatchers.Main) {
                    devices = deviceList
                    webSessions = sessionList
                }
            }.onFailure { e ->
                withContext(Dispatchers.Main) { error = e.message ?: "Failed to load devices" }
            }
            withContext(Dispatchers.Main) { loading = false }
        }
    }

    // Initial load + auto-refresh every 30 s so sessions approved by another
    // enrolled device become visible without a manual refresh.
    LaunchedEffect(Unit) {
        while (true) {
            load()
            kotlinx.coroutines.delay(30_000L)
        }
    }

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase)) {
        VelaTopBar(
            title = "My Devices",
            onBack = onBack,
            actions = {
                IconButton(onClick = onWebAccess) {
                    Icon(Icons.Filled.Public, "Web access", tint = VelaColors.TextSecondary)
                }
                IconButton(onClick = { load() }, enabled = !loading) {
                    Icon(Icons.Filled.Refresh, "Refresh", tint = VelaColors.TextSecondary)
                }
            }
        )

        Column(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 20.dp)) {
            error?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = VelaColors.ErrorRed, fontSize = 13.sp)
            }
            Spacer(Modifier.height(8.dp))
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
                    Spacer(Modifier.width(8.dp))
                    VelaSwitch(checked = hideRevoked, onCheckedChange = { hideRevoked = it })
                }
            }
            Spacer(Modifier.height(10.dp))

            // weight(1f) is what lets the list actually scroll: without a
            // bounded height the LazyColumn collapsed and device cards never
            // rendered, which is why this screen appeared empty.
            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(displayDevices, key = { it.id }) { device ->
                    VelaCard {
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                if (device.deviceType.contains("android", true) || device.deviceType.contains("mobile", true)) Icons.Filled.PhoneAndroid else Icons.Filled.Computer,
                                null,
                                tint = VelaColors.Green,
                                modifier = Modifier.size(22.dp)
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        device.name,
                                        fontWeight = FontWeight.SemiBold,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        modifier = Modifier.weight(1f, fill = false)
                                    )
                                    if (device.pending) {
                                        Spacer(Modifier.width(6.dp))
                                        StatusBadge("pending")
                                    }
                                    if (device.revoked) {
                                        Spacer(Modifier.width(6.dp))
                                        StatusBadge("revoked")
                                    }
                                }
                                Spacer(Modifier.height(2.dp))
                                Text("Last active: ${device.lastActive ?: "Never"}", color = VelaColors.TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("Enrolled: ${device.createdAt}", color = VelaColors.TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            if (!device.revoked) {
                                Spacer(Modifier.width(12.dp))
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

                // Web Sessions section header
                item {
                    Spacer(Modifier.height(14.dp))
                    Text("Temporary Web Sessions", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(2.dp))
                    Text("Active browser sessions approved from this account", color = VelaColors.TextMuted, fontSize = 13.sp)
                    Spacer(Modifier.height(6.dp))
                }

                if (webSessions.isEmpty()) {
                    item {
                        VelaCard {
                            Text("No active web sessions.", color = VelaColors.TextSecondary)
                        }
                    }
                } else {
                    items(webSessions, key = { "ws_${it.id}" }) { ws ->
                        VelaCard {
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    Icons.Filled.Public, null,
                                    tint = if (ws.mode == "rw") VelaColors.Violet else VelaColors.Green,
                                    modifier = Modifier.size(22.dp)
                                )
                                Spacer(Modifier.width(12.dp))
                                Column(Modifier.weight(1f)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text("Web Browser", fontWeight = FontWeight.SemiBold)
                                        Spacer(Modifier.width(6.dp))
                                        StatusBadge(if (ws.mode == "rw") "RW" else "RO")
                                    }
                                    Spacer(Modifier.height(2.dp))
                                    ws.expiresAt?.let {
                                        Text("Expires: ${it.take(16).replace('T', ' ')}", color = VelaColors.TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    }
                                }
                                VelaButton(
                                    text = "Revoke",
                                    onClick = {
                                        scope.launch(Dispatchers.IO) {
                                            runCatching {
                                                VelaRepositories.sync.withAuthenticatedClient { client, token ->
                                                    client.revokeWebSession(token, ws.id)
                                                }
                                                VelaRepositories.audit.record("web_session_revoked", ws.mode)
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

                item { Spacer(Modifier.height(16.dp)) }
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
