package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.VelaRepositories
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.theme.VelaColors

@Composable
fun AuditLogScreen(onBack: () -> Unit) {
    val entries = remember { VelaRepositories.audit.list().sortedByDescending { it.timestamp } }

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).padding(20.dp)) {
        ScreenHeader("Activity Log", onBack)
        Spacer(Modifier.height(16.dp))
        if (entries.isEmpty()) {
            VelaCard {
                Text("No activity recorded on Android yet.", color = VelaColors.TextSecondary)
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(entries, key = { it.id }) { entry ->
                    VelaCard {
                        Text(entry.actionType.replace('_', ' ').replaceFirstChar { it.uppercase() }, fontWeight = FontWeight.SemiBold)
                        entry.detail?.let { Text(it, color = VelaColors.TextSecondary, fontSize = 13.sp) }
                        Text("${entry.timestamp} · ${entry.deviceName}", color = VelaColors.TextMuted, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}
