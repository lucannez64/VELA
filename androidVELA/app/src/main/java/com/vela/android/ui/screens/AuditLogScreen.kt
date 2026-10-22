package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.AuditEntry
import com.vela.android.core.VelaRepositories
import com.vela.android.ui.components.Ink
import com.vela.android.ui.components.InstrumentChip
import com.vela.android.ui.components.InstrumentHeading
import com.vela.android.ui.components.InstrumentIconButton
import com.vela.android.ui.components.InstrumentLabel
import com.vela.android.ui.components.instrumentPanel
import com.vela.android.ui.theme.InstrumentBody
import com.vela.android.ui.theme.InstrumentDisplay
import com.vela.android.ui.theme.InstrumentMono
import com.vela.android.ui.theme.VelaColors
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Locale

private enum class ActivityKind { Security, Items, Sharing, Sync }

private sealed interface ActivityRow {
    data class Day(val label: String) : ActivityRow
    data class Item(val entry: AuditEntry, val kind: ActivityKind) : ActivityRow
}

private fun kindOf(type: String): ActivityKind = when {
    type.startsWith("item_") || type.startsWith("credential_") || type == "password_generated" -> ActivityKind.Items
    type.startsWith("share_") -> ActivityKind.Sharing
    type == "vault_sync" || type.startsWith("sync_") -> ActivityKind.Sync
    else -> ActivityKind.Security
}

private fun labelOf(type: String): String = when (type) {
    "vault_unlocked" -> "Vault unlocked"
    "vault_locked" -> "Vault locked"
    "item_added" -> "Item added"
    "item_updated" -> "Item updated"
    "item_deleted" -> "Item deleted"
    "share_sent" -> "Share sent"
    "share_received" -> "Share received"
    "share_declined" -> "Share declined"
    "share_revoked" -> "Share revoked"
    "vault_sync" -> "Vault synced"
    "device_revoked" -> "Device revoked"
    "web_session_granted" -> "Web access granted"
    "web_session_revoked" -> "Web access revoked"
    "breach_email_checked" -> "Email checked"
    "breach_passwords_checked" -> "Passwords checked"
    "sync_conflict_resolved" -> "Sync conflict resolved"
    else -> type.replace('_', ' ').replaceFirstChar { it.uppercase() }
}

@Composable
private fun kindColor(kind: ActivityKind): Color = when (kind) {
    ActivityKind.Security -> Ink.lime
    ActivityKind.Items -> VelaColors.Violet
    ActivityKind.Sharing -> VelaColors.WarningAmber
    ActivityKind.Sync -> VelaColors.TextMuted
}

/** Activity log in the Instrument language: metrics, 14-day chart, filters, timeline. */
@Composable
fun AuditLogScreen(onBack: () -> Unit, entriesOverride: List<AuditEntry>? = null) {
    val entries = remember(entriesOverride) { (entriesOverride ?: VelaRepositories.audit.list()).sortedByDescending { it.timestamp } }
    var filter by remember { mutableStateOf<ActivityKind?>(null) }
    val zone = remember { ZoneId.systemDefault() }
    val dayFormat = remember { DateTimeFormatter.ofPattern("EEEE, d MMMM yyyy", Locale.getDefault()) }
    val timeFormat = remember { DateTimeFormatter.ofPattern("HH:mm", Locale.getDefault()) }
    val today = LocalDate.now()

    val todayCount = remember(entries, today) {
        entries.count { it.timestamp.atZone(zone).toLocalDate() == today }
    }
    val counts = remember(entries, today) {
        IntArray(14).also { bars ->
            entries.forEach { entry ->
                val age = ChronoUnit.DAYS.between(entry.timestamp.atZone(zone).toLocalDate(), today)
                if (age in 0..13) bars[13 - age.toInt()]++
            }
        }
    }
    val maximum = counts.maxOrNull()?.coerceAtLeast(1) ?: 1

    val rows = remember(entries, filter) {
        val built = mutableListOf<ActivityRow>()
        var day: LocalDate? = null
        entries.filter { filter == null || kindOf(it.actionType) == filter }.forEach { entry ->
            val date = entry.timestamp.atZone(zone).toLocalDate()
            if (date != day) {
                day = date
                built += ActivityRow.Day(date.format(dayFormat))
            }
            built += ActivityRow.Item(entry, kindOf(entry.actionType))
        }
        built
    }

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).padding(horizontal = 20.dp).padding(top = 4.dp)) {
        Row(Modifier.fillMaxWidth().padding(top = 2.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            InstrumentIconButton(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack, size = 38.dp, iconSize = 17.dp)
            Spacer(Modifier.width(10.dp))
            Text("VELA", fontFamily = InstrumentBody, fontWeight = FontWeight.Medium,
                fontSize = 13.sp, letterSpacing = 1.8.sp, color = VelaColors.TextPrimary)
        }
        InstrumentHeading("This device / Activity", "Activity",
            "Every unlock, change and share on this account, newest first.")

        Row(Modifier.fillMaxWidth().padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricTile("Events", entries.size.toString(), Modifier.weight(1f))
            MetricTile("Today", todayCount.toString(), Modifier.weight(1f))
            ChartTile(counts, maximum, Modifier.weight(1.4f))
        }

        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(top = 16.dp, bottom = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(null to "All", ActivityKind.Security to "Security", ActivityKind.Items to "Items",
                ActivityKind.Sharing to "Sharing", ActivityKind.Sync to "Sync").forEach { (kind, label) ->
                InstrumentChip(label, filter == kind, { filter = kind })
            }
        }

        Column(Modifier.fillMaxWidth().weight(1f).instrumentPanel(22.dp, Ink.line, Ink.panel)) {
            if (rows.isEmpty()) {
                Text("No activity in this category.", Modifier.padding(20.dp), color = VelaColors.TextMuted, fontSize = 13.sp)
            } else LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp)) {
                items(rows) { row ->
                    when (row) {
                        is ActivityRow.Day -> Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 8.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            InstrumentLabel(row.label, color = Ink.faint)
                            Spacer(Modifier.width(12.dp))
                            Box(Modifier.weight(1f).height(1.dp).background(Ink.line))
                        }
                        is ActivityRow.Item -> ActivityEntryRow(row.entry, row.kind, timeFormat, zone)
                    }
                }
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun MetricTile(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier.instrumentPanel(18.dp, Ink.line, Ink.panel).padding(14.dp)) {
        InstrumentLabel(label)
        Spacer(Modifier.height(6.dp))
        Text(value, fontFamily = InstrumentDisplay, fontSize = 26.sp, lineHeight = 28.sp,
            fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
    }
}

@Composable
private fun ChartTile(counts: IntArray, maximum: Int, modifier: Modifier = Modifier) {
    Column(modifier.instrumentPanel(18.dp, Ink.line, Ink.panel).padding(14.dp)) {
        InstrumentLabel("14 days")
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth().height(30.dp), verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            counts.forEach { count ->
                Box(
                    Modifier.weight(1f).height((3f + 27f * count / maximum).dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(if (count == 0) VelaColors.Violet.copy(alpha = .12f) else VelaColors.Violet),
                )
            }
        }
    }
}

@Composable
private fun ActivityEntryRow(entry: AuditEntry, kind: ActivityKind, timeFormat: DateTimeFormatter, zone: ZoneId) {
    val risky = entry.actionType in setOf("item_deleted", "device_revoked", "web_session_revoked", "share_revoked")
    val dot = if (risky) Ink.red else kindColor(kind)
    Row(Modifier.fillMaxWidth().padding(vertical = 11.dp), verticalAlignment = Alignment.Top) {
        Text(entry.timestamp.atZone(zone).format(timeFormat), fontFamily = InstrumentMono, fontSize = 10.sp,
            color = VelaColors.TextMuted, modifier = Modifier.width(40.dp).padding(top = 3.dp))
        Box(Modifier.padding(top = 6.dp).size(8.dp).clip(RoundedCornerShape(2.dp)).background(dot))
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)) {
            Text(labelOf(entry.actionType), fontSize = 14.sp, color = VelaColors.TextPrimary)
            entry.detail?.takeIf { it.isNotBlank() }?.let {
                Text(it, fontSize = 12.sp, color = VelaColors.TextMuted, modifier = Modifier.padding(top = 2.dp))
            }
            Text(entry.deviceName, fontSize = 11.sp, color = Ink.faint, modifier = Modifier.padding(top = 3.dp))
        }
    }
    Box(Modifier.fillMaxWidth().height(1.dp).background(Ink.line))
}
