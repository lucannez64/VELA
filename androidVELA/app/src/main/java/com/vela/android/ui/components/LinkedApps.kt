package com.vela.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.unit.IntSize
import android.graphics.drawable.Drawable
import com.vela.android.autofill.AppAssociations
import com.vela.android.autofill.InstalledApps
import com.vela.android.ui.theme.MonoFont
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The apps a login has been granted to, and the controls to change that.
 *
 * A link is a standing permission — this app may be handed this password, with
 * no further check — so it has to be visible and revocable. Without this screen
 * the only way to withdraw one was to delete the whole item (audit A-2, #124).
 */
@Composable
fun LinkedAppsSection(
    appIds: List<String>,
    onLink: (packageName: String, pinSigningKey: Boolean) -> Boolean,
    onUnlink: (link: String) -> Unit,
) {
    val context = LocalContext.current
    var showPicker by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    VelaCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "Linked apps",
                color = VelaColors.TextSecondary,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
            )
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { showPicker = true }) {
                Icon(Icons.Filled.Add, "Link an app", tint = VelaColors.Green)
            }
        }

        error?.let { message ->
            Text(
                message,
                color = VelaColors.WarningAmber,
                fontSize = 12.sp,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        if (appIds.isEmpty()) {
            Text(
                "No apps can fill this login. Saving it from an app links it, " +
                    "or add one here.",
                color = VelaColors.TextMuted,
                fontSize = 13.sp,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        } else {
            for (link in appIds) {
                val pkg = AppAssociations.packageFromUri(link) ?: continue
                key(link) {
                    LinkedAppRow(
                        entry = remember(pkg) { InstalledApps.describe(context, pkg) },
                        pinned = AppAssociations.certFromUri(link) != null,
                        installed = remember(pkg) { InstalledApps.isInstalled(context, pkg) },
                        onUnlink = { onUnlink(link) },
                    )
                }
            }
        }
    }

    if (showPicker) {
        AppPickerDialog(
            alreadyLinked = appIds.mapNotNull { AppAssociations.packageFromUri(it) }.toSet(),
            onDismiss = { showPicker = false },
            onPick = { pkg, pin ->
                showPicker = false
                // Pinning needs the app's signature, which we cannot read if it
                // is not installed. Say so rather than quietly linking it
                // unpinned — the whole point of the switch is that the user
                // chose which kind of grant this is.
                error = if (onLink(pkg, pin)) {
                    null
                } else {
                    "Couldn't read that app's signing key. Install it first, or " +
                        "turn off \"Verify signing key\" to link by package name."
                }
            },
        )
    }
}

@Composable
private fun LinkedAppRow(
    entry: InstalledApps.Entry,
    pinned: Boolean,
    installed: Boolean,
    onUnlink: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppIcon(entry.icon)
        Spacer(Modifier.size(12.dp))
        Column(Modifier.weight(1f)) {
            Text(entry.label, color = VelaColors.TextPrimary, fontSize = 14.sp)
            Text(
                entry.packageName,
                color = VelaColors.TextMuted,
                fontSize = 11.sp,
                fontFamily = MonoFont,
            )
            if (!installed) {
                Text("Not installed", color = VelaColors.TextMuted, fontSize = 11.sp)
            }
        }
        if (pinned) {
            // Says what the grant is actually tied to. An unpinned link follows
            // the package name wherever it goes; a pinned one does not.
            Icon(
                Icons.Filled.Lock,
                "Signing key verified",
                tint = VelaColors.Green,
                modifier = Modifier.size(16.dp),
            )
        } else {
            StatusBadge(
                text = "name only",
                backgroundColor = VelaColors.WarningAmberBg,
                textColor = VelaColors.WarningAmber,
            )
        }
        IconButton(onClick = onUnlink) {
            Icon(Icons.Filled.Close, "Remove link", tint = VelaColors.TextMuted)
        }
    }
}

@Composable
private fun AppPickerDialog(
    alreadyLinked: Set<String>,
    onDismiss: () -> Unit,
    onPick: (packageName: String, pinSigningKey: Boolean) -> Unit,
) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<InstalledApps.Entry>?>(null) }
    var query by remember { mutableStateOf("") }
    var pinSigningKey by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { InstalledApps.launchable(context) }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = VelaColors.Surface,
        title = { Text("Link an app", color = VelaColors.TextPrimary) },
        text = {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Verify signing key", color = VelaColors.TextPrimary, fontSize = 14.sp)
                        Text(
                            if (pinSigningKey) {
                                "The link stops working if the app is ever signed by someone else."
                            } else {
                                "The link follows the package name, including to a rebuild by " +
                                    "someone else. Use for the same app from a different store."
                            },
                            color = VelaColors.TextMuted,
                            fontSize = 11.sp,
                        )
                    }
                    VelaSwitch(checked = pinSigningKey, onCheckedChange = { pinSigningKey = it })
                }

                Spacer(Modifier.size(12.dp))
                VelaTextField(value = query, onValueChange = { query = it }, label = "Search")
                Spacer(Modifier.size(8.dp))

                val shown = apps.orEmpty().filter {
                    query.isBlank() ||
                        it.label.contains(query, ignoreCase = true) ||
                        it.packageName.contains(query, ignoreCase = true)
                }
                when {
                    apps == null -> Text("Loading…", color = VelaColors.TextMuted, fontSize = 13.sp)
                    shown.isEmpty() -> Text("No apps found", color = VelaColors.TextMuted, fontSize = 13.sp)
                    else -> LazyColumn(
                        modifier = Modifier.heightIn(max = 320.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        items(shown, key = { it.packageName }) { entry ->
                            AppPickerRow(
                                entry = entry,
                                linked = entry.packageName in alreadyLinked,
                                onClick = { onPick(entry.packageName, pinSigningKey) },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done", color = VelaColors.Green) }
        },
    )
}

@Composable
private fun AppPickerRow(
    entry: InstalledApps.Entry,
    linked: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppIcon(entry.icon)
        Spacer(Modifier.size(12.dp))
        Column(Modifier.weight(1f)) {
            Text(entry.label, color = VelaColors.TextPrimary, fontSize = 14.sp)
            Text(
                entry.packageName,
                color = VelaColors.TextMuted,
                fontSize = 11.sp,
                fontFamily = MonoFont,
            )
        }
        if (linked) {
            StatusBadge(text = "linked")
        }
    }
}

/** Draws a [Drawable] app icon, or a neutral placeholder when it cannot be read. */
@Composable
private fun AppIcon(drawable: Drawable?) {
    if (drawable == null) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(VelaColors.SurfaceHigh),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Filled.Smartphone,
                null,
                tint = VelaColors.TextMuted,
                modifier = Modifier.size(18.dp),
            )
        }
        return
    }
    Box(
        modifier = Modifier
            .size(32.dp)
            .drawBehind { drawDrawable(drawable, size.asIntSize()) },
    )
}

private fun DrawScope.drawDrawable(drawable: Drawable, size: IntSize) {
    drawIntoCanvas { canvas ->
        drawable.setBounds(0, 0, size.width, size.height)
        drawable.draw(canvas.nativeCanvas)
    }
}

private fun androidx.compose.ui.geometry.Size.asIntSize() =
    IntSize(width.toInt(), height.toInt())
