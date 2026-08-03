package com.vela.android.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.autofill.BrowserAllowlist
import com.vela.android.autofill.InstalledApps
import com.vela.android.autofill.TrustedBrowsers
import com.vela.android.ui.theme.MonoFont
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Which browsers may be believed when they say what site they are showing.
 *
 * Most are already covered by the lists VELA ships, and those are shown as such
 * rather than offered as a choice — asking someone to approve what is already
 * verified teaches them to approve without reading. Only the browsers nothing
 * vouches for get a switch, because for those the device's owner is the only
 * authority left (#125).
 */
@Composable
fun TrustedBrowsersSection() {
    val context = LocalContext.current
    var browsers by remember { mutableStateOf<List<InstalledApps.Entry>?>(null) }
    var trusted by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    val store = remember { TrustedBrowsers(context) }
    val shipped = remember { BrowserAllowlist(context) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        browsers = withContext(Dispatchers.IO) { TrustedBrowsers.installedBrowsers(context) }
        trusted = withContext(Dispatchers.IO) { store.pinned() }
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            "Browsers",
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
            color = VelaColors.TextPrimary,
        )
        Spacer(Modifier.height(2.dp))
        Text(
            "A browser is believed when it says which site it is showing. Any app can "
                + "claim to be on paypal.com, so only browsers VELA can identify are trusted.",
            fontSize = 12.sp,
            color = VelaColors.TextMuted,
        )
        Spacer(Modifier.height(10.dp))

        error?.let {
            Text(it, fontSize = 12.sp, color = VelaColors.WarningAmber)
            Spacer(Modifier.height(8.dp))
        }

        when {
            browsers == null -> Text("Loading…", fontSize = 13.sp, color = VelaColors.TextMuted)
            browsers!!.isEmpty() ->
                Text("No browsers installed", fontSize = 13.sp, color = VelaColors.TextMuted)
            else -> for (entry in browsers!!) {
                key(entry.packageName) {
                    BrowserRow(
                        entry = entry,
                        verified = shipped.isCoveredByShippedList(entry.packageName),
                        trustedByUser = trusted.containsKey(entry.packageName.lowercase()),
                        onToggle = { on ->
                            if (on) {
                                if (store.trust(entry.packageName)) {
                                    error = null
                                } else {
                                    error = "Couldn't read ${entry.label}'s signing key, so it " +
                                        "can't be identified later. Not trusted."
                                }
                            } else {
                                store.revoke(entry.packageName)
                            }
                            trusted = store.pinned()
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun BrowserRow(
    entry: InstalledApps.Entry,
    verified: Boolean,
    trustedByUser: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(entry.label, color = VelaColors.TextPrimary, fontSize = 14.sp)
            Text(
                entry.packageName,
                color = VelaColors.TextMuted,
                fontSize = 11.sp,
                fontFamily = MonoFont.medium.fontFamily,
            )
        }
        if (verified) {
            // Already vouched for by a published list. Offering a switch here
            // would invite someone to turn off a verified browser, or teach them
            // to flip switches they do not need to read.
            Icon(
                Icons.Filled.Lock,
                "Verified by VELA",
                tint = VelaColors.Green,
                modifier = Modifier.size(16.dp),
            )
        } else {
            VelaSwitch(checked = trustedByUser, onCheckedChange = onToggle)
        }
    }
}
