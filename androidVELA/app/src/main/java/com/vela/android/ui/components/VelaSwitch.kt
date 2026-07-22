package com.vela.android.ui.components

import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.vela.android.ui.theme.VelaColors

/**
 * Themed M3 [Switch] using the VELA accent, so toggles stay consistent with
 * the active palette (e.g. DevicesScreen's "Hide revoked" uses the same look).
 */
@Composable
fun VelaSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true
) {
    Switch(
        checked = checked,
        onCheckedChange = onCheckedChange,
        modifier = modifier,
        enabled = enabled,
        colors = SwitchDefaults.colors(
            checkedThumbColor = VelaColors.GreenDark,
            checkedTrackColor = VelaColors.Green.copy(alpha = 0.6f),
            uncheckedThumbColor = VelaColors.TextMuted,
            uncheckedTrackColor = VelaColors.SurfaceHighest,
            uncheckedBorderColor = VelaColors.Outline.copy(alpha = 0.4f)
        )
    )
}
