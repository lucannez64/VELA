package com.vela.android.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.vela.android.ui.theme.VelaColors

@Composable
fun VelaTopBar(title: String, modifier: Modifier = Modifier, onBack: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {}) {
    Row(modifier.fillMaxWidth().heightIn(min = 64.dp).padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically) {
        if (onBack != null) IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Outlined.ArrowBack, "Back", tint = VelaColors.TextSecondary)
        }
        InstrumentLabel(title, Modifier.weight(1f).padding(horizontal = 8.dp))
        actions()
    }
}
