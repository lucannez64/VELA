package com.vela.android.ui.components

import androidx.compose.foundation.layout.RowScope
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.VelaColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VelaTopBar(
    title: String,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {}
) {
    TopAppBar(
        title = {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 18.sp, letterSpacing = 0.5.sp)
        },
        modifier = modifier,
        navigationIcon = {
            if (onBack != null) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                }
            }
        },
        actions = actions,
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = VelaColors.SurfaceBase,
            titleContentColor = VelaColors.TextPrimary,
            navigationIconContentColor = VelaColors.TextSecondary,
            actionIconContentColor = VelaColors.TextSecondary
        )
    )
}
