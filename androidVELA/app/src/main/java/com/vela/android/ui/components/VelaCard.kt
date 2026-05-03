package com.vela.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.VelaColors

sealed class VelaCardStyle {
    data object Default : VelaCardStyle()
    data object Interactive : VelaCardStyle()
    data object Elevated : VelaCardStyle()
    data object Warning : VelaCardStyle()
    data object Success : VelaCardStyle()
    data object Error : VelaCardStyle()
}

@Composable
fun VelaCard(
    modifier: Modifier = Modifier,
    style: VelaCardStyle = VelaCardStyle.Default,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val bg = when (style) {
        VelaCardStyle.Default -> VelaColors.SurfaceLow
        VelaCardStyle.Interactive -> VelaColors.SurfaceLow
        VelaCardStyle.Elevated -> VelaColors.Surface
        VelaCardStyle.Warning -> VelaColors.WarningAmberBg
        VelaCardStyle.Success -> VelaColors.SuccessGreenBg
        VelaCardStyle.Error -> VelaColors.ErrorRedBg
    }
    val border = when (style) {
        VelaCardStyle.Warning -> androidx.compose.foundation.BorderStroke(1.dp, VelaColors.WarningAmber.copy(alpha = 0.3f))
        VelaCardStyle.Success -> androidx.compose.foundation.BorderStroke(1.dp, VelaColors.Green.copy(alpha = 0.3f))
        VelaCardStyle.Error -> androidx.compose.foundation.BorderStroke(1.dp, VelaColors.ErrorRed.copy(alpha = 0.3f))
        else -> null
    }
    val shape = RoundedCornerShape(16.dp)

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(bg, shape)
            .then(
                if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier
            )
            .then(
                if (border != null) Modifier.border(border, shape) else Modifier
            )
            .padding(20.dp),
        content = content
    )
}

@Composable
fun VelaListItem(
    title: String,
    subtitle: String? = null,
    icon: ImageVector? = null,
    trailing: String? = null,
    onClick: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(VelaColors.SurfaceLow)
            .clickable(onClick = onClick)
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        icon?.let {
            Icon(
                it, null,
                modifier = Modifier.size(22.dp),
                tint = VelaColors.Green
            )
            Spacer(Modifier.width(14.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
            subtitle?.let {
                Spacer(Modifier.height(2.dp))
                Text(it, color = VelaColors.TextSecondary, fontSize = 13.sp)
            }
        }
        trailing?.let {
            Spacer(Modifier.width(12.dp))
            Text(it, color = VelaColors.TextMuted, fontSize = 13.sp)
        }
        Spacer(Modifier.width(8.dp))
        Icon(
            Icons.Filled.ChevronRight, null,
            modifier = Modifier.size(18.dp),
            tint = VelaColors.TextMuted
        )
    }
}
