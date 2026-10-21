package com.vela.android.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.InstrumentBody
import com.vela.android.ui.theme.VelaColors

sealed class VelaButtonStyle {
    data object Primary : VelaButtonStyle()
    data object Gradient : VelaButtonStyle()
    data object Tonal : VelaButtonStyle()
    data object Surface : VelaButtonStyle()
    data object Destructive : VelaButtonStyle()
    data object TextOnly : VelaButtonStyle()
}

@Composable
fun VelaButton(
    text: String, onClick: () -> Unit, modifier: Modifier = Modifier,
    style: VelaButtonStyle = VelaButtonStyle.Primary, icon: ImageVector? = null,
    trailingIcon: ImageVector? = null, enabled: Boolean = true, fullWidth: Boolean = true
) {
    val p = VelaColors
    val primary = style == VelaButtonStyle.Primary || style == VelaButtonStyle.Gradient
    val destructive = style == VelaButtonStyle.Destructive
    val textOnly = style == VelaButtonStyle.TextOnly
    val container = when { primary -> p.TextPrimary; destructive -> p.ErrorRedBg; textOnly -> Color.Transparent; else -> p.SurfaceLow }
    val content = when { primary -> p.SurfaceBase; destructive -> p.ErrorRed; style == VelaButtonStyle.Tonal -> p.Violet; else -> p.TextPrimary }
    Button(
        onClick = onClick,
        modifier = (if (fullWidth) modifier.fillMaxWidth() else modifier).heightIn(min = 48.dp),
        enabled = enabled, shape = RoundedCornerShape(50),
        border = if (primary || textOnly) null else BorderStroke(1.dp, p.Outline.copy(alpha = .4f)),
        colors = ButtonDefaults.buttonColors(containerColor = container, contentColor = content,
            disabledContainerColor = p.SurfaceHigh, disabledContentColor = p.TextMuted),
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 13.dp)
    ) {
        if (icon != null) { Icon(icon, null, Modifier.size(18.dp)); Spacer(Modifier.width(8.dp)) }
        Text(text, fontFamily = InstrumentBody, fontWeight = FontWeight.Medium, fontSize = 13.sp)
        if (trailingIcon != null) { Spacer(Modifier.width(8.dp)); Icon(trailingIcon, null, Modifier.size(18.dp)) }
    }
}
