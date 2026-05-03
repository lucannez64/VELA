package com.vela.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    style: VelaButtonStyle = VelaButtonStyle.Primary,
    icon: ImageVector? = null,
    trailingIcon: ImageVector? = null,
    enabled: Boolean = true,
    fullWidth: Boolean = true
) {
    val mod = if (fullWidth) modifier.fillMaxWidth() else modifier

    when (style) {
        VelaButtonStyle.Primary -> {
            Button(
                onClick = onClick,
                modifier = mod.height(52.dp),
                enabled = enabled,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = VelaColors.Green,
                    contentColor = VelaColors.GreenDark,
                    disabledContainerColor = VelaColors.SurfaceHighest,
                    disabledContentColor = VelaColors.TextMuted
                ),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 14.dp)
            ) {
                icon?.let { Icon(it, null, modifier = Modifier.size(20.dp)) }
                Text(text, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                trailingIcon?.let { Icon(it, null, modifier = Modifier.size(20.dp)) }
            }
        }
        VelaButtonStyle.Gradient -> {
            Box(
                modifier = mod
                    .height(56.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(
                        Brush.horizontalGradient(
                            listOf(VelaColors.Green, VelaColors.GreenDim)
                        )
                    )
            ) {
                Button(
                    onClick = onClick,
                    modifier = Modifier.fillMaxSize(),
                    enabled = enabled,
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent,
                        contentColor = VelaColors.GreenDark,
                        disabledContainerColor = VelaColors.SurfaceHighest,
                        disabledContentColor = VelaColors.TextMuted
                    ),
                    contentPadding = PaddingValues(horizontal = 24.dp, vertical = 16.dp)
                ) {
                    icon?.let { Icon(it, null, modifier = Modifier.size(20.dp)) }
                    Text(text, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    trailingIcon?.let { Icon(it, null, modifier = Modifier.size(20.dp)) }
                }
            }
        }
        VelaButtonStyle.Tonal -> {
            Button(
                onClick = onClick,
                modifier = mod.height(48.dp),
                enabled = enabled,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = VelaColors.Green.copy(alpha = 0.12f),
                    contentColor = VelaColors.Green,
                    disabledContainerColor = VelaColors.SurfaceHighest,
                    disabledContentColor = VelaColors.TextMuted
                ),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)
            ) {
                icon?.let { Icon(it, null, modifier = Modifier.size(18.dp)) }
                Text(text, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            }
        }
        VelaButtonStyle.Surface -> {
            Button(
                onClick = onClick,
                modifier = mod.height(48.dp),
                enabled = enabled,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = VelaColors.SurfaceHighest,
                    contentColor = VelaColors.TextPrimary,
                    disabledContainerColor = VelaColors.SurfaceHighest,
                    disabledContentColor = VelaColors.TextMuted
                ),
                border = androidx.compose.foundation.BorderStroke(1.dp, VelaColors.Outline.copy(alpha = 0.3f)),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)
            ) {
                icon?.let { Icon(it, null, modifier = Modifier.size(18.dp)) }
                Text(text, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            }
        }
        VelaButtonStyle.Destructive -> {
            Button(
                onClick = onClick,
                modifier = mod.height(48.dp),
                enabled = enabled,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = VelaColors.ErrorRedBg,
                    contentColor = VelaColors.ErrorRed,
                    disabledContainerColor = VelaColors.SurfaceHighest,
                    disabledContentColor = VelaColors.TextMuted
                ),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)
            ) {
                icon?.let { Icon(it, null, modifier = Modifier.size(18.dp)) }
                Text(text, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            }
        }
        VelaButtonStyle.TextOnly -> {
            androidx.compose.material3.TextButton(
                onClick = onClick,
                modifier = mod,
                enabled = enabled,
                colors = ButtonDefaults.textButtonColors(
                    contentColor = VelaColors.TextSecondary
                )
            ) {
                icon?.let { Icon(it, null, modifier = Modifier.size(18.dp)) }
                Text(text, fontWeight = FontWeight.Medium, fontSize = 14.sp)
            }
        }
    }
}
