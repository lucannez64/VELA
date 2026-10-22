package com.vela.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.ui.theme.VelaColors
import com.vela.android.ui.theme.InstrumentMono

@Composable
fun StatusBadge(
    text: String,
    modifier: Modifier = Modifier,
    backgroundColor: Color = VelaColors.Violet.copy(alpha = 0.08f),
    textColor: Color = VelaColors.Violet
) {
    Text(
        text = text.uppercase(),
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(backgroundColor)
            .padding(horizontal = 8.dp, vertical = 3.dp),
        color = textColor,
        fontSize = 10.sp,
        fontFamily = InstrumentMono,
        fontWeight = FontWeight.Normal,
        letterSpacing = .5.sp
    )
}
