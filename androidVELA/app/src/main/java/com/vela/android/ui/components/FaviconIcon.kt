package com.vela.android.ui.components

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.vela.android.favicon.FaviconFetcher
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun FaviconIcon(
    url: String?,
    fallback: ImageVector,
    size: Dp = 24.dp,
    shape: RoundedCornerShape = RoundedCornerShape(5.dp),
    showBackground: Boolean = false
) {
    var bitmap by remember(url) { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(url) {
        bitmap = null
        if (!url.isNullOrBlank()) {
            bitmap = withContext(Dispatchers.IO) {
                FaviconFetcher.fetchDataUrl(url)?.let { dataUrl ->
                    val base64 = dataUrl.substringAfter("base64,", "")
                    if (base64.isNotEmpty()) {
                        runCatching {
                            val bytes = android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
                            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                        }.getOrNull()
                    } else null
                }
            }
        }
    }

    if (bitmap != null) {
        Image(
            bitmap = bitmap!!.asImageBitmap(),
            contentDescription = null,
            modifier = Modifier
                .size(size)
                .clip(shape)
        )
    } else {
        val iconModifier = if (showBackground) {
            Modifier
                .size(size)
                .clip(shape)
                .background(VelaColors.Green.copy(alpha = 0.1f))
        } else {
            Modifier.size(size)
        }
        Box(modifier = iconModifier, contentAlignment = Alignment.Center) {
            Icon(
                imageVector = fallback,
                contentDescription = null,
                modifier = Modifier.size(size * 0.85f),
                tint = VelaColors.Green
            )
        }
    }
}
