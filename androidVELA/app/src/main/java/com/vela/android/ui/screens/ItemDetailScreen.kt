package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.VaultItem
import com.vela.android.security.SecureClipboard
import com.vela.android.ui.components.FaviconIcon
import com.vela.android.ui.components.StatusBadge
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaCardStyle
import com.vela.android.ui.components.VelaTopBar
import com.vela.android.ui.theme.MonoFont
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

@Composable
fun ItemDetailScreen(
    item: VaultItem?,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onShare: (() -> Unit)? = null
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showDeleteConfirm by remember { mutableStateOf(false) }

    if (item == null) return

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VelaColors.SurfaceBase)
    ) {
        VelaTopBar(
            title = item.name,
            onBack = onBack,
            actions = {
                if (item.favorite) {
                    Icon(Icons.Filled.Star, "Favorite", tint = VelaColors.WarningAmber)
                }
                if (onShare != null && !item.shared) {
                    IconButton(onClick = onShare) {
                        Icon(Icons.Filled.Share, "Share", tint = VelaColors.TextSecondary)
                    }
                }
                IconButton(onClick = onEdit) {
                    Icon(Icons.Filled.Edit, "Edit", tint = VelaColors.TextSecondary)
                }
            }
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
        ) {
            Spacer(Modifier.height(16.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                val fallbackIcon = when (item) {
                    is VaultItem.Login -> Icons.Filled.Key
                    is VaultItem.CreditCard -> Icons.Filled.CreditCard
                    is VaultItem.SecureNote -> Icons.Filled.Description
                    else -> Icons.Filled.Description
                }
                if (item is VaultItem.Login && item.url.isNotBlank()) {
                    FaviconIcon(
                        url = item.url,
                        fallback = fallbackIcon,
                        size = 64.dp,
                        shape = RoundedCornerShape(16.dp),
                        showBackground = true
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(VelaColors.Green.copy(alpha = 0.1f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(fallbackIcon, null, modifier = Modifier.size(32.dp), tint = VelaColors.Green)
                    }
                }
                Spacer(Modifier.width(16.dp))
                Text(
                    item.name,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = VelaColors.TextPrimary,
                    maxLines = 2,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(Modifier.height(20.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusBadge(text = item.typeLabel)
                Spacer(Modifier.weight(1f))
                Text(item.lastModified, color = VelaColors.TextMuted, fontSize = 12.sp)
            }

            Spacer(Modifier.height(20.dp))

            when (item) {
                is VaultItem.Login -> LoginFields(item, context, scope)
                is VaultItem.CreditCard -> CardFields(item, context, scope)
                is VaultItem.SecureNote -> NoteFields(item)
                else -> {}
            }

            Spacer(Modifier.height(24.dp))

            VelaButton(
                text = if (showDeleteConfirm) "Confirm Delete" else "Delete Item",
                onClick = {
                    if (showDeleteConfirm) onDelete() else { showDeleteConfirm = true }
                },
                style = if (showDeleteConfirm) VelaButtonStyle.Destructive else VelaButtonStyle.Tonal,
                icon = Icons.Filled.Delete
            )

            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun LoginFields(item: VaultItem.Login, context: android.content.Context, scope: CoroutineScope) {
    VelaCard {
        DetailField("Username", item.username, context, scope)
        DetailField("Password", item.password, context, scope, isMono = true, isSensitive = true)
        DetailField("URL", item.url, context, scope)
        TotpField(item.totp, context, scope)
        DetailField("Notes", item.notes.takeIf { it?.isNotBlank() == true }, context, scope)
    }
}

@Composable
private fun CardFields(item: VaultItem.CreditCard, context: android.content.Context, scope: CoroutineScope) {
    VelaCard {
        DetailField("Cardholder", item.cardholderName.ifBlank { null }, context, scope)
        DetailField("Card Number", item.cardNumber.ifBlank { null }, context, scope, isMono = true, isSensitive = true)
        DetailField("Expiration", item.expiration.ifBlank { null }, context, scope)
        DetailField("CVV", item.cvv.ifBlank { null }, context, scope, isMono = true, isSensitive = true)
        DetailField("PIN", item.pin?.takeIf { it.isNotBlank() }, context, scope, isMono = true, isSensitive = true)
    }
}

@Composable
private fun NoteFields(item: VaultItem.SecureNote) {
    VelaCard {
        Text(
            item.content,
            color = VelaColors.TextPrimary,
            fontSize = 15.sp,
            lineHeight = 22.sp
        )
    }
}

@Composable
private fun TotpField(totp: String?, context: android.content.Context, scope: CoroutineScope) {
    if (totp.isNullOrBlank()) return

    var code by remember(totp) { mutableStateOf<String?>(null) }
    var secondsLeft by remember(totp) { mutableStateOf(30) }
    val config = remember(totp) { parseTotpConfig(totp) }

    LaunchedEffect(totp) {
        while (true) {
            val epochSeconds = System.currentTimeMillis() / 1000
            secondsLeft = (config.period - (epochSeconds % config.period)).toInt()
            code = generateTotpCode(config)
            delay(1000)
        }
    }

    val display = code?.chunked(3)?.joinToString(" ") ?: "Invalid TOTP secret"
    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Text(
            "TOTP",
            color = VelaColors.TextMuted,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 2.sp
        )
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(display, color = VelaColors.TextPrimary, fontSize = 24.sp, fontFamily = MonoFont.medium.fontFamily)
                if (code != null) {
                    Text("Refreshes in ${secondsLeft}s", color = VelaColors.TextMuted, fontSize = 12.sp)
                }
            }
            if (code != null) {
                IconButton(onClick = { SecureClipboard.copy(context, scope, "TOTP", code.orEmpty()) }) {
                    Icon(Icons.Filled.ContentCopy, "Copy", modifier = Modifier.size(16.dp), tint = VelaColors.TextMuted)
                }
            }
        }
    }
}

@Composable
private fun DetailField(
    label: String,
    value: String?,
    context: android.content.Context,
    scope: CoroutineScope,
    isMono: Boolean = false,
    isSensitive: Boolean = false
) {
    if (value == null) return

    var revealed by remember { mutableStateOf(!isSensitive) }
    val displayValue = if (revealed) value else "•".repeat(minOf(value.length, 16))

    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Text(
            label.uppercase(),
            color = VelaColors.TextMuted,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = 2.sp
        )
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                displayValue,
                color = VelaColors.TextPrimary,
                fontSize = if (isMono) 15.sp else 14.sp,
                fontFamily = if (isMono) MonoFont.medium.fontFamily else null,
                letterSpacing = if (isMono) 1.sp else 0.sp,
                modifier = Modifier.weight(1f)
            )
            if (isSensitive) {
                IconButton(
                    onClick = { revealed = !revealed },
                    modifier = Modifier.size(width = 52.dp, height = 32.dp)
                ) {
                    Text(
                        if (revealed) "HIDE" else "SHOW",
                        color = VelaColors.TextMuted,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                }
            }
            IconButton(
                onClick = { SecureClipboard.copy(context, scope, label, value) },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    Icons.Filled.ContentCopy, "Copy",
                    modifier = Modifier.size(16.dp),
                    tint = VelaColors.TextMuted
                )
            }
        }
    }
}

private val VaultItem.typeLabel: String
    get() = when (this) {
        is VaultItem.Login -> "login"
        is VaultItem.CreditCard -> "card"
        is VaultItem.SecureNote -> "note"
        is VaultItem.FileBlob -> "file"
        else -> "item"
    }

private val VaultItem.lastModified: String
    get() = DateTimeFormatter.ofPattern("MMM d, yyyy")
        .withZone(ZoneId.systemDefault())
        .format(updatedAt)

private data class TotpConfig(
    val secret: String?,
    val digits: Int = 6,
    val period: Long = 30,
    val algorithm: String = "HmacSHA1"
)

private fun generateTotpCode(config: TotpConfig): String? {
    val secret = config.secret ?: return null
    val key = decodeBase32(secret) ?: return null
    val counter = System.currentTimeMillis() / 1000 / config.period
    val data = ByteArray(8)
    for (i in 7 downTo 0) {
        data[i] = ((counter shr ((7 - i) * 8)) and 0xff).toByte()
    }
    val mac = Mac.getInstance(config.algorithm)
    mac.init(SecretKeySpec(key, config.algorithm))
    val hash = mac.doFinal(data)
    val offset = hash.last().toInt() and 0x0f
    val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
        ((hash[offset + 1].toInt() and 0xff) shl 16) or
        ((hash[offset + 2].toInt() and 0xff) shl 8) or
        (hash[offset + 3].toInt() and 0xff)
    val modulus = 10.0.pow(config.digits).toInt()
    val otp = binary % modulus
    return otp.toString().padStart(config.digits, '0')
}

private fun parseTotpConfig(input: String): TotpConfig {
    val trimmed = input.trim()
    if (!trimmed.startsWith("otpauth://", ignoreCase = true)) return TotpConfig(secret = trimmed)
    return runCatching {
        val query = java.net.URI(trimmed).rawQuery.orEmpty()
        val params = query.split("&")
            .mapNotNull {
                val parts = it.split("=", limit = 2)
                if (parts.size == 2) {
                    parts[0].lowercase() to java.net.URLDecoder.decode(parts[1], "UTF-8")
                } else {
                    null
                }
            }
            .toMap()
        val algMap = mapOf("SHA1" to "HmacSHA1", "SHA256" to "HmacSHA256", "SHA512" to "HmacSHA512")
        TotpConfig(
            secret = params["secret"],
            digits = params["digits"]?.toIntOrNull()?.coerceIn(6, 8) ?: 6,
            period = params["period"]?.toLongOrNull()?.coerceIn(5, 120) ?: 30,
            algorithm = algMap[params["algorithm"]?.uppercase()] ?: "HmacSHA1"
        )
    }.getOrDefault(TotpConfig(secret = null))
}

private fun decodeBase32(value: String): ByteArray? {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    var buffer = 0
    var bitsLeft = 0
    val output = mutableListOf<Byte>()
    value.uppercase().filter { it != '=' && !it.isWhitespace() }.forEach { char ->
        val next = alphabet.indexOf(char)
        if (next < 0) return null
        buffer = (buffer shl 5) or next
        bitsLeft += 5
        if (bitsLeft >= 8) {
            output += ((buffer shr (bitsLeft - 8)) and 0xff).toByte()
            bitsLeft -= 8
        }
    }
    return output.toByteArray()
}
