package com.vela.android.ui.screens

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.*
import org.json.JSONObject
import com.vela.android.core.VaultItem
import com.vela.android.core.VelaRepositories
import com.vela.android.security.SecureClipboard
import com.vela.android.ui.components.*
import com.vela.android.ui.theme.InstrumentDisplay
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.delay
import java.time.Duration
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

/**
 * Item details, laid out like the Instrument reference: centred back header,
 * large glyph with a favourite toggle, one bordered card per field (each with
 * its own copy action), a dot-matrix authenticator with a countdown ring, and
 * Edit / Share actions. Deleting is a deliberate two-step action at the end.
 *
 * `linkedApps` is a slot so the production screen can show Android app links
 * while previews and design review pass nothing.
 */
@Composable
fun ItemDetailScreen(
    item: VaultItem?,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onShare: (() -> Unit)? = null,
    onToggleFavorite: ((VaultItem) -> Unit)? = null,
    linkedApps: (@Composable (VaultItem.Login) -> Unit)? = { login ->
        LinkedAppsSection(
            appIds = login.appIds,
            onLink = { pkg, pin -> VelaRepositories.vault.linkApp(login.id, pkg, pin) },
            onUnlink = { link -> VelaRepositories.vault.unlinkApp(login.id, link) },
        )
    },
    organization: VaultOrganization = VelaRepositories.vault.organization.value,
) {
    if (item == null) return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val toast = LocalInstrumentToast.current
    var revealed by remember(item.id) { mutableStateOf(false) }
    var confirmDelete by remember(item.id) { mutableStateOf(false) }
    var revealedRich by remember(item.id) { mutableStateOf(setOf<String>()) }
    var showApps by remember(item.id) { mutableStateOf(false) }
    var favorite by remember(item.id, item.favorite) { mutableStateOf(item.favorite) }
    fun copy(label: String, value: String) {
        SecureClipboard.copy(context, scope, label, value)
        toast.show("$label copied. Clears in ${SecureClipboard.clearDelaySeconds} seconds.")
    }
    var step = 0
    fun next() = step++

    Box(Modifier.fillMaxSize().background(VelaColors.SurfaceBase)) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp).padding(top = 10.dp, bottom = 24.dp)
    ) {
        Box(Modifier.arrive(next())) { BackHead("VAULT / ${item.kindLabel.uppercase()}", onBack) }

        // Heading: glyph, favourite, name, site · updated.
        Column(Modifier.padding(top = 12.dp, bottom = 22.dp).arrive(next())) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                InstrumentAvatar(item.glyph, large = true)
                Spacer(Modifier.weight(1f))
                InstrumentIconButton(InstrumentIcons.Trash, "Delete item", { confirmDelete = true }, tint = VelaColors.TextMuted)
                Spacer(Modifier.width(8.dp))
                if (onToggleFavorite != null) {
                    val pop by animateFloatAsState(if (favorite) 1f else 0f,
                        spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessMediumLow), label = "fav")
                    Box(Modifier.graphicsLayer { val s = 1f + .18f * pop * (1f - pop) * 4f; scaleX = s; scaleY = s }) {
                        InstrumentIconButton(InstrumentIcons.Star,
                            if (favorite) "Remove from favourites" else "Add to favourites",
                            { favorite = !favorite; onToggleFavorite(item) },
                            tint = if (favorite) Ink.lime else VelaColors.TextPrimary)
                    }
                }
            }
            Text(item.name, Modifier.padding(top = 16.dp), fontFamily = InstrumentDisplay, fontSize = 27.sp, lineHeight = 30.sp,
                letterSpacing = (-1.2).sp, fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(7.dp))
            InstrumentFine("${item.siteOrKind} · Updated ${relativeAge(item.updatedAt)}")
        }

        if (item is VaultItem.Login && linkedApps != null) {
            InstrumentPill("Autofill in apps", { showApps = true }, Modifier.fillMaxWidth().padding(bottom = 16.dp), icon = InstrumentIcons.Device)
        }
        Column(Modifier.arrive(next())) {
            when (item) {
                is VaultItem.Login -> {
                    if (item.username.isNotBlank()) InstrumentField("Username", item.username, { copy("Username", item.username) })
                    if (item.password.isNotBlank()) InstrumentField("Password", item.password, { copy("Password", item.password) },
                        secret = true, revealed = revealed, onReveal = { revealed = !revealed })
                    if (!item.totp.isNullOrBlank()) LiveTotp(item.totp) { code -> copy("Authenticator code", code) }
                    if (item.url.isNotBlank()) InstrumentField("Website", item.url.displayHost(), { copy("Website", item.url) })
                }
                is VaultItem.Identity -> {
                    InstrumentField("First name",item.firstName,{copy("First name",item.firstName)})
                    InstrumentField("Last name",item.lastName,{copy("Last name",item.lastName)})
                    if(item.ssn.isNotBlank()) InstrumentField("Identity number",item.ssn,{copy("Identity number",item.ssn)},secret=true,revealed=revealed,onReveal={revealed=!revealed})
                }
                is VaultItem.CreditCard -> {
                    val digits = item.cardNumber.filter(Char::isDigit)
                    val grouped = digits.chunked(4).joinToString(" ")
                    val masked = "•••• •••• •••• ${digits.takeLast(4)}"
                    CardArt("${item.name} / ${cardBrand(digits)}", if (revealed) grouped else masked,
                        item.cardholderName.ifBlank { "Cardholder" }, item.expiration.replace("/", " / "))
                    if (digits.isNotBlank()) InstrumentField("Card number", grouped, { copy("Card number", digits) },
                        secret = true, revealed = revealed, onReveal = { revealed = !revealed })
                    if (item.cardholderName.isNotBlank()) InstrumentField("Cardholder", item.cardholderName, { copy("Cardholder", item.cardholderName) })
                    if (item.expiration.isNotBlank()) InstrumentField("Expires", item.expiration, { copy("Expiry", item.expiration) }, mono = true)
                    if (item.cvv.isNotBlank()) InstrumentField("Security code", item.cvv, { copy("Security code", item.cvv) },
                        secret = true, revealed = revealed, onReveal = { revealed = !revealed })
                    item.pin?.takeIf { it.isNotBlank() }?.let { pin ->
                        InstrumentField("PIN", pin, { copy("PIN", pin) }, secret = true, revealed = revealed, onReveal = { revealed = !revealed })
                    }
                }
                is VaultItem.SecureNote -> InstrumentField("Note", item.content, { copy("Note", item.content) })
                is VaultItem.Passkey -> {
                    if (item.rpId.isNotBlank()) InstrumentField("Website", item.rpId, { copy("Website", item.rpId) })
                    if (item.userName.isNotBlank()) InstrumentField("Account", item.userName, { copy("Account", item.userName) })
                    Column(Modifier.fillMaxWidth().padding(bottom = 9.dp).instrumentPanel(17.dp, Ink.line, Ink.panel)
                        .padding(horizontal = 15.dp, vertical = 14.dp)) {
                        Row { InstrumentTag("Passkey", TagKind.Ok) }
                        Spacer(Modifier.height(10.dp))
                        InstrumentFine(
                            if (item.privateKey.isEmpty()) "This passkey's key stays on the device that created it."
                            else "Sign in with a fingerprint or your device unlock.")
                    }
                }
                else -> {}
            }
            val rich = item.rich
            if(organization.enabled) {
                InstrumentField("Folder",organization.folderPath(rich.folderId).ifEmpty{"Unfiled"})
                val tags=rich.tagIds.map(organization::tagName).filter(String::isNotEmpty)
                if(tags.isNotEmpty()) InstrumentField("Tags",tags.joinToString(" · "))
            }
            rich.customFields.forEach { raw ->
                val field=JSONObject(raw);val id=field.getString("id"); val kind=field.getString("type")
                val label=field.stringOrEmpty("label")
                if(kind !in listOf("text","concealed","boolean")) InstrumentFine("$label · Unsupported field, preserved read-only")
                else {
                    val value=if(kind=="boolean")if(field.optBoolean("value"))"On" else "Off" else field.stringOrEmpty("value")
                    InstrumentField(label,value,{copy(label,value)},secret=kind=="concealed",revealed=id in revealedRich,
                        onReveal={revealedRich=if(id in revealedRich)revealedRich-id else revealedRich+id})
                }
            }
            rich.additionalUrls.forEach {val url=JSONObject(it)
                InstrumentField("Additional website · ${url.stringOrEmpty("match")}",url.stringOrEmpty("url"),{copy("Additional website",url.stringOrEmpty("url"))})
            }
            if(item is VaultItem.Identity) {
                val details=rich.identity
                listOf("middleName" to "Middle name","preferredName" to "Preferred name","email" to "Email","phone" to "Phone","company" to "Company","jobTitle" to "Job title").forEach {(key,label)->
                    val value=details.stringOrEmpty(key);if(value.isNotBlank())InstrumentField(label,value,{copy(label,value)})
                }
                details.optJSONArray("addresses").records().forEach {raw ->
                    val address=JSONObject(raw);val label=address.stringOrEmpty("label").ifBlank{"Address"}
                    val value=listOf("line1","line2","city","region","postalCode","countryCode").map(address::stringOrEmpty).filter(String::isNotBlank).joinToString("\n")
                    InstrumentField(label,value,{copy(label,value)})
                }
            }
            item.notes?.takeIf { it.isNotBlank() && item !is VaultItem.SecureNote }?.let { notes ->
                InstrumentField("Notes", notes, { copy("Notes", notes) })
            }
        }

        Row(Modifier.fillMaxWidth().padding(vertical = 20.dp).arrive(next()), horizontalArrangement = Arrangement.spacedBy(9.dp)) {
            InstrumentPill("Edit item", onEdit, Modifier.weight(1f), icon = InstrumentIcons.Pen)
            if (onShare != null && !item.shared)
                InstrumentPill("Share item", onShare, Modifier.weight(1f), icon = InstrumentIcons.Share, style = PillStyle.Primary)
        }
        VelaButton("Delete item", { confirmDelete = true }, style = VelaButtonStyle.Destructive, icon = InstrumentIcons.Trash)
        Spacer(Modifier.height(10.dp))
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            InstrumentLabel("Encrypted · Only you hold the keys", size = 8.sp)
        }
    }
    InstrumentSheet(confirmDelete, "Delete ${item.name}?", { confirmDelete = false }) {
        InstrumentFine("This permanently removes the item from your vault.")
        Spacer(Modifier.height(20.dp))
        VelaButton("Delete item permanently", { confirmDelete = false; onDelete() }, style = VelaButtonStyle.Destructive, icon = InstrumentIcons.Trash)
        Spacer(Modifier.height(10.dp))
        InstrumentPill("Keep item", { confirmDelete = false }, Modifier.fillMaxWidth())
    }
    if (showApps && item is VaultItem.Login && linkedApps != null) {
        InstrumentSheet(true, "Autofill in apps", { showApps = false }) { linkedApps(item) }
    }
    }
}

/** Live code that recomputes every second; the ring glides between ticks. */
@Composable
private fun LiveTotp(secret: String, onCopy: (String) -> Unit) {
    val config = remember(secret) { parseTotpConfig(secret) }
    var code by remember(secret) { mutableStateOf<String?>(null) }
    var secondsLeft by remember(secret) { mutableIntStateOf(config.period.toInt()) }
    LaunchedEffect(secret) {
        while (true) {
            val now = System.currentTimeMillis()
            secondsLeft = (config.period - (now / 1000 % config.period)).toInt()
            code = generateTotpCode(config)
            delay(1000 - now % 1000)
        }
    }
    TotpField(code, secondsLeft, config.period.toInt()) { code?.let(onCopy) }
}

internal val VaultItem.glyph: ImageVector
    get() = when (this) {
        is VaultItem.Identity -> InstrumentIcons.User
    is VaultItem.Login -> InstrumentIcons.Key
        is VaultItem.CreditCard -> InstrumentIcons.Card
        is VaultItem.Passkey -> InstrumentIcons.Fingerprint
        else -> InstrumentIcons.Note
    }

internal val VaultItem.kindLabel: String
    get() = when (this) {
        is VaultItem.Login -> "Login"; is VaultItem.CreditCard -> "Card"; is VaultItem.SecureNote -> "Note"
        is VaultItem.Identity -> "Identity"; is VaultItem.Passkey -> "Passkey"; is VaultItem.FileBlob -> "File"; is VaultItem.BreachMonitor -> "Breach"
    }

private val VaultItem.siteOrKind: String
    get() = when (this) {
        is VaultItem.Login -> url.displayHost().ifBlank { kindLabel }
        is VaultItem.Passkey -> rpId.ifBlank { kindLabel }
        else -> kindLabel
    }

internal fun String.displayHost(): String =
    removePrefix("https://").removePrefix("http://").removePrefix("www.").substringBefore('/')

private fun cardBrand(digits: String): String = when {
    digits.startsWith("4") -> "Visa"
    digits.matches(Regex("^(5[1-5]|2[2-7]).*")) -> "Mastercard"
    digits.matches(Regex("^3[47].*")) -> "Amex"
    else -> "Card"
}

internal fun relativeAge(at: Instant): String {
    val days = Duration.between(at, Instant.now()).toDays()
    return when {
        days < 1 -> "today"
        days == 1L -> "yesterday"
        days < 30 -> "$days days ago"
        days < 365 -> "${days / 30} month${if (days / 30 == 1L) "" else "s"} ago"
        else -> "${days / 365} year${if (days / 365 == 1L) "" else "s"} ago"
    }
}

internal data class TotpConfig(
    val secret: String?,
    val digits: Int = 6,
    val period: Long = 30,
    val algorithm: String = "HmacSHA1"
)

internal fun generateTotpCode(config: TotpConfig): String? {
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

internal fun parseTotpConfig(input: String): TotpConfig {
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
