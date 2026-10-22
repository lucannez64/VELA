package com.vela.android.ui.screens

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.VaultItem
import com.vela.android.core.accountsNeedingAttention
import com.vela.android.security.SecureClipboard
import com.vela.android.sync.SyncState
import com.vela.android.ui.components.*
import com.vela.android.ui.theme.*
import kotlinx.coroutines.launch
import java.security.SecureRandom

private fun greeting(): String = when (java.time.LocalTime.now().hour) {
    in 5..11 -> "Good morning."
    in 12..17 -> "Good afternoon."
    else -> "Good evening."
}

internal fun VaultItem.rowSubtitle(): String = when (this) {
    is VaultItem.Login -> username.ifBlank { url.displayHost() }
    is VaultItem.Identity -> listOf(firstName,lastName).filter(String::isNotBlank).joinToString(" ")
    is VaultItem.CreditCard -> listOf("•••• ${cardNumber.filter(Char::isDigit).takeLast(4)}", expiration).filter(String::isNotBlank).joinToString(" · ")
    is VaultItem.Passkey -> userName.ifBlank { rpId }
    is VaultItem.SecureNote -> "Private note"
    else -> kindLabel
}

/** The vault's standard row, shared by Overview and Vault. */
@Composable
fun VaultItemRow(item: VaultItem, needsReview: Boolean = false, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val favicon = (item as? VaultItem.Login)?.url?.takeIf { it.isNotBlank() }
    InstrumentItemRow(item.glyph, item.name, item.rowSubtitle(), onClick, modifier,
        needsReview = needsReview, favorite = item.favorite, faviconUrl = favicon)
}

@Composable
fun OverviewScreen(items: List<VaultItem>, syncState: SyncState, onItem: (VaultItem) -> Unit,
    onVault: () -> Unit, onFavorites: () -> Unit, onGenerate: () -> Unit, onLock: () -> Unit,
    onAttention: () -> Unit = onVault, recentIds: List<String> = emptyList()) {
    val greet = remember { greeting() }
    val attentionIds = remember(items) { items.accountsNeedingAttention() }
    val recent = remember(items, recentIds) {
        val byId = items.associateBy { it.id }
        (recentIds.mapNotNull(byId::get) + items.sortedByDescending { it.updatedAt }).distinctBy { it.id }.take(3)
    }
    LazyColumn(Modifier.fillMaxSize().background(VelaColors.SurfaceBase),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 10.dp, bottom = 20.dp)) {
        item { Box(Modifier.arrive(0)) { InstrumentBrand(onLock, syncState) } }
        item { InstrumentHeading("Your private space", greet, modifier = Modifier.arrive(1)) }
        item {
            SunrisePanel(Modifier.heightIn(min = 207.dp).arrive(2, 14.dp)) {
                Column(Modifier.padding(22.dp)) {
                    InstrumentLabel("One vault. Only yours.", color = Color(0xFFB2ACC3))
                    Spacer(Modifier.height(10.dp))
                    Text("A little peace\nof mind.", fontFamily = InstrumentDisplay, fontSize = 29.sp, lineHeight = 33.sp,
                        letterSpacing = (-.9).sp, fontWeight = FontWeight.Medium, color = Color(0xFFF3F2EF))
                    Spacer(Modifier.height(26.dp))
                    Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                        DotMatrix(items.size.toString().padStart(2, '0'), color = Color(0xFFE9DCFF), pitch = 5.5.dp)
                        InstrumentFine("Items in your vault\nEncrypted on this device.", size = 10.sp, color = Color(0xC7E6DDF5),
                            align = androidx.compose.ui.text.style.TextAlign.End)
                    }
                }
            }
        }
        item {
            Row(Modifier.padding(top = 12.dp).height(IntrinsicSize.Min).arrive(3), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                InstrumentTile(InstrumentIcons.Star, items.count { it.favorite }.toString(), "Favourites", onFavorites, Modifier.weight(1f).fillMaxHeight())
                InstrumentTile(InstrumentIcons.Dice, "Generate", "Something hard to guess.", onGenerate, Modifier.weight(1f).fillMaxHeight())
            }
        }
        if (attentionIds.isNotEmpty()) item {
            val n = attentionIds.size
            Row(
                Modifier.padding(top = 16.dp).arrive(4).fillMaxWidth()
                    .instrumentPanel(18.dp, Ink.red.copy(alpha = .24f), Ink.red.copy(alpha = .04f).compositeOver(Ink.panel))
                    .instrumentClick(onClick = onAttention).padding(15.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                InstrumentIcon(InstrumentIcons.Shield, 20.dp, Ink.red)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(if (n == 1) "1 account needs attention" else "$n accounts need attention",
                        fontSize = 14.sp, fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
                    Spacer(Modifier.height(3.dp))
                    InstrumentFine("A small check makes a difference.", size = 10.sp)
                }
                InstrumentIcon(InstrumentIcons.Chev, 16.dp, VelaColors.TextMuted)
            }
        }
        item { SectionHead("01 / Recently opened", Modifier.arrive(5)) { TextAction("View all ↗", onVault) } }
        if (items.isEmpty()) item {
            Column(Modifier.fillMaxWidth().padding(vertical = 32.dp).arrive(6), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("A place for your essentials.", fontFamily = InstrumentDisplay, fontSize = 18.sp, color = VelaColors.TextPrimary)
                Spacer(Modifier.height(12.dp))
                InstrumentFine("Add a login, card or private note from your vault.")
                Spacer(Modifier.height(16.dp))
                InstrumentPill("Open vault", onVault, icon = InstrumentIcons.Vault)
            }
        }
        itemsIndexed(recent, key = { _, it -> it.id }) { i, item ->
            VaultItemRow(item, item.id in attentionIds, Modifier.arrive(6 + i)) { onItem(item) }
        }
    }
}

private fun Color.compositeOver(background: Color): Color {
    val a = alpha
    return Color(red * a + background.red * (1 - a), green * a + background.green * (1 - a), blue * a + background.blue * (1 - a), 1f)
}

@Composable
fun MoreScreen(userId: String?, onNavigate: (String) -> Unit, onLock: () -> Unit, syncState: SyncState? = null,
    favorites: Int? = null, attention: Int? = null) {
    LazyColumn(Modifier.fillMaxSize().background(VelaColors.SurfaceBase), contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 10.dp, bottom = 20.dp)) {
        item { Box(Modifier.arrive(0)) { InstrumentBrand(onLock, syncState) } }
        item {
            Row(
                Modifier.padding(top = 3.dp, bottom = 25.dp).arrive(1).fillMaxWidth().instrumentPanel(22.dp, Ink.line, Ink.panel)
                    .instrumentClick { onNavigate("settings") }.padding(17.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                InstrumentAvatar(InstrumentIcons.User, large = true)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("Your private vault", fontFamily = InstrumentDisplay, fontSize = 18.sp, fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
                    Spacer(Modifier.height(4.dp))
                    Text(userId ?: "Local account · This device", fontSize = 10.sp, color = VelaColors.TextMuted, maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                    Spacer(Modifier.height(4.dp))
                    InstrumentLabel("This phone · Personal vault", size = 8.sp, color = Ink.faint)
                }
                InstrumentIcon(InstrumentIcons.Chev, 15.dp, VelaColors.TextMuted)
            }
        }
        item { Box(Modifier.arrive(2)) { GroupLabel("01 / Vault") } }
        item { InstrumentGroup(Modifier.arrive(2)) {
            InstrumentMenuRow(InstrumentIcons.Star, "Favourites", favorites?.toString()) { onNavigate("favorites") }
            GroupDivider()
            InstrumentMenuRow(InstrumentIcons.Shield, "Needs attention", attention?.takeIf { it > 0 }?.toString()) { onNavigate("attention") }
        } }
        item { Box(Modifier.arrive(3)) { GroupLabel("02 / Security") } }
        item { InstrumentGroup(Modifier.arrive(3)) {
            InstrumentMenuRow(InstrumentIcons.Share, "Sharing") { onNavigate("sharing") }
            GroupDivider()
            InstrumentMenuRow(InstrumentIcons.Shield, "Breach watch") { onNavigate("breach_monitor") }
        } }
        item { Box(Modifier.arrive(4)) { GroupLabel("03 / This device") } }
        item { InstrumentGroup(Modifier.arrive(4)) {
            InstrumentMenuRow(InstrumentIcons.Device, "Devices") { onNavigate("devices") }
            GroupDivider()
            InstrumentMenuRow(InstrumentIcons.Pulse, "Activity") { onNavigate("audit_log") }
            GroupDivider()
            InstrumentMenuRow(InstrumentIcons.Gear, "Settings") { onNavigate("settings") }
        } }
        item { InstrumentPill("Lock vault", onLock, Modifier.fillMaxWidth().padding(top = 12.dp).arrive(5), icon = InstrumentIcons.Lock, style = PillStyle.Primary) }
    }
}

@Composable
fun GroupLabel(text: String) {
    InstrumentLabel(text, Modifier.padding(start = 3.dp, end = 3.dp, top = 11.dp, bottom = 12.dp), color = Ink.faint)
}

@Composable
fun GeneratorScreen(onSaveLogin: (String) -> Unit, syncState: SyncState? = null, embedded: Boolean = false, useLabel: String = "Save as a new login") {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val toast = LocalInstrumentToast.current
    val random = remember { SecureRandom() }
    val words = remember { context.assets.open("instrument-words.txt").bufferedReader().use { it.readLines().filter(String::isNotBlank) } }
    var phrase by remember { mutableStateOf(false) }
    var length by remember { mutableIntStateOf(20) }
    var wordCount by remember { mutableIntStateOf(4) }
    val optionNames = remember { listOf("Uppercase", "Lowercase", "Numbers", "Symbols") }
    val options = remember { mutableStateMapOf("Uppercase" to true, "Lowercase" to true, "Numbers" to true, "Symbols" to true) }
    fun generate(): String {
        if (phrase) return List(wordCount) { words[random.nextInt(words.size)] }.joinToString("-")
        val sets = buildList {
            if (options["Uppercase"] == true) add("ABCDEFGHJKLMNPQRSTUVWXYZ")
            if (options["Lowercase"] == true) add("abcdefghijkmnopqrstuvwxyz")
            if (options["Numbers"] == true) add("23456789")
            if (options["Symbols"] == true) add("!@#$%&*+-=?")
        }.ifEmpty { listOf("abcdefghijkmnopqrstuvwxyz") }
        val alphabet = sets.joinToString("")
        // One from each chosen group, so "Numbers" really means at least one number.
        val chars = MutableList(length) { alphabet[random.nextInt(alphabet.length)] }
        sets.forEachIndexed { i, set -> chars[i] = set[random.nextInt(set.length)] }
        java.util.Collections.shuffle(chars, random)
        return chars.joinToString("")
    }
    var value by remember { mutableStateOf(generate()) }
    var spins by remember { mutableIntStateOf(0) }
    fun regenerate() { value = generate(); spins++ }

    val lime = Ink.lime; val violet = VelaColors.Violet
    val container = if (embedded) Modifier.fillMaxWidth() else Modifier.fillMaxSize()
        .background(VelaColors.SurfaceBase).verticalScroll(rememberScrollState())
        .padding(start = 20.dp, end = 20.dp, top = 10.dp, bottom = 20.dp)
    Column(container) {
        if (!embedded) {
            Box(Modifier.arrive(0)) { InstrumentBrand(syncState = syncState) }
            InstrumentHeading("02 / Generator", "A good kind\nof unpredictable.", modifier = Modifier.arrive(1))
        }
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(vertical = 3.dp).arrive(2), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            InstrumentChip("Password", !phrase, { if (phrase) { phrase = false; regenerate() } })
            InstrumentChip("Passphrase", phrase, { if (!phrase) { phrase = true; regenerate() } })
        }
        Column(Modifier.padding(vertical = 16.dp).arrive(3).fillMaxWidth().instrumentPanel(22.dp, Ink.line2, Ink.panel)
            .padding(horizontal = 18.dp, vertical = 20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                InstrumentLabel(if (phrase) "Passphrase" else "Password", Modifier.weight(1f))
                val turn by animateFloatAsState(spins * 180f, tween(450, easing = InstrumentEase), label = "spin")
                Box(Modifier.graphicsLayer { rotationZ = turn }) {
                    InstrumentIconButton(InstrumentIcons.Refresh, "Generate again", ::regenerate, iconSize = 16.dp)
                }
            }
            // Readout settles in from 3dp below on every new value.
            val settle = remember { Animatable(1f) }
            LaunchedEffect(value) { settle.snapTo(0f); settle.animateTo(1f, tween(180)) }
            val lift = with(LocalDensity.current) { 3.dp.toPx() }
            Text(
                buildAnnotatedString {
                    value.forEach { c ->
                        when {
                            c.isDigit() -> withStyle(SpanStyle(color = lime)) { append(c) }
                            !c.isLetterOrDigit() && !phrase -> withStyle(SpanStyle(color = violet)) { append(c) }
                            else -> append(c)
                        }
                    }
                },
                Modifier.fillMaxWidth().heightIn(min = 118.dp).padding(top = 8.dp, bottom = 20.dp)
                    .graphicsLayer { alpha = .4f + .6f * settle.value; translationY = (1f - settle.value) * lift },
                fontFamily = InstrumentMono, fontWeight = FontWeight.Medium, fontSize = 22.sp, lineHeight = 37.sp,
                letterSpacing = (-1.1).sp, color = VelaColors.TextPrimary,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                InstrumentFine("Generated on your device", Modifier.weight(1f), size = 9.sp)
                InstrumentIconButton(InstrumentIcons.Copy, "Copy generated password", {
                    SecureClipboard.copy(context, scope, "Generated password", value)
                    toast.show("Copied. Clears in ${SecureClipboard.clearDelaySeconds} seconds.")
                }, iconSize = 16.dp)
            }
        }
        Row(Modifier.padding(top = 7.dp).arrive(4), verticalAlignment = Alignment.CenterVertically) {
            InstrumentLabel(if (phrase) "Words" else "Length", Modifier.weight(1f))
            Text((if (phrase) wordCount else length).toString(), fontFamily = InstrumentMono, fontSize = 11.sp, color = violet)
        }
        InstrumentSlider(if (phrase) wordCount else length, if (phrase) 3..8 else 8..40, { v ->
            if (phrase && v != wordCount) { wordCount = v; value = generate() }
            if (!phrase && v != length) { length = v; value = generate() }
        }, if (phrase) "Word count" else "Password length", Modifier.padding(top = 8.dp, bottom = 16.dp).arrive(4))
        if (!phrase) InstrumentGroup(Modifier.arrive(5)) {
            optionNames.forEachIndexed { i, name ->
                if (i > 0) GroupDivider()
                InstrumentControlRow(name) {
                    InstrumentToggle(options[name] == true, { on ->
                        // Keep at least one character group switched on.
                        if (on || options.values.count { it } > 1) { options[name] = on; value = generate() }
                        else toast.show("Keep at least one character type.")
                    }, name)
                }
            }
        } else InstrumentFine("A few unexpected words. Easier to remember, harder to guess.", Modifier.arrive(5))
        InstrumentPill(useLabel, { onSaveLogin(value) }, Modifier.fillMaxWidth().padding(top = 16.dp).arrive(6),
            icon = InstrumentIcons.Plus, style = PillStyle.Primary)
    }
}
