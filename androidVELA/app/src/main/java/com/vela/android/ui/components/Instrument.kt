package com.vela.android.ui.components

import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.layout.layout
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.setProgress
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import kotlin.math.roundToInt
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.favicon.FaviconFetcher
import com.vela.android.sync.SyncState
import com.vela.android.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.delay

// ── tokens ──────────────────────────────────────────────────────────────
// The reference's --line / --line2 / --faint / --lime / --red, derived from
// the active palette so every theme gets them.

object Ink {
    val line: Color @Composable @ReadOnlyComposable get() = VelaColors.TextPrimary.copy(alpha = .075f)
    val line2: Color @Composable @ReadOnlyComposable get() = VelaColors.TextPrimary.copy(alpha = .14f)
    val faint: Color @Composable @ReadOnlyComposable get() = VelaColors.TextMuted.copy(alpha = .66f)
    val lime: Color @Composable @ReadOnlyComposable get() = VelaColors.SuccessGreen
    val onLime: Color @Composable @ReadOnlyComposable get() = if (VelaColors.isDark) Color(0xFF202709) else Color.White
    val red: Color @Composable @ReadOnlyComposable get() = VelaColors.ErrorRed
    val panel: Color @Composable @ReadOnlyComposable get() = VelaColors.SurfaceLow
    val panel2: Color @Composable @ReadOnlyComposable get() = VelaColors.SurfaceHigh
    val bg: Color @Composable @ReadOnlyComposable get() = VelaColors.SurfaceBase
}

// ── motion ──────────────────────────────────────────────────────────────

/** True when the user turned animations off in system settings. */
@Composable
fun rememberReducedMotion(): Boolean {
    val context = LocalContext.current
    return remember {
        runCatching {
            Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f
        }.getOrDefault(false)
    }
}

/** The reference's `cubic-bezier(.2,.8,.2,1)` — quick start, soft landing. */
val InstrumentEase = CubicBezierEasing(.2f, .8f, .2f, 1f)

/**
 * Staggered arrival: fades and lifts into place once, `index * 45ms` after
 * the screen appears. Matches the prototype's `arrive` keyframe, spread out.
 */
fun Modifier.arrive(index: Int = 0, distance: Dp = 10.dp): Modifier = composed {
    val reduced = rememberReducedMotion()
    val progress = remember { Animatable(if (reduced) 1f else 0f) }
    LaunchedEffect(Unit) {
        if (!reduced) {
            delay(index.coerceAtMost(12) * 45L)
            progress.animateTo(1f, tween(380, easing = InstrumentEase))
        }
    }
    val px = with(LocalDensity.current) { distance.toPx() }
    graphicsLayer {
        alpha = progress.value
        translationY = (1f - progress.value) * px
    }
}

/** Gentle press feedback: scales to 97% while held. */
fun Modifier.pressScale(source: MutableInteractionSource): Modifier = composed {
    val pressed by source.collectIsPressedAsState()
    val s by animateFloatAsState(if (pressed) .97f else 1f, tween(120), label = "press")
    graphicsLayer { scaleX = s; scaleY = s }
}

/** Clickable with press feedback and no ripple flash, like the prototype. */
fun Modifier.instrumentClick(enabled: Boolean = true, role: Role = Role.Button, onClick: () -> Unit): Modifier = composed {
    val source = remember { MutableInteractionSource() }
    pressScale(source).clickable(source, indication = null, enabled = enabled, role = role, onClick = onClick)
}

// ── type ────────────────────────────────────────────────────────────────

@Composable
fun InstrumentLabel(text: String, modifier: Modifier = Modifier, color: Color = VelaColors.TextMuted, size: TextUnit = 9.sp) {
    Text(text.uppercase(), modifier, fontFamily = InstrumentMono, fontSize = size,
        letterSpacing = (size.value * .1f).sp, color = color, maxLines = 1)
}

@Composable
fun InstrumentFine(text: String, modifier: Modifier = Modifier, size: TextUnit = 11.sp, color: Color = VelaColors.TextMuted,
    align: TextAlign? = null) {
    Text(text, modifier, fontSize = size, lineHeight = (size.value * 1.6f).sp, color = color, textAlign = align)
}

@Composable
fun InstrumentHeading(eyebrow: String, title: String, subtitle: String? = null, modifier: Modifier = Modifier) {
    Column(modifier.padding(top = 0.dp, bottom = 14.dp)) {
        InstrumentLabel(eyebrow)
        Spacer(Modifier.height(12.dp))
        Text(title, fontFamily = InstrumentDisplay, fontSize = 33.sp, lineHeight = 36.sp,
            letterSpacing = (-1.5).sp, fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
        if (subtitle != null) {
            Spacer(Modifier.height(10.dp))
            InstrumentFine(subtitle)
        }
    }
}

@Composable
fun SectionHead(label: String, modifier: Modifier = Modifier, action: (@Composable () -> Unit)? = null) {
    Row(modifier.fillMaxWidth().padding(top = 18.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        InstrumentLabel(label, Modifier.weight(1f))
        action?.invoke()
    }
}

@Composable
fun TextAction(text: String, onClick: () -> Unit) {
    Text(text, Modifier.clip(RoundedCornerShape(8.dp)).instrumentClick(onClick = onClick).padding(vertical = 8.dp),
        color = VelaColors.TextMuted, fontSize = 10.sp)
}

// ── controls ────────────────────────────────────────────────────────────

@Composable
fun InstrumentIcon(icon: ImageVector, size: Dp = 18.dp, tint: Color = VelaColors.TextPrimary, description: String? = null) {
    Icon(icon, description, Modifier.size(size), tint = tint)
}

/** Round 44dp icon button with a hairline, the prototype's `.ibtn`. */
@Composable
fun InstrumentIconButton(icon: ImageVector, description: String, onClick: () -> Unit, modifier: Modifier = Modifier,
    size: Dp = 44.dp, iconSize: Dp = 18.dp, bordered: Boolean = true, tint: Color = VelaColors.TextPrimary) {
    Box(
        modifier.size(size).clip(CircleShape)
            .then(if (bordered) Modifier.border(1.dp, Ink.line2, CircleShape) else Modifier)
            .instrumentClick(onClick = onClick)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) { Icon(icon, null, Modifier.size(iconSize), tint = tint) }
}

enum class PillStyle { Outline, Primary, Signal }

@Composable
fun InstrumentPill(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, icon: ImageVector? = null,
    style: PillStyle = PillStyle.Outline, iconTrailing: Boolean = false, enabled: Boolean = true) {
    val (bg, fg, border) = when (style) {
        PillStyle.Primary -> Triple(VelaColors.TextPrimary, VelaColors.SurfaceBase, VelaColors.TextPrimary)
        PillStyle.Signal -> Triple(Ink.lime, Ink.onLime, Ink.lime)
        PillStyle.Outline -> Triple(Color.Transparent, VelaColors.TextPrimary, Ink.line2)
    }
    Row(
        modifier.heightIn(min = 44.dp).clip(RoundedCornerShape(99.dp)).background(bg)
            .border(1.dp, border, RoundedCornerShape(99.dp))
            .graphicsLayer { alpha = if (enabled) 1f else .45f }
            .instrumentClick(enabled = enabled, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 11.dp),
        horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null && !iconTrailing) { Icon(icon, null, Modifier.size(15.dp), tint = fg); Spacer(Modifier.width(8.dp)) }
        Text(text, fontSize = 12.sp, color = fg, maxLines = 1)
        if (icon != null && iconTrailing) { Spacer(Modifier.width(8.dp)); Icon(icon, null, Modifier.size(15.dp), tint = fg) }
    }
}

@Composable
fun InstrumentChip(text: String, selected: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val bg by animateColorAsState(if (selected) VelaColors.TextPrimary else Color.Transparent, tween(200), label = "chip")
    val fg by animateColorAsState(if (selected) VelaColors.SurfaceBase else VelaColors.TextMuted, tween(200), label = "chipText")
    Box(
        modifier.heightIn(min = 44.dp).clip(RoundedCornerShape(99.dp)).background(bg)
            .border(1.dp, if (selected) VelaColors.TextPrimary else Ink.line2, RoundedCornerShape(99.dp))
            .instrumentClick(role = Role.Tab, onClick = onClick).padding(horizontal = 13.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center,
    ) { Text(text, fontSize = 11.sp, color = fg, maxLines = 1) }
}

/** 38×23 switch: lime when on, thumb slides over 200ms. */
@Composable
fun InstrumentToggle(checked: Boolean, onCheckedChange: (Boolean) -> Unit, description: String, modifier: Modifier = Modifier) {
    val offset by animateDpAsState(if (checked) 15.dp else 0.dp, tween(200, easing = InstrumentEase), label = "thumb")
    val track by animateColorAsState(if (checked) Ink.lime else Ink.panel2, tween(200), label = "track")
    val thumb by animateColorAsState(if (checked) Ink.onLime else VelaColors.TextMuted, tween(200), label = "thumbColor")
    Box(
        modifier.size(38.dp, 23.dp).clip(RoundedCornerShape(20.dp)).background(track)
            .border(1.dp, if (checked) Ink.lime else Ink.line2, RoundedCornerShape(20.dp))
            .clickable(role = Role.Switch) { onCheckedChange(!checked) }
            .semantics { contentDescription = description },
    ) { Box(Modifier.padding(2.dp).offset(x = offset).size(17.dp).clip(CircleShape).background(thumb)) }
}

enum class TagKind { Plain, Ok, Risk }

@Composable
fun InstrumentTag(text: String, kind: TagKind = TagKind.Plain) {
    val color = when (kind) { TagKind.Ok -> Ink.lime; TagKind.Risk -> Ink.red; TagKind.Plain -> VelaColors.TextMuted }
    val border = if (kind == TagKind.Plain) Ink.line2 else color.copy(alpha = .25f)
    Text(text.uppercase(), Modifier.border(1.dp, border, RoundedCornerShape(6.dp)).padding(horizontal = 6.dp, vertical = 4.dp),
        fontFamily = InstrumentMono, fontSize = 8.sp, color = color, maxLines = 1)
}

/** 39dp rounded tile holding an item's glyph (or initials), violet. */
@Composable
fun InstrumentAvatar(icon: ImageVector? = null, initials: String? = null, large: Boolean = false,
    faviconUrl: String? = null) {
    val size = if (large) 60.dp else 44.dp
    val shape = RoundedCornerShape(if (large) 20.dp else 15.dp)
    Box(Modifier.size(size).clip(shape).background(Ink.panel2).border(1.dp, Ink.line, shape), contentAlignment = Alignment.Center) {
        if (!faviconUrl.isNullOrBlank()) InstrumentFavicon(faviconUrl, icon, initials, large)
        else AvatarGlyph(icon, initials, large)
    }
}

@Composable
private fun AvatarGlyph(icon: ImageVector?, initials: String?, large: Boolean) {
    if (icon != null) Icon(icon, null, Modifier.size(if (large) 25.dp else 20.dp), tint = VelaColors.Violet)
    else Text(initials.orEmpty(), fontFamily = InstrumentMono, fontSize = 12.sp, color = VelaColors.Violet)
}

/** Favicon inside the avatar tile; the glyph stays visible until a bitmap arrives. */
@Composable
private fun InstrumentFavicon(url: String, glyph: ImageVector?, initials: String?, large: Boolean) {
    var bitmap by remember(url) { mutableStateOf<Bitmap?>(null) }
    LaunchedEffect(url) {
        bitmap = withContext(Dispatchers.IO) {
            FaviconFetcher.fetchDataUrl(url)?.let { dataUrl ->
                val base64 = dataUrl.substringAfter("base64,", "")
                if (base64.isEmpty()) null else runCatching {
                    val bytes = android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                }.getOrNull()
            }
        }
    }
    val icon = bitmap
    if (icon != null) {
        Image(icon.asImageBitmap(), contentDescription = null,
            modifier = Modifier.fillMaxSize().padding(if (large) 10.dp else 7.dp)
                .clip(RoundedCornerShape(if (large) 10.dp else 7.dp)),
            contentScale = ContentScale.Fit)
    } else AvatarGlyph(glyph, initials, large)
}

/** List row: avatar, name, subtitle, REVIEW tag or lime star, chevron. */
@Composable
fun InstrumentItemRow(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit,
    modifier: Modifier = Modifier, needsReview: Boolean = false, favorite: Boolean = false,
    faviconUrl: String? = null) {
    Row(
        modifier.fillMaxWidth().heightIn(min = 76.dp).clip(RoundedCornerShape(14.dp))
            .instrumentClick(onClick = onClick)
            .padding(horizontal = 3.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        InstrumentAvatar(icon, faviconUrl = faviconUrl)
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.Medium, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                color = VelaColors.TextPrimary)
            Spacer(Modifier.height(6.dp))
            Text(subtitle, fontSize = 12.5.sp, color = VelaColors.TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (needsReview) { InstrumentTag("Review", TagKind.Risk); Spacer(Modifier.width(9.dp)) }
        else if (favorite) { Icon(InstrumentIcons.Star, "Favourite", Modifier.size(13.dp), tint = Ink.lime); Spacer(Modifier.width(9.dp)) }
        Icon(InstrumentIcons.Chev, null, Modifier.size(15.dp), tint = Ink.faint)
    }
    Box(Modifier.fillMaxWidth().height(1.dp).background(Ink.line))
}

// ── surfaces ────────────────────────────────────────────────────────────

/** Bordered panel used by tiles, fields and groups. */
fun Modifier.instrumentPanel(radius: Dp = 20.dp, borderColor: Color, background: Color): Modifier =
    clip(RoundedCornerShape(radius)).background(background).border(1.dp, borderColor, RoundedCornerShape(radius))

@Composable
fun InstrumentTile(icon: ImageVector, title: String, caption: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier.instrumentPanel(20.dp, Ink.line, Ink.panel).instrumentClick(onClick = onClick).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(15.dp),
    ) {
        Icon(icon, null, Modifier.size(20.dp), tint = VelaColors.Violet)
        Column {
            Text(title, fontFamily = InstrumentDisplay, fontSize = 22.sp, lineHeight = 24.sp, fontWeight = FontWeight.Medium,
                color = VelaColors.TextPrimary, maxLines = 1)
            Spacer(Modifier.height(3.dp))
            InstrumentFine(caption, size = 10.sp)
        }
    }
}

/** Rounded container for a section's menu rows, separated by hairlines. */
@Composable
fun InstrumentGroup(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxWidth().padding(bottom = 12.dp).instrumentPanel(20.dp, Ink.line, Ink.panel), content = content)
}

@Composable
fun InstrumentMenuRow(icon: ImageVector?, label: String, meta: String? = null, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).heightIn(min = 55.dp).padding(horizontal = 15.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) { Icon(icon, null, Modifier.size(17.dp), tint = VelaColors.TextMuted); Spacer(Modifier.width(12.dp)) }
        Text(label, Modifier.weight(1f), fontSize = 12.sp, color = VelaColors.TextPrimary)
        if (meta != null) { Text(meta, fontFamily = InstrumentMono, fontSize = 9.sp, color = VelaColors.TextMuted); Spacer(Modifier.width(12.dp)) }
        Icon(InstrumentIcons.Chev, null, Modifier.size(14.dp), tint = VelaColors.TextMuted)
    }
}

/** A row with a trailing control instead of a chevron (toggles). */
@Composable
fun InstrumentControlRow(label: String, trailing: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 55.dp).padding(horizontal = 15.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), fontSize = 12.sp, color = VelaColors.TextPrimary)
        trailing()
    }
}

@Composable
fun GroupDivider() {
    Box(Modifier.fillMaxWidth().height(1.dp).background(Ink.line))
}

// ── header ──────────────────────────────────────────────────────────────

/** The reference's dot "V" mark: two dot columns that converge. */
@Composable
fun BrandMark(color: Color = VelaColors.Violet, modifier: Modifier = Modifier) {
    Canvas(modifier.size(20.dp, 26.dp).semantics { contentDescription = "VELA" }) {
        val u = size.width / 20f
        for (y in 0 until 8) for (x in 0..1) {
            val cx = if (y < 5) 3f + x * 14f else 3f + x * 14f + (if (x == 1) -1 else 1) * (y - 4) * 2f
            drawCircle(color, 1.1f * u, Offset(cx * u, (2f + y * 3f) * u))
        }
    }
}

@Composable
fun InstrumentBrand(onLock: (() -> Unit)? = null, syncState: SyncState? = null, trailingLabel: String? = null) {
    Row(Modifier.fillMaxWidth().padding(top = 2.dp, bottom = 14.dp).height(44.dp), verticalAlignment = Alignment.CenterVertically) {
        BrandMark()
        Spacer(Modifier.width(9.dp))
        Text("VELA", fontFamily = InstrumentBody, fontWeight = FontWeight.Medium, fontSize = 13.sp,
            letterSpacing = 1.8.sp, color = VelaColors.TextPrimary)
        Spacer(Modifier.weight(1f))
        if (trailingLabel != null) InstrumentLabel(trailingLabel)
        if (syncState != null) { SyncStatus(syncState); Spacer(Modifier.width(12.dp)) }
        if (onLock != null) InstrumentIconButton(InstrumentIcons.Lock, "Lock vault", onLock, iconSize = 15.dp)
    }
}

@Composable
private fun SyncStatus(state: SyncState) {
    val (label, dot) = when {
        state.syncing -> "Syncing changes" to VelaColors.TextMuted
        state.conflict != null -> "Sync needs attention" to Ink.red
        state.error != null -> "Sync unavailable" to Ink.red
        state.lastSyncedAt != null -> "All changes synced" to Ink.lime
        else -> "On this device only" to VelaColors.TextMuted
    }
    val reduced = rememberReducedMotion()
    val pulse = rememberInfiniteTransition(label = "sync")
    val a by pulse.animateFloat(1f, if (state.syncing && !reduced) .25f else 1f,
        infiniteRepeatable(tween(700), RepeatMode.Reverse), label = "syncDot")
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(5.dp).graphicsLayer { alpha = a }.clip(CircleShape).background(dot))
        Spacer(Modifier.width(5.dp))
        Text(label, fontFamily = InstrumentMono, fontSize = 9.sp, color = VelaColors.TextMuted, maxLines = 1)
    }
}

/** Centered back header: `[←]  SECTION / PAGE`. */
@Composable
fun BackHead(title: String, onBack: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(bottom = 22.dp).heightIn(min = 44.dp), verticalAlignment = Alignment.CenterVertically) {
        InstrumentIconButton(InstrumentIcons.Back, "Back", onBack)
        Box(Modifier.weight(1f).padding(end = 44.dp), contentAlignment = Alignment.Center) { InstrumentLabel(title) }
    }
}

// ── dock ────────────────────────────────────────────────────────────────

data class InstrumentDockItem(val route: String, val label: String, val icon: ImageVector)

/** Floating pill navigation; the active entry fills and its icon turns violet. */
@Composable
fun InstrumentDock(items: List<InstrumentDockItem>, selectedRoute: String, onSelect: (String) -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 8.dp)
            .clip(RoundedCornerShape(99.dp)).background(Ink.panel)
            .border(1.dp, Ink.line2, RoundedCornerShape(99.dp)).padding(5.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        items.forEach { item ->
            val active = item.route == selectedRoute
            val bg by animateColorAsState(if (active) Ink.panel2 else Ink.panel.copy(alpha = 0f), tween(200), label = "dockBg")
            val fg by animateColorAsState(if (active) VelaColors.TextPrimary else VelaColors.TextMuted, tween(200), label = "dockFg")
            val iconTint by animateColorAsState(if (active) VelaColors.Violet else VelaColors.TextMuted, tween(200), label = "dockIcon")
            val lift by animateDpAsState(if (active) (-1).dp else 0.dp, spring(dampingRatio = .55f), label = "dockLift")
            Column(
                Modifier.weight(1f).heightIn(min = 51.dp).clip(RoundedCornerShape(99.dp)).background(bg)
                    .instrumentClick(role = Role.Tab) { onSelect(item.route) },
                horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center,
            ) {
                Icon(item.icon, null, Modifier.size(18.dp).offset(y = lift), tint = iconTint)
                Spacer(Modifier.height(3.dp))
                Text(item.label, fontSize = 9.sp, lineHeight = 12.sp, maxLines = 1, color = fg)
            }
        }
    }
}

// ── dot matrix ──────────────────────────────────────────────────────────

private val digitRows = listOf(
    "11111/10001/10011/10101/11001/10001/11111", "00100/01100/00100/00100/00100/00100/01110",
    "11110/00001/00001/01110/10000/10000/11111", "11110/00001/00001/01110/00001/00001/11110",
    "10010/10010/10010/11111/00010/00010/00010", "11111/10000/10000/11110/00001/00001/11110",
    "01111/10000/10000/11110/10001/10001/01110", "11111/00001/00010/00100/01000/01000/01000",
    "01110/10001/10001/01110/10001/10001/01110", "01110/10001/10001/01111/00001/00001/11110")

/**
 * The prototype's 5×7 dot readout. Lit dots light column by column the
 * first time it appears (and whenever the value changes).
 */
@Composable
fun DotMatrix(value: String, modifier: Modifier = Modifier, color: Color = VelaColors.Violet, pitch: Dp = 5.5.dp) {
    val reduced = rememberReducedMotion()
    val reveal = remember(value) { Animatable(if (reduced) 1f else 0f) }
    LaunchedEffect(value) { if (!reduced) reveal.animateTo(1f, tween(420, easing = LinearOutSlowInEasing)) }
    val cols = (value.length * 6 - 1).coerceAtLeast(1)
    Canvas(modifier.size(pitch * cols, pitch * 7).semantics { contentDescription = value }) {
        val p = size.height / 7f
        val lit = reveal.value * cols
        value.forEachIndexed { index, char ->
            val rows = digitRows.getOrNull(char.digitToIntOrNull() ?: -1)?.split('/') ?: return@forEachIndexed
            rows.forEachIndexed { y, row -> row.forEachIndexed { x, c ->
                val col = index * 6 + x
                val on = c == '1' && col <= lit
                drawCircle(color.copy(alpha = if (on) 1f else .09f), p * .32f, Offset((col + .5f) * p, (y + .5f) * p))
            } }
        }
    }
}

// ── artwork ─────────────────────────────────────────────────────────────

/**
 * The hero sunrise, drawn to match the CSS exactly:
 * `radial-gradient(ellipse 85% 90% at 83% 116%, #ffd7a1 0, #ff866a 17%,
 * #b58aff 42%, #5a4ad54d 65%, transparent 85%)` breathing over 9s, plus the
 * repeating 25dp ring texture centred off the bottom-right corner.
 */
@Composable
fun SunrisePanel(modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val reduced = rememberReducedMotion()
    val breathe = rememberInfiniteTransition(label = "breathe")
    val t by breathe.animateFloat(0f, if (reduced) 0f else 1f, infiniteRepeatable(tween(9000, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "t")
    val density = LocalDensity.current
    Box(modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(Color(0xFF09090F))) {
        Canvas(Modifier.matchParentSize()) {
            val w = size.width; val h = size.height
            val center = Offset(w * .83f, h * 1.16f)
            val rx = w * .85f; val ry = h * .90f
            val grow = 1f + .04f * t
            scale(grow * 1f, grow * (ry / rx), pivot = center) {
                drawCircle(
                    Brush.radialGradient(
                        0f to Color(0xFFFFD7A1), .17f to Color(0xFFFF866A), .42f to Color(0xFFB58AFF),
                        .65f to Color(0x4D5A4AD5), .85f to Color.Transparent, 1f to Color.Transparent,
                        center = center, radius = rx,
                    ),
                    radius = rx, center = center, alpha = .85f + .15f * t,
                )
            }
            val ringCenter = Offset(w - with(density) { 150.dp.toPx() }, h + with(density) { 60.dp.toPx() })
            val step = with(density) { 25.dp.toPx() }
            var r = step
            while (r <= with(density) { 300.dp.toPx() }) {
                drawCircle(Color.White.copy(alpha = .043f), r, ringCenter, style = Stroke(1.dp.toPx()))
                r += step
            }
        }
        content()
    }
}

/** Lock-screen halo: a soft bottom glow with two orbit rings that breathe. */
@Composable
fun LockOrbit(modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val reduced = rememberReducedMotion()
    val orbit = rememberInfiniteTransition(label = "orbit")
    val t by orbit.animateFloat(0f, if (reduced) 0f else 1f, infiniteRepeatable(tween(4200, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "o")
    val line = Ink.line2
    // Bleeds 20dp past the screen padding on both sides, like `margin:0 -20px`.
    Box(modifier.fillMaxWidth().layout { m, c ->
        val extra = 40.dp.roundToPx()
        val p = m.measure(c.copy(minWidth = c.maxWidth + extra, maxWidth = c.maxWidth + extra))
        layout(c.maxWidth, p.height) { p.place(-extra / 2, 0) }
    }.height(192.dp).clipToBounds(), contentAlignment = Alignment.Center) {
        Canvas(Modifier.matchParentSize()) {
            val c = Offset(size.width / 2f, size.height)
            val rx = size.width * .55f; val ry = size.height * .55f
            scale(1f, ry / rx, pivot = c) {
                drawCircle(Brush.radialGradient(listOf(Color(0xB0CA9DEC), Color.Transparent), c, rx), rx, c)
            }
            val mid = Offset(size.width / 2f, size.height / 2f)
            drawCircle(line, 100.dp.toPx() * (1f + .02f * t), mid, style = Stroke(1.dp.toPx()))
            drawCircle(line.copy(alpha = line.alpha * (1f - .4f * t)), 145.dp.toPx() * (1f + .03f * t), mid, style = Stroke(1.dp.toPx()))
        }
        content()
    }
}

/** Payment card art: violet bloom from the top right on deep ink. */
@Composable
fun CardArt(label: String, number: String, holder: String, expiry: String) {
    Column(
        Modifier.fillMaxWidth().padding(top = 10.dp, bottom = 20.dp).heightIn(min = 185.dp)
            .clip(RoundedCornerShape(22.dp)).background(Color(0xFF181620))
            .drawBehind {
                drawRect(Brush.radialGradient(listOf(Color(0x658A68CE), Color.Transparent), Offset(size.width, 0f), size.width * 1.1f))
            }
            .border(1.dp, Color(0x30B99FFF), RoundedCornerShape(22.dp)).padding(22.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            InstrumentLabel(label, Modifier.weight(1f), color = Color(0xFFA9A0BC))
            Icon(InstrumentIcons.Card, null, Modifier.size(22.dp), tint = Color(0xFFF3F2EF))
        }
        Text(number, Modifier.padding(top = 28.dp, bottom = 22.dp), fontFamily = InstrumentMono, fontSize = 17.sp,
            letterSpacing = .85.sp, color = Color(0xFFF3F2EF))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(holder.uppercase(), Modifier.weight(1f), fontSize = 11.sp, color = Color(0xFFC4BDD1), maxLines = 1)
            InstrumentLabel(expiry, color = Color(0xFFA9A0BC))
        }
    }
}

// ── fields ──────────────────────────────────────────────────────────────

/** One bordered field card: mono label, value, optional reveal + copy. */
@Composable
fun InstrumentField(label: String, value: String, onCopy: (() -> Unit)? = null, secret: Boolean = false,
    revealed: Boolean = true, onReveal: (() -> Unit)? = null, mono: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(bottom = 9.dp).instrumentPanel(17.dp, Ink.line, Ink.panel).padding(horizontal = 15.dp, vertical = 14.dp)) {
        InstrumentLabel(label, size = 8.sp, color = Ink.faint)
        Row(verticalAlignment = Alignment.CenterVertically) {
            val shown = if (secret && !revealed) "•".repeat(value.length.coerceIn(8, 14)) else value
            Text(shown, Modifier.weight(1f).padding(top = 9.dp), fontSize = if (secret || mono) 12.sp else 13.sp,
                lineHeight = 19.sp, fontFamily = if (secret || mono) InstrumentMono else null, color = VelaColors.TextPrimary)
            if (secret && onReveal != null)
                InstrumentIconButton(if (revealed) InstrumentIcons.Eyeoff else InstrumentIcons.Eye,
                    if (revealed) "Hide $label" else "Reveal $label", onReveal, size = 38.dp, bordered = false, tint = VelaColors.TextMuted)
            if (onCopy != null)
                InstrumentIconButton(InstrumentIcons.Copy, "Copy ${label.lowercase()}", onCopy, size = 38.dp, iconSize = 17.dp,
                    bordered = false, tint = VelaColors.TextMuted)
        }
    }
}

/** Authenticator field: large dot readout, smooth countdown ring, copy. */
@Composable
fun TotpField(code: String?, secondsLeft: Int, period: Int, onCopy: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(bottom = 9.dp).instrumentPanel(17.dp, Ink.line, Ink.panel).padding(horizontal = 15.dp, vertical = 14.dp)) {
        InstrumentLabel("Authenticator", size = 8.sp, color = Ink.faint)
        Row(Modifier.padding(top = 15.dp), verticalAlignment = Alignment.CenterVertically) {
            if (code != null) DotMatrix(code, color = VelaColors.Violet, pitch = 3.8.dp)
            else InstrumentFine("This setup key isn't valid.", size = 12.sp)
            Spacer(Modifier.weight(1f))
            if (code != null) {
                CountdownRing(secondsLeft, period)
                Spacer(Modifier.width(10.dp))
                InstrumentIconButton(InstrumentIcons.Copy, "Copy authenticator code", onCopy, size = 44.dp, iconSize = 17.dp,
                    bordered = false, tint = VelaColors.TextMuted)
            }
        }
    }
}

@Composable
fun CountdownRing(secondsLeft: Int, period: Int, size: Dp = 34.dp) {
    val target = secondsLeft.toFloat() / period.coerceAtLeast(1)
    // Linear 1s glide between ticks, snapping back up at rollover.
    val frac by animateFloatAsState(target, if (target > .97f) snap() else tween(1000, easing = LinearEasing), label = "ring")
    val track = Ink.line2
    val arc = if (secondsLeft <= 5) Ink.red else VelaColors.Violet
    Box(Modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.matchParentSize()) {
            val stroke = 2.dp.toPx(); val r = this.size.minDimension / 2f - stroke * 1.2f
            drawCircle(track, r, style = Stroke(stroke))
            drawArc(arc, -90f, 360f * frac, false, topLeft = Offset(center.x - r, center.y - r),
                size = androidx.compose.ui.geometry.Size(r * 2, r * 2), style = Stroke(stroke, cap = androidx.compose.ui.graphics.StrokeCap.Round))
        }
        Text(secondsLeft.toString(), fontFamily = InstrumentMono, fontSize = 9.sp, color = VelaColors.TextMuted)
    }
}

// ── slider ──────────────────────────────────────────────────────────────

/** Thin range slider like the prototype's native input: 4dp track, round violet thumb. */
@Composable
fun InstrumentSlider(value: Int, range: IntRange, onChange: (Int) -> Unit, description: String, modifier: Modifier = Modifier) {
    val violet = VelaColors.Violet; val track = Ink.line2
    val frac = (value - range.first).toFloat() / (range.last - range.first).coerceAtLeast(1)
    val shown by animateFloatAsState(frac, tween(90), label = "slider")
    var widthPx by remember { mutableFloatStateOf(1f) }
    fun pick(x: Float) = onChange((range.first + ((x / widthPx).coerceIn(0f, 1f) * (range.last - range.first))).roundToInt())
    Canvas(
        modifier.fillMaxWidth().height(32.dp)
            .onSizeChanged { widthPx = it.width.toFloat() }
            .pointerInput(range) { detectTapGestures { pick(it.x) } }
            .pointerInput(range) { detectHorizontalDragGestures { change, _ -> pick(change.position.x) } }
            .semantics(mergeDescendants = true) {
                contentDescription = description
                progressBarRangeInfo = androidx.compose.ui.semantics.ProgressBarRangeInfo(value.toFloat(), range.first.toFloat()..range.last.toFloat(), range.last - range.first - 1)
                setProgress { target -> onChange(target.roundToInt().coerceIn(range)); true }
            }
    ) {
        val r = 8.dp.toPx(); val y = size.height / 2f; val x = r + (size.width - 2 * r) * shown
        drawLine(track, Offset(r, y), Offset(size.width - r, y), 4.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round)
        drawLine(violet, Offset(r, y), Offset(x, y), 4.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round)
        drawCircle(violet, r, Offset(x, y))
    }
}

// ── sheet ───────────────────────────────────────────────────────────────

/**
 * Bottom sheet drawn inside the current window (so screenshot protection
 * still covers it): dimmed backdrop fades in, the sheet rises 60dp with the
 * reference's easing. Back or the backdrop closes it.
 */
@Composable
fun InstrumentSheet(visible: Boolean, title: String, onDismiss: () -> Unit, maxHeight: Dp? = null, content: @Composable ColumnScope.() -> Unit) {
    if (visible) BackHandler(onBack = onDismiss)
    var entered by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { entered = true }
    Box(Modifier.fillMaxSize()) {
        AnimatedVisibility(visible && entered, enter = fadeIn(tween(200)), exit = fadeOut(tween(180))) {
            Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = .6f)).clickable(
                remember { MutableInteractionSource() }, indication = null, onClick = onDismiss))
        }
        AnimatedVisibility(
            visible && entered, Modifier.align(Alignment.BottomCenter),
            enter = slideInVertically(tween(300, easing = InstrumentEase)) { it / 6 } + fadeIn(tween(300), initialAlpha = .4f),
            exit = slideOutVertically(tween(220)) { it / 3 } + fadeOut(tween(180)),
        ) {
            val shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
            Column(
                Modifier.fillMaxWidth().heightIn(max = maxHeight ?: (LocalConfiguration.current.screenHeightDp * .9f).dp)
                    .clip(shape).background(Ink.bg).border(1.dp, Ink.line2, shape)
                    .pointerInput(Unit) { detectTapGestures(onTap = {}) }
                    .navigationBarsPadding().imePadding()
                    .verticalScroll(rememberScrollState())
                    .padding(start = 20.dp, end = 20.dp, top = 10.dp, bottom = 26.dp),
            ) {
                Box(Modifier.align(Alignment.CenterHorizontally).padding(bottom = 14.dp).size(32.dp, 4.dp)
                    .clip(RoundedCornerShape(99.dp)).background(Ink.faint.copy(alpha = .5f)))
                Row(Modifier.fillMaxWidth().padding(bottom = 22.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(title, Modifier.weight(1f), fontFamily = InstrumentDisplay, fontSize = 22.sp, lineHeight = 26.sp,
                        letterSpacing = (-.6).sp, fontWeight = FontWeight.Medium, color = VelaColors.TextPrimary)
                    InstrumentIconButton(InstrumentIcons.X, "Close", onDismiss, iconSize = 17.dp)
                }
                content()
            }
        }
    }
}

/** Small mono form label inside sheets. */
@Composable
fun SheetLabel(text: String) {
    InstrumentLabel(text, Modifier.padding(top = 17.dp, bottom = 8.dp), size = 9.sp)
}

/** Read-only form box matching the sheet inputs (48dp, panel, hairline). */
@Composable
fun SheetValue(text: String, placeholder: Boolean = false) {
    Box(Modifier.fillMaxWidth().heightIn(min = 48.dp).instrumentPanel(14.dp, Ink.line2, Ink.panel).padding(12.dp),
        contentAlignment = Alignment.CenterStart) {
        Text(text, fontSize = 12.sp, color = if (placeholder) Ink.faint else VelaColors.TextPrimary)
    }
}

// ── toast ───────────────────────────────────────────────────────────────

class InstrumentToastState {
    var message by mutableStateOf<String?>(null)
        private set
    private var serial by mutableIntStateOf(0)
    fun show(text: String) { message = text; serial++ }
    internal val key: Int get() = serial
    internal fun clear() { message = null }
}

val LocalInstrumentToast = staticCompositionLocalOf { InstrumentToastState() }

/** Wrap a screen tree once; anything inside can call `LocalInstrumentToast.current.show(...)`. */
@Composable
fun InstrumentToastHost(bottomInset: Dp = 83.dp, content: @Composable () -> Unit) {
    val state = remember { InstrumentToastState() }
    CompositionLocalProvider(LocalInstrumentToast provides state) {
        Box(Modifier.fillMaxSize()) {
            content()
            val key = state.key
            LaunchedEffect(key) { if (state.message != null) { delay(2600); state.clear() } }
            AnimatedVisibility(state.message != null, Modifier.align(Alignment.BottomCenter).padding(start = 20.dp, end = 20.dp, bottom = bottomInset),
                enter = slideInVertically(tween(220, easing = InstrumentEase)) { it / 2 } + fadeIn(tween(200)),
                exit = fadeOut(tween(200))) {
                Text(state.message.orEmpty(), Modifier.fillMaxWidth().instrumentPanel(18.dp, Ink.line2, Ink.panel2)
                    .padding(horizontal = 15.dp, vertical = 13.dp), fontSize = 11.sp, textAlign = TextAlign.Center,
                    color = VelaColors.TextPrimary)
            }
        }
    }
}

/** Shape helper kept for older call sites. */
val InstrumentRound: Shape = RoundedCornerShape(99.dp)
