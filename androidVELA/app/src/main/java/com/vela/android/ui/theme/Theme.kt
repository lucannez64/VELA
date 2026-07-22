package com.vela.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * The active palette for the current composition. Provided by [VelaTheme].
 * Defaults to VELA Dark so previews/non-themed hosts still render.
 */
val LocalVelaPalette = staticCompositionLocalOf { VelaPalettes.Vela }

/**
 * Theme-reactive access to the active [VelaPalette]. Mirrors the
 * `MaterialTheme.colorScheme` pattern: a read-only composable property, so
 * every `VelaColors.SurfaceBase` (etc.) call site recomposes on theme change
 * without each call site needing to read a CompositionLocal directly.
 *
 * Kept as a top-level property (rather than inside an object) so that the
 * legacy `VelaColors.X` property-access syntax still resolves.
 */
val VelaColors: VelaPalette
    @Composable
    @ReadOnlyComposable
    get() = LocalVelaPalette.current

/** Theme ids, matching desktopVELA/src/themes.ts for parity. */
typealias VelaThemeId = String

object VelaThemes {
    const val VELA: VelaThemeId = "vela"
    const val MACCHIATO: VelaThemeId = "macchiato"
    const val LATTE: VelaThemeId = "latte"
    const val GRUVBOX: VelaThemeId = "gruvbox"
    /** Follow the OS light/dark preference (picks Latte or VELA Dark). */
    const val SYSTEM: VelaThemeId = "system"

    data class Meta(
        val id: VelaThemeId,
        val label: String,
        val description: String,
        val dark: Boolean,
        /** [background, container, primary, accent] preview colors for the picker. */
        val swatches: List<Long>
    )

    val ALL: List<Meta> = listOf(
        Meta(VELA, "VELA Dark", "Default obsidian look", true, listOf(0xFF121416, 0xFF1E2022, 0xFF73DB9A, 0xFF8B5CF6)),
        Meta(MACCHIATO, "Macchiato", "Catppuccin Macchiato", true, listOf(0xFF24273A, 0xFF363A4F, 0xFFA6DA95, 0xFFC6A0F6)),
        Meta(LATTE, "Latte", "Catppuccin Latte — light", false, listOf(0xFFEFF1F5, 0xFFDCE0E8, 0xFF40A02B, 0xFF8839EF)),
        Meta(GRUVBOX, "Gruvbox", "Retro groove, warm dark", true, listOf(0xFF282828, 0xFF3C3836, 0xFFB8BB26, 0xFFD3869B))
    )

    fun meta(id: VelaThemeId): Meta = ALL.first { it.id == id }

    fun palette(id: VelaThemeId): VelaPalette = when (id) {
        MACCHIATO -> VelaPalettes.Macchiato
        LATTE -> VelaPalettes.Latte
        GRUVBOX -> VelaPalettes.Gruvbox
        else -> VelaPalettes.Vela
    }
}

/**
 * Maps a stored setting (including "system") to a concrete palette, using the
 * OS dark-mode preference for the system option — the same behaviour as the
 * desktop app's `resolveTheme`.
 */
@Composable
fun resolveVelaPalette(setting: VelaThemeId?): VelaPalette {
    if (setting == null || setting == VelaThemes.SYSTEM || setting.isBlank()) {
        return if (isSystemInDarkTheme()) VelaPalettes.Vela else VelaPalettes.Latte
    }
    return VelaThemes.palette(setting)
}

/** Builds a Material3 [ColorScheme] from a [VelaPalette], picking light vs dark. */
private fun darkVelaColorScheme(p: VelaPalette): ColorScheme = darkColorScheme(
    primary = p.Green,
    onPrimary = p.GreenDark,
    primaryContainer = p.GreenDim,
    onPrimaryContainer = p.TextPrimary,
    secondary = p.Teal,
    onSecondary = p.TealDark,
    secondaryContainer = p.Violet,
    onSecondaryContainer = p.TextPrimary,
    tertiary = p.Violet,
    onTertiary = p.TextPrimary,
    background = p.SurfaceBase,
    onBackground = p.TextPrimary,
    surface = p.Surface,
    onSurface = p.TextPrimary,
    surfaceVariant = p.SurfaceHigh,
    onSurfaceVariant = p.TextSecondary,
    surfaceDim = p.SurfaceLow,
    surfaceBright = p.SurfaceBright,
    surfaceContainerLowest = p.SurfaceDarkest,
    surfaceContainerLow = p.SurfaceLow,
    surfaceContainer = p.Surface,
    surfaceContainerHigh = p.SurfaceHigh,
    surfaceContainerHighest = p.SurfaceHighest,
    error = p.ErrorRed,
    onError = p.SurfaceDarkest,
    outline = p.Outline,
    outlineVariant = p.Outline.copy(alpha = 0.5f),
    inverseSurface = p.TextPrimary,
    inverseOnSurface = p.SurfaceBase,
    inversePrimary = p.GreenDim
)

private fun lightVelaColorScheme(p: VelaPalette): ColorScheme = lightColorScheme(
    primary = p.Green,
    onPrimary = p.GreenDark,
    primaryContainer = p.GreenDim,
    onPrimaryContainer = p.SurfaceDarkest,
    secondary = p.Teal,
    onSecondary = p.TealDark,
    secondaryContainer = p.Violet,
    onSecondaryContainer = p.SurfaceDarkest,
    tertiary = p.Violet,
    onTertiary = p.SurfaceDarkest,
    background = p.SurfaceBase,
    onBackground = p.TextPrimary,
    surface = p.Surface,
    onSurface = p.TextPrimary,
    surfaceVariant = p.SurfaceHigh,
    onSurfaceVariant = p.TextSecondary,
    surfaceDim = p.SurfaceLow,
    surfaceBright = p.SurfaceBright,
    surfaceContainerLowest = p.SurfaceDarkest,
    surfaceContainerLow = p.SurfaceLow,
    surfaceContainer = p.Surface,
    surfaceContainerHigh = p.SurfaceHigh,
    surfaceContainerHighest = p.SurfaceHighest,
    error = p.ErrorRed,
    onError = p.SurfaceBase,
    outline = p.Outline,
    outlineVariant = p.Outline.copy(alpha = 0.5f),
    inverseSurface = p.TextPrimary,
    inverseOnSurface = p.SurfaceBase,
    inversePrimary = p.GreenDim
)

private fun velaColorScheme(p: VelaPalette): ColorScheme =
    if (p.isDark) darkVelaColorScheme(p) else lightVelaColorScheme(p)

@Composable
fun VelaTheme(
    themeSetting: VelaThemeId? = null,
    content: @Composable () -> Unit
) {
    val palette = resolveVelaPalette(themeSetting)
    MaterialTheme(
        colorScheme = velaColorScheme(palette),
        typography = VelaTypography,
        shapes = VelaShapes,
        content = { CompositionLocalProvider(LocalVelaPalette provides palette, content = content) }
    )
}
