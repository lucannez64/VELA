package com.vela.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val VelaColorScheme = darkColorScheme(
    primary = VelaColors.Green,
    onPrimary = VelaColors.GreenDark,
    primaryContainer = VelaColors.GreenDim,
    onPrimaryContainer = VelaColors.TextPrimary,
    secondary = VelaColors.Teal,
    onSecondary = VelaColors.TealDark,
    secondaryContainer = VelaColors.Violet,
    onSecondaryContainer = VelaColors.TextPrimary,
    tertiary = VelaColors.Violet,
    onTertiary = VelaColors.TextPrimary,
    background = VelaColors.SurfaceBase,
    onBackground = VelaColors.TextPrimary,
    surface = VelaColors.Surface,
    onSurface = VelaColors.TextPrimary,
    surfaceVariant = VelaColors.SurfaceHigh,
    onSurfaceVariant = VelaColors.TextSecondary,
    surfaceDim = VelaColors.SurfaceLow,
    surfaceBright = VelaColors.SurfaceBright,
    surfaceContainerLowest = VelaColors.SurfaceDarkest,
    surfaceContainerLow = VelaColors.SurfaceLow,
    surfaceContainer = VelaColors.Surface,
    surfaceContainerHigh = VelaColors.SurfaceHigh,
    surfaceContainerHighest = VelaColors.SurfaceHighest,
    error = VelaColors.ErrorRed,
    onError = VelaColors.SurfaceDarkest,
    outline = VelaColors.Outline,
    outlineVariant = VelaColors.Outline.copy(alpha = 0.5f),
    inverseSurface = VelaColors.TextPrimary,
    inverseOnSurface = VelaColors.SurfaceBase,
    inversePrimary = VelaColors.GreenDim
)

@Composable
fun VelaTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = VelaColorScheme,
        typography = VelaTypography,
        shapes = VelaShapes,
        content = content
    )
}
