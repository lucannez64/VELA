package com.vela.android.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Full set of semantic colors used throughout the app. One instance exists
 * per theme (see [VelaPalettes]) and the active one is exposed to
 * composition via [LocalVelaPalette] / the [VelaColors] composable accessor.
 *
 * Field names are kept identical to the legacy `object VelaColors` so that
 * existing `VelaColors.SurfaceBase`-style call sites compile unchanged while
 * becoming theme-reactive.
 */
data class VelaPalette(
    val isDark: Boolean,
    val Green: Color,
    val GreenDim: Color,
    val GreenDark: Color,
    val Teal: Color,
    val TealDark: Color,
    val Violet: Color,
    val VioletDim: Color,
    val SurfaceDarkest: Color,
    val SurfaceBase: Color,
    val SurfaceLow: Color,
    val Surface: Color,
    val SurfaceHigh: Color,
    val SurfaceHighest: Color,
    val SurfaceBright: Color,
    val TextPrimary: Color,
    val TextSecondary: Color,
    val TextMuted: Color,
    val Outline: Color,
    val ErrorRed: Color,
    val ErrorRedBg: Color,
    val WarningAmber: Color,
    val WarningAmberBg: Color,
    val SuccessGreen: Color,
    val SuccessGreenBg: Color,
    val InfoTeal: Color
)

/**
 * Palettes for the four themes the desktop app exposes. Swatches mirror
 * desktopVELA/src/themes.ts; the supporting surface/text scales are drawn
 * from each theme's canonical palette (VELA obsidian, Catppuccin, Gruvbox).
 */
object VelaPalettes {
    /** VELA Dark — default obsidian look. */
    val Vela = VelaPalette(
        isDark = true,
        Green = Color(0xFFD9F36A),
        GreenDim = Color(0xFFAFC44F),
        GreenDark = Color(0xFF202709),
        Teal = Color(0xFFD9F36A),
        TealDark = Color(0xFF202709),
        Violet = Color(0xFFA28AFF),
        VioletDim = Color(0xFF7455D3),
        SurfaceDarkest = Color(0xFF060609),
        SurfaceBase = Color(0xFF0B0B10),
        SurfaceLow = Color(0xFF15151D),
        Surface = Color(0xFF15151D),
        SurfaceHigh = Color(0xFF1D1D27),
        SurfaceHighest = Color(0xFF242430),
        SurfaceBright = Color(0xFF2B2B38),
        TextPrimary = Color(0xFFF3F2EF),
        TextSecondary = Color(0xFFB1AEBC),
        TextMuted = Color(0xFF96949F),
        Outline = Color(0xFF34323F),
        ErrorRed = Color(0xFFFF7869),
        ErrorRedBg = Color(0x1AFFB4AB),
        WarningAmber = Color(0xFFFFD166),
        WarningAmberBg = Color(0x1AFFD166),
        SuccessGreen = Color(0xFFD9F36A),
        SuccessGreenBg = Color(0x1A73DB9A),
        InfoTeal = Color(0xFFD9F36A)
    )

    val Paper = Vela.copy(
        isDark = false, Green = Color(0xFF5B6C13), GreenDark = Color.White,
        Violet = Color(0xFF7455D3), SurfaceDarkest = Color(0xFFF7F6F2), SurfaceBase = Color(0xFFF7F6F2),
        SurfaceLow = Color(0xFFEEECE7), Surface = Color(0xFFEEECE7), SurfaceHigh = Color(0xFFE4E1D9),
        SurfaceHighest = Color(0xFFE4E1D9), SurfaceBright = Color(0xFFE4E1D9),
        TextPrimary = Color(0xFF19191E), TextSecondary = Color(0xFF716F78), TextMuted = Color(0xFF8C8992),
        Outline = Color(0xFFD0CDD5), ErrorRed = Color(0xFFBD4437), SuccessGreen = Color(0xFF5B6C13)
    )

    /** Catppuccin Macchiato — dark. */
    val Macchiato = VelaPalette(
        isDark = true,
        Green = Color(0xFFA6DA95),
        GreenDim = Color(0xFF8BC56F),
        GreenDark = Color(0xFF1E2030),
        Teal = Color(0xFF8BD5CA),
        TealDark = Color(0xFF1E2030),
        Violet = Color(0xFFC6A0F6),
        VioletDim = Color(0xFFB290EA),
        SurfaceDarkest = Color(0xFF181926),
        SurfaceBase = Color(0xFF24273A),
        SurfaceLow = Color(0xFF1E2030),
        Surface = Color(0xFF363A4F),
        SurfaceHigh = Color(0xFF494D64),
        SurfaceHighest = Color(0xFF5B6078),
        SurfaceBright = Color(0xFF6E738D),
        TextPrimary = Color(0xFFCAD3F5),
        TextSecondary = Color(0xFFB8C0E0),
        TextMuted = Color(0xFF8087A3),
        Outline = Color(0xFF6E738D),
        ErrorRed = Color(0xFFED8796),
        ErrorRedBg = Color(0x1AED8796),
        WarningAmber = Color(0xFFEED49F),
        WarningAmberBg = Color(0x1AEED49F),
        SuccessGreen = Color(0xFFA6DA95),
        SuccessGreenBg = Color(0x1AA6DA95),
        InfoTeal = Color(0xFF8BD5CA)
    )

    /** Catppuccin Latte — light. */
    val Latte = VelaPalette(
        isDark = false,
        Green = Color(0xFF40A02B),
        GreenDim = Color(0xFF2F5E1E),
        GreenDark = Color(0xFFFFFFFF),
        Teal = Color(0xFF179299),
        TealDark = Color(0xFFFFFFFF),
        Violet = Color(0xFF8839EF),
        VioletDim = Color(0xFF7325C9),
        SurfaceDarkest = Color(0xFFDCE0E8),
        SurfaceBase = Color(0xFFEFF1F5),
        SurfaceLow = Color(0xFFE6E9EF),
        Surface = Color(0xFFDCE0E8),
        SurfaceHigh = Color(0xFFCCD0DA),
        SurfaceHighest = Color(0xFFBCC0CC),
        SurfaceBright = Color(0xFFACB0BE),
        TextPrimary = Color(0xFF4C4F69),
        TextSecondary = Color(0xFF5C5F77),
        TextMuted = Color(0xFF7C8096),
        Outline = Color(0xFF8C8FA1),
        ErrorRed = Color(0xFFD20F39),
        ErrorRedBg = Color(0x1AD20F39),
        WarningAmber = Color(0xFFDF8E1D),
        WarningAmberBg = Color(0x1ADF8E1D),
        SuccessGreen = Color(0xFF40A02B),
        SuccessGreenBg = Color(0x1A40A02B),
        InfoTeal = Color(0xFF179299)
    )

    /** Gruvbox — retro groove, warm dark. */
    val Gruvbox = VelaPalette(
        isDark = true,
        Green = Color(0xFFB8BB26),
        GreenDim = Color(0xFF98971A),
        GreenDark = Color(0xFF1D2021),
        Teal = Color(0xFF8EC07C),
        TealDark = Color(0xFF1D2021),
        Violet = Color(0xFFD3869B),
        VioletDim = Color(0xFFB16286),
        SurfaceDarkest = Color(0xFF1D2021),
        SurfaceBase = Color(0xFF282828),
        SurfaceLow = Color(0xFF1D2021),
        Surface = Color(0xFF3C3836),
        SurfaceHigh = Color(0xFF504945),
        SurfaceHighest = Color(0xFF665C54),
        SurfaceBright = Color(0xFF7C6F64),
        TextPrimary = Color(0xFFEBDBB2),
        TextSecondary = Color(0xFFD5C4A1),
        TextMuted = Color(0xFFA89984),
        Outline = Color(0xFF504945),
        ErrorRed = Color(0xFFFB4934),
        ErrorRedBg = Color(0x1AFB4934),
        WarningAmber = Color(0xFFFABD2F),
        WarningAmberBg = Color(0x1AFABD2F),
        SuccessGreen = Color(0xFFB8BB26),
        SuccessGreenBg = Color(0x1AB8BB26),
        InfoTeal = Color(0xFF8EC07C)
    )
}
