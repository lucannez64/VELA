import SwiftUI

// Instrument design tokens, matching docs/mobile-redesign-instrument.html and
// the Android `Ink` palette. Every theme exposes the same names as the
// prototype's CSS variables (--bg, --panel, --line, --violet, --lime, …).

extension Color {
    /// `0xRRGGBB`, optionally with a separate alpha.
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: alpha)
    }

    /// `0xRRGGBBAA`, the CSS 8-digit form used by the prototype.
    init(rgba: UInt32) {
        self.init(hex: rgba >> 8, alpha: Double(rgba & 0xFF) / 255)
    }
}

enum InstrumentThemeID: String, CaseIterable, Identifiable {
    case night, paper, macchiato, latte

    var id: String { rawValue }

    var title: String {
        switch self {
        case .night: return "Night"
        case .paper: return "Paper"
        case .macchiato: return "Macchiato"
        case .latte: return "Latte"
        }
    }

    var palette: InstrumentPalette {
        switch self {
        case .night: return .night
        case .paper: return .paper
        case .macchiato: return .macchiato
        case .latte: return .latte
        }
    }
}

struct InstrumentPalette {
    let isDark: Bool
    let bg: Color
    let panel: Color
    let panel2: Color
    let text: Color
    let muted: Color
    let faint: Color
    let line: Color
    let line2: Color
    let violet: Color
    let lime: Color
    let onLime: Color
    let primary: Color
    let onPrimary: Color
    let red: Color

    static let night = InstrumentPalette(
        isDark: true, bg: Color(hex: 0x0B0B10), panel: Color(hex: 0x15151D), panel2: Color(hex: 0x1D1D27),
        text: Color(hex: 0xF3F2EF), muted: Color(hex: 0x96949F), faint: Color(hex: 0x62606E),
        line: Color(rgba: 0xFFFFFF12), line2: Color(rgba: 0xFFFFFF20), violet: Color(hex: 0xA28AFF),
        lime: Color(hex: 0xD9F36A), onLime: Color(hex: 0x202709), primary: Color(hex: 0xF3F2EF),
        onPrimary: Color(hex: 0x101014), red: Color(hex: 0xFF7869))

    static let paper = InstrumentPalette(
        isDark: false, bg: Color(hex: 0xF7F6F2), panel: Color(hex: 0xEEECE7), panel2: Color(hex: 0xE4E1D9),
        text: Color(hex: 0x19191E), muted: Color(hex: 0x716F78), faint: Color(hex: 0x8C8992),
        line: Color(rgba: 0x19191E12), line2: Color(rgba: 0x19191E25), violet: Color(hex: 0x7455D3),
        lime: Color(hex: 0x5B6C13), onLime: .white, primary: Color(hex: 0x19191E),
        onPrimary: .white, red: Color(hex: 0xBD4437))

    static let macchiato = InstrumentPalette(
        isDark: true, bg: Color(hex: 0x181926), panel: Color(hex: 0x24273A), panel2: Color(hex: 0x363A4F),
        text: Color(hex: 0xCAD3F5), muted: Color(hex: 0xA5ADCB), faint: Color(hex: 0x6E738D),
        line: Color(rgba: 0xFFFFFF12), line2: Color(rgba: 0xFFFFFF20), violet: Color(hex: 0xC6A0F6),
        lime: Color(hex: 0xA6DA95), onLime: Color(hex: 0x181926), primary: Color(hex: 0xCAD3F5),
        onPrimary: Color(hex: 0x181926), red: Color(hex: 0xED8796))

    static let latte = InstrumentPalette(
        isDark: false, bg: Color(hex: 0xEFF1F5), panel: Color(hex: 0xE6E9EF), panel2: Color(hex: 0xDCE0E8),
        text: Color(hex: 0x4C4F69), muted: Color(hex: 0x6C6F85), faint: Color(hex: 0x8C8FA1),
        line: Color(rgba: 0x4C4F6914), line2: Color(rgba: 0x4C4F6928), violet: Color(hex: 0x8839EF),
        lime: Color(hex: 0x40A02B), onLime: .white, primary: Color(hex: 0x4C4F69),
        onPrimary: .white, red: Color(hex: 0xD20F39))
}

private struct InkKey: EnvironmentKey {
    static let defaultValue = InstrumentPalette.night
}

extension EnvironmentValues {
    /// The active Instrument palette.
    var ink: InstrumentPalette {
        get { self[InkKey.self] }
        set { self[InkKey.self] = newValue }
    }
}

/// The four bundled typefaces (see Resources/Fonts and UIAppFonts).
enum InstrumentFont {
    static func body(_ size: CGFloat) -> Font { .custom("Inter-Regular", size: size) }
    static func medium(_ size: CGFloat) -> Font { .custom("Inter-Medium", size: size) }
    static func display(_ size: CGFloat) -> Font { .custom("SpaceGrotesk-Medium", size: size) }
    static func mono(_ size: CGFloat) -> Font { .custom("JetBrainsMono-Regular", size: size) }
}

extension Animation {
    /// The prototype's `cubic-bezier(.2,.8,.2,1)`: quick start, soft landing.
    static func instrument(_ duration: Double = 0.38) -> Animation {
        .timingCurve(0.2, 0.8, 0.2, 1, duration: duration)
    }
}

/// Persisted theme choice, shared by the root view and the More tab.
enum InstrumentThemeStore {
    static let key = "vela.instrumentTheme"
}
