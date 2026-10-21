import SwiftUI
import UIKit

// SwiftUI port of the Instrument components (Android: ui/components/Instrument.kt).
// Sizes are the prototype's CSS pixels, which map 1:1 to points on iPhone.

// MARK: - Motion

/// Gentle press feedback: scales to 97% while held.
struct PressScaleStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// Staggered arrival: fades and lifts into place `index * 45ms` after appearing.
private struct Arrive: ViewModifier {
    let index: Int
    let distance: CGFloat
    @State private var shown = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .opacity(shown || reduceMotion ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : distance)
            .onAppear {
                guard !shown else { return }
                withAnimation(.instrument(0.38).delay(Double(min(index, 12)) * 0.045)) { shown = true }
            }
    }
}

extension View {
    func arrive(_ index: Int = 0, distance: CGFloat = 10) -> some View {
        modifier(Arrive(index: index, distance: distance))
    }

    /// Bordered rounded panel used by tiles, fields and groups.
    func instrumentPanel(radius: CGFloat = 20, border: Color, fill: Color) -> some View {
        background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(fill))
            .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).stroke(border, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
    }
}

// MARK: - Type

struct MonoLabel: View {
    let text: String
    var color: Color? = nil
    var size: CGFloat = 9

    @Environment(\.ink) private var ink

    init(_ text: String, color: Color? = nil, size: CGFloat = 9) {
        self.text = text
        self.color = color
        self.size = size
    }

    var body: some View {
        Text(text.uppercased())
            .font(InstrumentFont.mono(size))
            .tracking(size * 0.1)
            .foregroundColor(color ?? ink.muted)
            .lineLimit(1)
    }
}

struct FineText: View {
    let text: String
    var size: CGFloat = 11
    var color: Color? = nil
    var alignment: TextAlignment = .leading

    @Environment(\.ink) private var ink

    init(_ text: String, size: CGFloat = 11, color: Color? = nil, alignment: TextAlignment = .leading) {
        self.text = text
        self.size = size
        self.color = color
        self.alignment = alignment
    }

    var body: some View {
        Text(text)
            .font(InstrumentFont.body(size))
            .lineSpacing(size * 0.4)
            .foregroundColor(color ?? ink.muted)
            .multilineTextAlignment(alignment)
    }
}

/// Eyebrow label, 33pt display title and optional subtitle (`.page-head`).
struct InstrumentHeading: View {
    let eyebrow: String
    let title: String
    var subtitle: String? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            MonoLabel(eyebrow)
            Text(title)
                .font(InstrumentFont.display(33))
                .tracking(-1.5)
                .lineSpacing(-2)
                .foregroundColor(ink.text)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 12)
            if let subtitle {
                FineText(subtitle).padding(.top, 10)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 4)
        .padding(.bottom, 22)
    }
}

struct SectionHead<Trailing: View>: View {
    let label: String
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack {
            MonoLabel(label)
            Spacer(minLength: 10)
            trailing()
        }
        .padding(.top, 23)
        .padding(.bottom, 12)
    }
}

extension SectionHead where Trailing == EmptyView {
    init(label: String) {
        self.label = label
        self.trailing = { EmptyView() }
    }
}

struct TextAction: View {
    let text: String
    let action: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        Button(action: action) {
            Text(text)
                .font(InstrumentFont.body(10))
                .foregroundColor(ink.muted)
                .padding(.vertical, 8)
                .contentShape(Rectangle())
        }
        .buttonStyle(PressScaleStyle())
    }
}

// MARK: - Controls

/// Round 44pt icon button with a hairline, the prototype's `.ibtn`.
struct InstrumentIconButton: View {
    let icon: InstrumentIconName
    let label: String
    var size: CGFloat = 44
    var iconSize: CGFloat = 18
    var bordered: Bool = true
    var tint: Color? = nil
    let action: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        Button(action: action) {
            InstrumentIcon(name: icon, size: iconSize, color: tint ?? ink.text)
                .frame(width: size, height: size)
                .overlay(Circle().stroke(bordered ? ink.line2 : Color.clear, lineWidth: 1))
                .contentShape(Circle())
        }
        .buttonStyle(PressScaleStyle())
        .accessibilityLabel(label)
    }
}

enum PillStyle {
    case outline, primary, signal
}

struct InstrumentPill: View {
    let text: String
    var icon: InstrumentIconName? = nil
    var style: PillStyle = .outline
    var iconTrailing: Bool = false
    var fullWidth: Bool = false
    var enabled: Bool = true
    let action: () -> Void

    @Environment(\.ink) private var ink

    private var fill: Color {
        switch style {
        case .primary: return ink.primary
        case .signal: return ink.lime
        case .outline: return Color.clear
        }
    }

    private var foreground: Color {
        switch style {
        case .primary: return ink.onPrimary
        case .signal: return ink.onLime
        case .outline: return ink.text
        }
    }

    private var border: Color {
        switch style {
        case .primary: return ink.primary
        case .signal: return ink.lime
        case .outline: return ink.line2
        }
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let icon, !iconTrailing {
                    InstrumentIcon(name: icon, size: 15, color: foreground)
                }
                Text(text)
                    .font(InstrumentFont.body(12))
                    .foregroundColor(foreground)
                    .lineLimit(1)
                if let icon, iconTrailing {
                    InstrumentIcon(name: icon, size: 15, color: foreground)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 11)
            .frame(minHeight: 44)
            .frame(maxWidth: fullWidth ? .infinity : nil)
            .background(Capsule().fill(fill))
            .overlay(Capsule().stroke(border, lineWidth: 1))
            .contentShape(Capsule())
        }
        .buttonStyle(PressScaleStyle())
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.45)
    }
}

struct InstrumentChip: View {
    let text: String
    let selected: Bool
    let action: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        Button(action: action) {
            Text(text)
                .font(InstrumentFont.body(10))
                .foregroundColor(selected ? ink.bg : ink.muted)
                .lineLimit(1)
                .padding(.horizontal, 13)
                .padding(.vertical, 8)
                .frame(minHeight: 44)
                .background(Capsule().fill(selected ? ink.text : Color.clear))
                .overlay(Capsule().stroke(selected ? ink.text : ink.line2, lineWidth: 1))
                .contentShape(Capsule())
                .animation(.easeOut(duration: 0.2), value: selected)
        }
        .buttonStyle(PressScaleStyle())
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// 38×23 switch: lime when on, the thumb slides over 200ms.
struct InstrumentToggle: View {
    @Binding var isOn: Bool
    let label: String

    @Environment(\.ink) private var ink

    var body: some View {
        Button {
            withAnimation(.instrument(0.2)) { isOn.toggle() }
        } label: {
            ZStack(alignment: isOn ? .trailing : .leading) {
                Capsule().fill(isOn ? ink.lime : ink.panel2)
                Capsule().stroke(isOn ? ink.lime : ink.line2, lineWidth: 1)
                Circle()
                    .fill(isOn ? ink.onLime : ink.muted)
                    .frame(width: 17, height: 17)
                    .padding(3)
            }
            .frame(width: 38, height: 23)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        .accessibilityValue(isOn ? "On" : "Off")
    }
}

enum TagKind {
    case plain, ok, risk
}

struct InstrumentTag: View {
    let text: String
    var kind: TagKind = .plain

    @Environment(\.ink) private var ink

    var body: some View {
        let color: Color = kind == .ok ? ink.lime : (kind == .risk ? ink.red : ink.muted)
        Text(text.uppercased())
            .font(InstrumentFont.mono(8))
            .foregroundColor(color)
            .lineLimit(1)
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(kind == .plain ? ink.line2 : color.opacity(0.25), lineWidth: 1)
            )
    }
}

/// 39pt rounded tile holding an item's glyph, violet.
struct InstrumentAvatar: View {
    let icon: InstrumentIconName
    var large: Bool = false

    @Environment(\.ink) private var ink

    var body: some View {
        let size: CGFloat = large ? 60 : 39
        let radius: CGFloat = large ? 20 : 13
        InstrumentIcon(name: icon, size: large ? 25 : 18, color: ink.violet)
            .frame(width: size, height: size)
            .instrumentPanel(radius: radius, border: ink.line, fill: ink.panel2)
    }
}

/// List row: avatar, name, subtitle, REVIEW tag or lime star, chevron, hairline.
/// Not a Button, so its texts stay individually visible to UI tests.
struct InstrumentItemRow: View {
    let icon: InstrumentIconName
    let title: String
    let subtitle: String
    var needsReview: Bool = false
    var favorite: Bool = false
    let action: () -> Void

    @Environment(\.ink) private var ink
    @State private var pressed = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 11) {
                InstrumentAvatar(icon: icon)
                VStack(alignment: .leading, spacing: 5) {
                    Text(title)
                        .font(InstrumentFont.medium(13))
                        .foregroundColor(ink.text)
                        .lineLimit(1)
                    Text(subtitle)
                        .font(InstrumentFont.body(10))
                        .foregroundColor(ink.muted)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                if needsReview {
                    InstrumentTag(text: "Review", kind: .risk).padding(.trailing, 9)
                } else if favorite {
                    InstrumentIcon(name: .star, size: 13, color: ink.lime)
                        .padding(.trailing, 9)
                        .accessibilityLabel("Favourite")
                }
                InstrumentIcon(name: .chev, size: 15, color: ink.faint)
            }
            .padding(.horizontal, 3)
            .padding(.vertical, 12)
            .frame(minHeight: 69)
            Rectangle().fill(ink.line).frame(height: 1)
        }
        .background(RoundedRectangle(cornerRadius: 12).fill(pressed ? ink.panel : Color.clear))
        .scaleEffect(pressed ? 0.985 : 1)
        .animation(.easeOut(duration: 0.12), value: pressed)
        .contentShape(Rectangle())
        .onTapGesture(perform: action)
        .onLongPressGesture(minimumDuration: 0.4, maximumDistance: 8, perform: {}, onPressingChanged: { pressed = $0 })
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isButton)
    }
}

// MARK: - Surfaces

struct InstrumentTile: View {
    let icon: InstrumentIconName
    let title: String
    let caption: String
    let action: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 15) {
                InstrumentIcon(name: icon, size: 20, color: ink.violet)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(InstrumentFont.display(22))
                        .foregroundColor(ink.text)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                    FineText(caption, size: 10)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .instrumentPanel(radius: 20, border: ink.line, fill: ink.panel)
            .contentShape(RoundedRectangle(cornerRadius: 20))
        }
        .buttonStyle(PressScaleStyle())
    }
}

/// Rounded container for a section's rows, separated by hairlines.
struct InstrumentGroup<Content: View>: View {
    @ViewBuilder var content: () -> Content

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(spacing: 0, content: content)
            .instrumentPanel(radius: 20, border: ink.line, fill: ink.panel)
            .padding(.bottom, 12)
    }
}

struct GroupDivider: View {
    @Environment(\.ink) private var ink

    var body: some View {
        Rectangle().fill(ink.line).frame(height: 1)
    }
}

struct GroupLabel: View {
    let text: String

    @Environment(\.ink) private var ink

    var body: some View {
        MonoLabel(text, color: ink.faint)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 3)
            .padding(.top, 11)
            .padding(.bottom, 12)
    }
}

struct InstrumentMenuRow: View {
    let icon: InstrumentIconName?
    let label: String
    var meta: String? = nil
    let action: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                if let icon {
                    InstrumentIcon(name: icon, size: 17, color: ink.muted)
                }
                Text(label)
                    .font(InstrumentFont.body(12))
                    .foregroundColor(ink.text)
                Spacer(minLength: 8)
                if let meta {
                    Text(meta).font(InstrumentFont.mono(9)).foregroundColor(ink.muted)
                }
                InstrumentIcon(name: .chev, size: 14, color: ink.muted)
            }
            .padding(.horizontal, 15)
            .padding(.vertical, 12)
            .frame(minHeight: 55)
            .contentShape(Rectangle())
        }
        .buttonStyle(MenuRowStyle())
    }
}

private struct MenuRowStyle: ButtonStyle {
    @Environment(\.ink) private var ink

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(configuration.isPressed ? ink.panel2 : Color.clear)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

struct InstrumentControlRow<Trailing: View>: View {
    let label: String
    @ViewBuilder var trailing: () -> Trailing

    @Environment(\.ink) private var ink

    var body: some View {
        HStack {
            Text(label).font(InstrumentFont.body(12)).foregroundColor(ink.text)
            Spacer(minLength: 8)
            trailing()
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 55)
    }
}

// MARK: - Header

/// The dot "V" mark: two dot columns that converge.
struct BrandMark: View {
    var color: Color? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        let tint = color ?? ink.violet
        Canvas { context, size in
            let u = size.width / 20
            for y in 0..<8 {
                for x in 0..<2 {
                    var cx = 3 + CGFloat(x) * 14
                    if y >= 5 {
                        cx += (x == 1 ? -1 : 1) * CGFloat(y - 4) * 2
                    }
                    let cy = 2 + CGFloat(y) * 3
                    let r = 1.1 * u
                    context.fill(Path(ellipseIn: CGRect(x: cx * u - r, y: cy * u - r, width: r * 2, height: r * 2)), with: .color(tint))
                }
            }
        }
        .frame(width: 20, height: 26)
        .accessibilityLabel("VELA")
    }
}

enum InstrumentSyncState {
    case local, syncing, synced, failed
}

struct InstrumentBrand: View {
    var sync: InstrumentSyncState? = nil
    var trailingLabel: String? = nil
    var onLock: (() -> Void)? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        HStack(spacing: 0) {
            BrandMark()
            Text("VELA")
                .font(InstrumentFont.medium(13))
                .tracking(1.8)
                .foregroundColor(ink.text)
                .padding(.leading, 9)
            Spacer(minLength: 8)
            if let trailingLabel {
                MonoLabel(trailingLabel)
            }
            if let sync {
                SyncStatusView(state: sync).padding(.trailing, onLock == nil ? 0 : 12)
            }
            if let onLock {
                InstrumentIconButton(icon: .lock, label: "Lock vault", iconSize: 15, action: onLock)
                    .accessibilityIdentifier("brandLockButton")
            }
        }
        .frame(height: 44)
        .padding(.top, 5)
        .padding(.bottom, 24)
    }
}

private struct SyncStatusView: View {
    let state: InstrumentSyncState

    @Environment(\.ink) private var ink
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var dim = false

    private var appearance: (label: String, dot: Color) {
        switch state {
        case .syncing: return ("Syncing changes", ink.muted)
        case .failed: return ("Sync unavailable", ink.red)
        case .synced: return ("All changes synced", ink.lime)
        case .local: return ("On this device only", ink.muted)
        }
    }

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(appearance.dot).frame(width: 5, height: 5)
                .opacity(state == .syncing && dim ? 0.25 : 1)
            Text(appearance.label).font(InstrumentFont.mono(9)).foregroundColor(ink.muted).lineLimit(1)
        }
        .onAppear { pulse() }
        .onChange(of: state) { _ in pulse() }
    }

    private func pulse() {
        guard state == .syncing, !reduceMotion else { dim = false; return }
        withAnimation(.easeInOut(duration: 0.7).repeatForever(autoreverses: true)) { dim = true }
    }
}

/// Centred back header: `[←]  SECTION / PAGE`.
struct BackHead: View {
    let title: String
    let onBack: () -> Void

    var body: some View {
        ZStack {
            MonoLabel(title)
            HStack {
                InstrumentIconButton(icon: .back, label: "Back", action: onBack)
                    .accessibilityIdentifier("backButton")
                Spacer()
            }
        }
        .frame(minHeight: 44)
        .padding(.bottom, 22)
    }
}

// MARK: - Dock

struct InstrumentDockItem: Identifiable {
    let id: String
    let label: String
    let icon: InstrumentIconName
}

/// Floating pill navigation. The active fill slides between tabs.
struct InstrumentDock: View {
    let items: [InstrumentDockItem]
    @Binding var selection: String

    @Environment(\.ink) private var ink
    @Namespace private var namespace

    var body: some View {
        HStack(spacing: 3) {
            ForEach(items) { item in
                let active = item.id == selection
                Button {
                    guard !active else { return }
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    withAnimation(.spring(response: 0.36, dampingFraction: 0.82)) { selection = item.id }
                } label: {
                    VStack(spacing: 5) {
                        InstrumentIcon(name: item.icon, size: 18, color: active ? ink.violet : ink.muted)
                            .offset(y: active ? -1 : 0)
                        Text(item.label)
                            .font(InstrumentFont.body(9))
                            .foregroundColor(active ? ink.text : ink.muted)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, minHeight: 51)
                    .background {
                        if active {
                            Capsule().fill(ink.panel2).matchedGeometryEffect(id: "dock-fill", in: namespace)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(PressScaleStyle())
                .accessibilityIdentifier("dock-\(item.id)")
                .accessibilityLabel(item.label)
                .accessibilityAddTraits(active ? .isSelected : [])
            }
        }
        .padding(5)
        .background(Capsule().fill(ink.panel))
        .overlay(Capsule().stroke(ink.line2, lineWidth: 1))
        .shadow(color: ink.bg, radius: 12, x: 0, y: -8)
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }
}

// MARK: - Dot matrix

private let digitRows: [String] = [
    "11111/10001/10011/10101/11001/10001/11111", "00100/01100/00100/00100/00100/00100/01110",
    "11110/00001/00001/01110/10000/10000/11111", "11110/00001/00001/01110/00001/00001/11110",
    "10010/10010/10010/11111/00010/00010/00010", "11111/10000/10000/11110/00001/00001/11110",
    "01111/10000/10000/11110/10001/10001/01110", "11111/00001/00010/00100/01000/01000/01000",
    "01110/10001/10001/01110/10001/10001/01110", "01110/10001/10001/01111/00001/00001/11110",
]

/// Draws a 5×7 dot readout; `reveal` (0…1) lights columns left to right.
private struct DotMatrixCanvas: View, Animatable {
    let value: String
    let color: Color
    let pitch: CGFloat
    var reveal: CGFloat

    var animatableData: CGFloat {
        get { reveal }
        set { reveal = newValue }
    }

    var body: some View {
        let digits = Array(value)
        let columns = max(digits.count * 6 - 1, 1)
        return Canvas { context, size in
            let p = size.height / 7
            let lit = reveal * CGFloat(columns)
            for (index, char) in digits.enumerated() {
                guard let digit = char.wholeNumberValue, digit < digitRows.count else { continue }
                let rows = digitRows[digit].split(separator: "/")
                for (y, row) in rows.enumerated() {
                    for (x, bit) in row.enumerated() {
                        let col = index * 6 + x
                        let on = bit == "1" && CGFloat(col) <= lit
                        let r = p * 0.32
                        let cx = (CGFloat(col) + 0.5) * p
                        let cy = (CGFloat(y) + 0.5) * p
                        context.fill(Path(ellipseIn: CGRect(x: cx - r, y: cy - r, width: r * 2, height: r * 2)),
                                     with: .color(color.opacity(on ? 1 : 0.09)))
                    }
                }
            }
        }
        .frame(width: pitch * CGFloat(columns), height: pitch * 7)
    }
}

/// The prototype's dot-matrix numerals. Lights column by column on appear
/// and whenever the value changes.
struct DotMatrix: View {
    let value: String
    var color: Color? = nil
    var pitch: CGFloat = 5.5

    @Environment(\.ink) private var ink
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var reveal: CGFloat = 0

    var body: some View {
        DotMatrixCanvas(value: value, color: color ?? ink.violet, pitch: pitch, reveal: reduceMotion ? 1 : reveal)
            .onAppear { play() }
            .onChange(of: value) { _ in
                reveal = 0
                DispatchQueue.main.async { play() }
            }
            .accessibilityElement()
            .accessibilityLabel(value)
    }

    private func play() {
        withAnimation(.easeOut(duration: 0.42)) { reveal = 1 }
    }
}

// MARK: - Artwork

/// The hero sunrise drawn like the CSS:
/// `radial-gradient(ellipse 85% 90% at 83% 116%, #ffd7a1 0, #ff866a 17%,
/// #b58aff 42%, #5a4ad54d 65%, transparent 85%)` breathing over 9s, with the
/// 25pt ring texture centred off the bottom-right corner.
struct SunriseBackground: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30, paused: reduceMotion)) { timeline in
            let seconds = timeline.date.timeIntervalSinceReferenceDate
            // `breathe 9s ease-in-out infinite alternate`.
            let phase: CGFloat = reduceMotion ? 0 : CGFloat((1 - cos(seconds / 9 * Double.pi)) / 2)
            Canvas { context, size in
                let w = size.width
                let h = size.height
                context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(Color(hex: 0x09090F)))

                let center = CGPoint(x: w * 0.83, y: h * 1.16)
                let rx = w * 0.85
                let ry = h * 0.90
                let grow = 1 + 0.04 * phase
                var glow = context
                glow.opacity = Double(0.85 + 0.15 * phase)
                glow.translateBy(x: center.x, y: center.y)
                glow.scaleBy(x: grow, y: grow * ry / rx)
                let gradient = Gradient(stops: [
                    .init(color: Color(hex: 0xFFD7A1), location: 0),
                    .init(color: Color(hex: 0xFF866A), location: 0.17),
                    .init(color: Color(hex: 0xB58AFF), location: 0.42),
                    .init(color: Color(rgba: 0x5A4AD54D), location: 0.65),
                    .init(color: Color(hex: 0x5A4AD5, alpha: 0), location: 0.85),
                    .init(color: Color(hex: 0x5A4AD5, alpha: 0), location: 1),
                ])
                glow.fill(Path(ellipseIn: CGRect(x: -rx, y: -rx, width: rx * 2, height: rx * 2)),
                          with: .radialGradient(gradient, center: .zero, startRadius: 0, endRadius: rx))

                let ringCenter = CGPoint(x: w - 150, y: h + 60)
                var r: CGFloat = 25
                while r <= 300 {
                    context.stroke(Path(ellipseIn: CGRect(x: ringCenter.x - r, y: ringCenter.y - r, width: r * 2, height: r * 2)),
                                   with: .color(Color.white.opacity(0.043)), lineWidth: 1)
                    r += 25
                }
            }
        }
    }
}

/// Lock-screen halo: a soft bottom glow with two orbit rings that breathe.
struct LockOrbit<Content: View>: View {
    @ViewBuilder var content: () -> Content

    @Environment(\.ink) private var ink
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30, paused: reduceMotion)) { timeline in
            let seconds = timeline.date.timeIntervalSinceReferenceDate
            let t: CGFloat = reduceMotion ? 0 : CGFloat((1 - cos(seconds / 4.2 * Double.pi)) / 2)
            ZStack {
                Canvas { context, size in
                    let c = CGPoint(x: size.width / 2, y: size.height)
                    let rx = size.width * 0.55
                    let ry = size.height * 0.55
                    var glow = context
                    glow.translateBy(x: c.x, y: c.y)
                    glow.scaleBy(x: 1, y: ry / rx)
                    glow.fill(Path(ellipseIn: CGRect(x: -rx, y: -rx, width: rx * 2, height: rx * 2)),
                              with: .radialGradient(Gradient(colors: [Color(rgba: 0xCA9DECB0), Color(rgba: 0xCA9DEC00)]),
                                                    center: .zero, startRadius: 0, endRadius: rx))
                    let mid = CGPoint(x: size.width / 2, y: size.height / 2)
                    let r1 = 100 * (1 + 0.02 * t)
                    let r2 = 145 * (1 + 0.03 * t)
                    context.stroke(Path(ellipseIn: CGRect(x: mid.x - r1, y: mid.y - r1, width: r1 * 2, height: r1 * 2)),
                                   with: .color(ink.line2), lineWidth: 1)
                    context.stroke(Path(ellipseIn: CGRect(x: mid.x - r2, y: mid.y - r2, width: r2 * 2, height: r2 * 2)),
                                   with: .color(ink.line2.opacity(Double(1 - 0.4 * t))), lineWidth: 1)
                }
                content()
            }
        }
        .frame(height: 192)
        .padding(.horizontal, -20)
        .clipped()
    }
}

// MARK: - Toast

final class ToastCenter: ObservableObject {
    @Published private(set) var message: String?
    private var serial = 0

    func show(_ text: String) {
        serial += 1
        let current = serial
        withAnimation(.instrument(0.22)) { message = text }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.6) { [weak self] in
            guard let self, self.serial == current else { return }
            withAnimation(.easeOut(duration: 0.2)) { self.message = nil }
        }
    }
}

struct ToastOverlay: View {
    @ObservedObject var center: ToastCenter
    var bottomInset: CGFloat = 83

    @Environment(\.ink) private var ink

    var body: some View {
        VStack {
            Spacer()
            if let message = center.message {
                Text(message)
                    .font(InstrumentFont.body(11))
                    .foregroundColor(ink.text)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 15)
                    .padding(.vertical, 13)
                    .instrumentPanel(radius: 18, border: ink.line2, fill: ink.panel2)
                    .padding(.horizontal, 20)
                    .padding(.bottom, bottomInset)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .accessibilityIdentifier("toast")
            }
        }
        .allowsHitTesting(false)
    }
}

// MARK: - Search

/// Pill search field; the hairline turns violet while focused.
struct InstrumentSearchField: View {
    @Binding var text: String
    var placeholder: String = "Search your vault"

    @Environment(\.ink) private var ink
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 9) {
            InstrumentIcon(name: .search, size: 17, color: ink.muted)
            ZStack(alignment: .leading) {
                if text.isEmpty {
                    Text(placeholder).font(InstrumentFont.body(12)).foregroundColor(ink.faint)
                }
                TextField("", text: $text)
                    .font(InstrumentFont.body(12))
                    .foregroundColor(ink.text)
                    .tint(ink.violet)
                    .focused($focused)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .accessibilityLabel("Search your vault")
                    .accessibilityIdentifier("searchField")
            }
            if !text.isEmpty {
                InstrumentIconButton(icon: .x, label: "Clear search", size: 30, iconSize: 14, bordered: false, tint: ink.muted) {
                    text = ""
                }
            }
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 2)
        .frame(minHeight: 46)
        .background(Capsule().fill(ink.panel))
        .overlay(Capsule().stroke(focused ? ink.violet : ink.line2, lineWidth: 1))
        .animation(.easeOut(duration: 0.18), value: focused)
    }
}
