import SwiftUI
import UIKit

/// Password and passphrase generation for the Generate tab. Uses the system
/// CSPRNG (`SystemRandomNumberGenerator`) and guarantees one character from
/// every chosen group.
enum InstrumentGenerator {
    static let uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    static let lowercase = "abcdefghijkmnopqrstuvwxyz"
    static let digits = "23456789"
    static let symbols = "!@#$%&*+-=?"

    static let words: [String] = {
        guard let url = Bundle.main.url(forResource: "instrument-words", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return ["amber", "harbor", "velvet", "orbit", "lantern", "meadow", "quartz", "willow"]
        }
        let list = text.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.isEmpty }
        return list.isEmpty ? ["amber", "harbor", "velvet", "orbit"] : list
    }()

    static func password(length: Int, upper: Bool, lower: Bool, numbers: Bool, symbols useSymbols: Bool) -> String {
        var sets: [[Character]] = []
        if upper { sets.append(Array(uppercase)) }
        if lower { sets.append(Array(lowercase)) }
        if numbers { sets.append(Array(digits)) }
        if useSymbols { sets.append(Array(symbols)) }
        if sets.isEmpty { sets = [Array(lowercase)] }
        let alphabet = sets.flatMap { $0 }
        var rng = SystemRandomNumberGenerator()
        var chars = (0..<max(length, sets.count)).map { _ in alphabet.randomElement(using: &rng)! }
        for (i, set) in sets.enumerated() {
            chars[i] = set.randomElement(using: &rng)!
        }
        chars.shuffle(using: &rng)
        return String(chars)
    }

    static func passphrase(words count: Int) -> String {
        var rng = SystemRandomNumberGenerator()
        return (0..<count).map { _ in words.randomElement(using: &rng)! }.joined(separator: "-")
    }
}

struct GeneratorScreen: View {
    let sync: InstrumentSyncState
    let onSave: (String) -> Void

    @EnvironmentObject private var toast: ToastCenter
    @Environment(\.ink) private var ink

    @State private var phrase = false
    @State private var length = 20
    @State private var wordCount = 4
    @State private var upper = true
    @State private var lower = true
    @State private var numbers = true
    @State private var symbols = true
    @State private var value = InstrumentGenerator.password(length: 20, upper: true, lower: true, numbers: true, symbols: true)
    @State private var spins = 0
    @State private var settled = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                InstrumentBrand(sync: sync).arrive(0)
                InstrumentHeading(eyebrow: "02 / Generator", title: "A good kind\nof unpredictable.").arrive(1)
                HStack(spacing: 6) {
                    InstrumentChip(text: "Password", selected: !phrase) {
                        if phrase { phrase = false; regenerate() }
                    }
                    .accessibilityIdentifier("generatorPasswordChip")
                    InstrumentChip(text: "Passphrase", selected: phrase) {
                        if !phrase { phrase = true; regenerate() }
                    }
                    .accessibilityIdentifier("generatorPassphraseChip")
                }
                .padding(.vertical, 3)
                .arrive(2)
                readoutCard.padding(.vertical, 16).arrive(3)
                HStack {
                    MonoLabel(phrase ? "Words" : "Length")
                    Spacer()
                    Text("\(phrase ? wordCount : length)")
                        .font(InstrumentFont.mono(11))
                        .foregroundColor(ink.violet)
                        .contentTransition(.numericText())
                }
                .padding(.top, 7)
                .arrive(4)
                InstrumentSlider(
                    value: phrase ? $wordCount : $length,
                    range: phrase ? 3...8 : 8...40,
                    label: phrase ? "Word count" : "Password length"
                )
                .padding(.top, 8)
                .padding(.bottom, 16)
                .arrive(4)
                .onChange(of: length) { _ in if !phrase { refresh() } }
                .onChange(of: wordCount) { _ in if phrase { refresh() } }
                if phrase {
                    FineText("A few unexpected words. Easier to remember, harder to guess.").arrive(5)
                } else {
                    InstrumentGroup {
                        optionRow("Uppercase", $upper)
                        GroupDivider()
                        optionRow("Lowercase", $lower)
                        GroupDivider()
                        optionRow("Numbers", $numbers)
                        GroupDivider()
                        optionRow("Symbols", $symbols)
                    }
                    .arrive(5)
                }
                InstrumentPill(text: "Save as a new login", icon: .plus, style: .primary, fullWidth: true) {
                    onSave(value)
                }
                .accessibilityIdentifier("generatorSaveButton")
                .padding(.top, 16)
                .arrive(6)
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 100)
        }
        .scrollIndicators(.hidden)
    }

    private var readoutCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                MonoLabel(phrase ? "Passphrase" : "Password")
                Spacer()
                InstrumentIconButton(icon: .refresh, label: "Generate again", iconSize: 16) { regenerate() }
                    .rotationEffect(.degrees(Double(spins) * 180))
                    .animation(.instrument(0.45), value: spins)
                    .accessibilityIdentifier("generatorRefreshButton")
            }
            readout
                .frame(maxWidth: .infinity, minHeight: 118, alignment: .topLeading)
                .padding(.top, 8)
                .padding(.bottom, 20)
                .opacity(settled ? 1 : 0.4)
                .offset(y: settled ? 0 : 3)
            HStack {
                FineText("Generated on your device", size: 9)
                Spacer()
                InstrumentIconButton(icon: .copy, label: "Copy generated password", iconSize: 16) {
                    Clipboard.copySecurely(value)
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                    toast.show("Copied. Clears in 20 seconds.")
                }
                .accessibilityIdentifier("generatorCopyButton")
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 20)
        .instrumentPanel(radius: 22, border: ink.line2, fill: ink.panel)
    }

    /// Digits lime, symbols violet, letters in the text colour.
    private var readout: some View {
        var text = Text("")
        for char in value {
            let piece = Text(String(char))
            if char.isNumber {
                text = text + piece.foregroundColor(ink.lime)
            } else if !phrase && !char.isLetter && !char.isNumber {
                text = text + piece.foregroundColor(ink.violet)
            } else {
                text = text + piece.foregroundColor(ink.text)
            }
        }
        return text
            .font(InstrumentFont.mono(22))
            .tracking(-1.1)
            .lineSpacing(10)
            .accessibilityLabel(value)
            .accessibilityIdentifier("generatorValue")
    }

    private func optionRow(_ label: String, _ binding: Binding<Bool>) -> some View {
        InstrumentControlRow(label: label) {
            InstrumentToggle(isOn: Binding(
                get: { binding.wrappedValue },
                set: { on in
                    let active = [upper, lower, numbers, symbols].filter { $0 }.count
                    if on || active > 1 {
                        binding.wrappedValue = on
                        refresh()
                    } else {
                        toast.show("Keep at least one character type.")
                    }
                }
            ), label: label)
        }
    }

    private func generate() -> String {
        phrase
            ? InstrumentGenerator.passphrase(words: wordCount)
            : InstrumentGenerator.password(length: length, upper: upper, lower: lower, numbers: numbers, symbols: symbols)
    }

    /// New value with the settle animation (slider and option changes).
    private func refresh() {
        value = generate()
        settled = false
        DispatchQueue.main.async {
            withAnimation(.easeOut(duration: 0.18)) { settled = true }
        }
    }

    /// New value plus a half turn of the refresh button.
    private func regenerate() {
        UIImpactFeedbackGenerator(style: .soft).impactOccurred()
        spins += 1
        refresh()
    }
}

/// Thin range slider like the prototype's native input: 4pt track, round violet thumb.
struct InstrumentSlider: View {
    @Binding var value: Int
    let range: ClosedRange<Int>
    let label: String

    @Environment(\.ink) private var ink

    var body: some View {
        GeometryReader { geo in
            let span = CGFloat(max(range.upperBound - range.lowerBound, 1))
            let fraction = CGFloat(value - range.lowerBound) / span
            let r: CGFloat = 8
            let x = r + (geo.size.width - 2 * r) * fraction
            ZStack(alignment: .leading) {
                Capsule().fill(ink.line2).frame(height: 4).padding(.horizontal, r)
                Capsule().fill(ink.violet).frame(width: max(x - r, 0), height: 4).offset(x: r)
                Circle().fill(ink.violet).frame(width: r * 2, height: r * 2).offset(x: x - r)
            }
            .frame(height: 32)
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0).onChanged { drag in
                    let usable = max(geo.size.width - 2 * r, 1)
                    let f = min(max((drag.location.x - r) / usable, 0), 1)
                    let next = range.lowerBound + Int((f * span).rounded())
                    if next != value {
                        UISelectionFeedbackGenerator().selectionChanged()
                        value = next
                    }
                }
            )
            .animation(.easeOut(duration: 0.09), value: value)
        }
        .frame(height: 32)
        .accessibilityElement()
        .accessibilityLabel(label)
        .accessibilityValue("\(value)")
        .accessibilityAdjustableAction { direction in
            switch direction {
            case .increment: value = min(value + 1, range.upperBound)
            case .decrement: value = max(value - 1, range.lowerBound)
            @unknown default: break
            }
        }
    }
}
