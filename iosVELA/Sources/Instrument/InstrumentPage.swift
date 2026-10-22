import SwiftUI
import UIKit

/// Scaffold for secondary screens: Instrument background, hidden system bar,
/// back header and a scrolling column with the standard insets.
struct InstrumentScreenScaffold<Content: View>: View {
    let backTitle: String
    var showsBack: Bool = true
    @ViewBuilder var content: () -> Content

    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if showsBack {
                        BackHead(title: backTitle) { dismiss() }.arrive(0)
                    }
                    content()
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
            .scrollDismissesKeyboard(.interactively)
        }
        .toolbar(.hidden, for: .navigationBar)
    }
}

/// Mono label over a 48pt bordered input. Violet hairline while focused.
struct LabeledInput: View {
    let label: String
    @Binding var text: String
    var placeholder: String = ""
    var id: String? = nil
    var secure: Bool = false
    var mono: Bool = false
    var keyboard: UIKeyboardType = .default

    @Environment(\.ink) private var ink
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            MonoLabel(label)
            Group {
                if secure {
                    SecureField("", text: $text, prompt: Text(placeholder).foregroundColor(ink.faint))
                } else {
                    TextField("", text: $text, prompt: Text(placeholder).foregroundColor(ink.faint))
                }
            }
            .font(mono ? InstrumentFont.mono(12) : InstrumentFont.body(12))
            .foregroundColor(ink.text)
            .tint(ink.violet)
            .keyboardType(keyboard)
            .textInputAutocapitalization(keyboard == .default && !mono ? TextInputAutocapitalization.sentences : TextInputAutocapitalization.never)
            .disableAutocorrection(mono || keyboard != .default)
            .focused($focused)
            .accessibilityLabel(label)
            .accessibilityIdentifier(id ?? label)
            .padding(.horizontal, 12)
            .frame(minHeight: 48)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(ink.panel))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(focused ? ink.violet : ink.line2, lineWidth: 1))
            .animation(.easeOut(duration: 0.18), value: focused)
        }
        .padding(.bottom, 14)
    }
}

/// Outline pill in the error colour, for destructive actions.
struct DangerPill: View {
    let text: String
    var icon: InstrumentIconName? = .trash
    var fullWidth: Bool = false
    let action: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let icon { InstrumentIcon(name: icon, size: 14, color: ink.red) }
                Text(text).font(InstrumentFont.body(12)).foregroundColor(ink.red).lineLimit(1)
            }
            .padding(.horizontal, 14)
            .frame(minHeight: fullWidth ? 44 : 36)
            .frame(maxWidth: fullWidth ? .infinity : nil)
            .overlay(Capsule().stroke(ink.red.opacity(0.3), lineWidth: 1))
            .contentShape(Capsule())
        }
        .buttonStyle(PressScaleStyle())
    }
}

/// Row for a NavigationLink inside an InstrumentGroup (icon, label, meta, chevron).
struct InstrumentLinkLabel: View {
    let icon: InstrumentIconName?
    let label: String
    var meta: String? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        HStack(spacing: 12) {
            if let icon { InstrumentIcon(name: icon, size: 17, color: ink.muted) }
            Text(label).font(InstrumentFont.body(12)).foregroundColor(ink.text)
            Spacer(minLength: 8)
            if let meta { Text(meta).font(InstrumentFont.mono(9)).foregroundColor(ink.muted) }
            InstrumentIcon(name: .chev, size: 14, color: ink.muted)
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 55)
        .contentShape(Rectangle())
    }
}

/// Label/value row inside a group (read-only facts like versions and IDs).
struct InstrumentFactRow: View {
    let label: String
    let value: String
    var copyValue: String? = nil
    var onCopy: ((String) -> Void)? = nil

    @Environment(\.ink) private var ink

    var body: some View {
        HStack(spacing: 12) {
            Text(label).font(InstrumentFont.body(12)).foregroundColor(ink.muted)
            Spacer(minLength: 8)
            Text(value).font(InstrumentFont.mono(10)).foregroundColor(ink.text).lineLimit(1).truncationMode(.middle)
            if let copyValue, let onCopy {
                InstrumentIconButton(icon: .copy, label: "Copy \(label.lowercased())", size: 32, iconSize: 14,
                                     bordered: false, tint: ink.muted) { onCopy(copyValue) }
            }
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }
}
