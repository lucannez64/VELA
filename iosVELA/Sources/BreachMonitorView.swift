import SwiftUI
import UIKit

/// Breach monitor: check stored passwords against Pwned Passwords (k-anonymity)
/// and look up an email in Have I Been Pwned.
struct BreachMonitorView: View {
    @StateObject private var vm: BreachViewModel
    @State private var email = ""

    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    init(vault: VaultViewModel) {
        _vm = StateObject(wrappedValue: BreachViewModel(vault: vault))
    }

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    BackHead(title: "Security / Breach watch") { dismiss() }
                        .arrive(0)

                    InstrumentHeading(eyebrow: "02 / Security",
                                      title: "Breach watch.",
                                      subtitle: "Checks your email and passwords against known breaches without revealing them.")
                        .arrive(1)

                    GroupLabel(text: "01 / Stored passwords")
                        .arrive(2)
                    InstrumentGroup {
                        InstrumentPill(text: "Check stored passwords", icon: .shield,
                                       style: .primary, fullWidth: true, enabled: !vm.busy) {
                            vm.checkAllPasswords()
                        }
                        .padding(15)
                        .accessibilityIdentifier("checkPasswordsButton")
                        GroupDivider()
                        if vm.passwordResults.isEmpty {
                            FineText("No passwords checked yet.", size: 10)
                                .padding(15)
                        } else {
                            ForEach(vm.passwordResults.indices, id: \.self) { index in
                                if index > 0 { GroupDivider() }
                                passwordRow(vm.passwordResults[index])
                            }
                        }
                    }
                    .arrive(3)

                    GroupLabel(text: "02 / Email monitoring")
                        .arrive(4)
                    BreachField(label: "Email address", text: $email,
                                keyboard: .emailAddress, id: "breachEmailField")
                    InstrumentPill(text: "Check email", icon: .mail,
                                   style: .primary, fullWidth: true,
                                   enabled: !vm.busy && !email.isEmpty) {
                        vm.checkEmail(email)
                    }
                    .padding(.top, 10)
                    .arrive(5)

                    InstrumentGroup {
                        if vm.emailBreaches.isEmpty {
                            FineText("No email checked yet.", size: 10)
                                .padding(15)
                        } else {
                            ForEach(vm.emailBreaches.indices, id: \.self) { index in
                                if index > 0 { GroupDivider() }
                                emailRow(vm.emailBreaches[index])
                            }
                        }
                    }
                    .padding(.top, 12)
                    .arrive(6)

                    FineText("Passwords are checked privately: only the first 5 characters of each SHA-1 hash are sent (k-anonymity).",
                             size: 10)
                        .padding(.top, 2)
                        .arrive(7)

                    if !vm.status.isEmpty {
                        FineText(vm.status, size: 10)
                            .padding(.top, 8)
                            .accessibilityIdentifier("breachStatus")
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    private func passwordRow(_ result: BreachViewModel.PasswordResult) -> some View {
        HStack(spacing: 11) {
            InstrumentIcon(name: result.breached ? InstrumentIconName.shield : InstrumentIconName.check,
                           size: 16,
                           color: result.breached ? ink.red : ink.lime)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 4) {
                Text(result.name)
                    .font(InstrumentFont.body(12))
                    .foregroundColor(ink.text)
                    .lineLimit(1)
                FineText(result.breached ? "Exposed \(result.count)×" : "Safe",
                         size: 10,
                         color: result.breached ? ink.red : ink.muted)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 55)
    }

    private func emailRow(_ breach: EmailBreach) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(breach.title.isEmpty ? breach.name : breach.title)
                .font(InstrumentFont.body(12))
                .foregroundColor(ink.text)
                .fixedSize(horizontal: false, vertical: true)
            FineText("\(breach.domain) · \(breach.breachDate)", size: 10)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 55)
    }
}

/// Input styled like the editor's `EditorField`, but without a FocusState.
private struct BreachField: View {
    let label: String
    @Binding var text: String
    var keyboard: UIKeyboardType = .default
    let id: String

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            MonoLabel(label)
            TextField("", text: $text)
                .font(InstrumentFont.body(12))
                .foregroundColor(ink.text)
                .tint(ink.violet)
                .keyboardType(keyboard)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .accessibilityLabel(label)
                .accessibilityIdentifier(id)
                .padding(.horizontal, 12)
                .frame(minHeight: 48)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(ink.panel))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(ink.line2, lineWidth: 1))
        }
        .id(id)
    }
}
