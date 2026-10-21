import SwiftUI

/// Approve a browser's temporary, revocable web access to this vault
/// (EPHEMERAL_WEB_ACCESS_DESIGN.md). Paste the code shown by the web page, pick a
/// duration, and approve. Read-only is the default; read-write is behind an
/// explicit "I trust this device" toggle.
struct WebAccessView: View {
    @ObservedObject var account: AccountViewModel

    @State private var code: String = ""
    @State private var ttlSecs: Int = 30 * 60
    @State private var showAdvanced = false
    @State private var mode: String = "ro"

    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    private struct DurationChoice: Identifiable {
        let label: String
        let seconds: Int
        var id: Int { seconds }
    }

    private let ttlOptions: [DurationChoice] = [
        DurationChoice(label: "30 minutes", seconds: 30 * 60),
        DurationChoice(label: "1 hour", seconds: 60 * 60),
        DurationChoice(label: "8 hours", seconds: 8 * 60 * 60),
        DurationChoice(label: "24 hours", seconds: 24 * 60 * 60),
    ]

    private var trimmedCode: String {
        code.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    BackHead(title: "Devices / Web access") { dismiss() }
                        .arrive(0)

                    InstrumentHeading(eyebrow: "Web access",
                                      title: "Approve a browser.",
                                      subtitle: "Enter the code shown in the browser to give it temporary access.")
                        .arrive(1)

                    FineText("Temporarily open this vault in a browser — no install, no permanent device. "
                             + "Access expires automatically and can be revoked any time.")
                        .padding(.bottom, 4)
                        .arrive(2)

                    GroupLabel(text: "01 / Access code")
                        .arrive(3)
                    codeField
                        .arrive(4)

                    GroupLabel(text: "02 / Duration")
                        .arrive(5)
                    InstrumentGroup {
                        InstrumentControlRow(label: "Expires after") {
                            Picker("Expires after", selection: $ttlSecs) {
                                ForEach(ttlOptions) { option in
                                    Text(option.label).tag(option.seconds)
                                }
                            }
                            .labelsHidden()
                            .tint(ink.text)
                        }
                    }
                    .arrive(6)

                    GroupLabel(text: "03 / Permissions")
                        .arrive(7)
                    permissions

                    InstrumentPill(text: account.busy ? "Approving…" : "Approve",
                                   icon: .check,
                                   style: .primary,
                                   fullWidth: true,
                                   enabled: !account.busy && !trimmedCode.isEmpty) {
                        account.grantWebAccess(codeJSON: code, mode: mode, ttlSecs: ttlSecs)
                    }
                    .padding(.top, 12)
                    .accessibilityIdentifier("approveWebAccessButton")
                    .arrive(9)

                    if !account.status.isEmpty {
                        FineText(account.status, size: 10)
                            .padding(.top, 8)
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

    private var codeField: some View {
        VStack(alignment: .leading, spacing: 8) {
            MonoLabel("Code from the browser")
            TextEditor(text: $code)
                .font(InstrumentFont.mono(12))
                .foregroundColor(ink.text)
                .tint(ink.violet)
                .scrollContentBackground(.hidden)
                .accessibilityLabel("Web access code")
                .accessibilityIdentifier("webAccessCodeField")
                .frame(minHeight: 96)
                .padding(.horizontal, 8)
                .padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(ink.panel))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(ink.line2, lineWidth: 1))
        }
    }

    @ViewBuilder private var permissions: some View {
        if showAdvanced {
            InstrumentGroup {
                InstrumentControlRow(label: "Mode") {
                    Picker("Mode", selection: $mode) {
                        Text("Read-only").tag("ro")
                        Text("Read & write").tag("rw")
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(maxWidth: 190)
                }
                if mode == "rw" {
                    GroupDivider()
                    FineText("Read & write lets the browser change the vault for this "
                             + "session: it receives per-chunk vault keys, but never "
                             + "the master key itself, and the grant expires with the "
                             + "session. Only approve it on a device you trust.",
                             size: 10,
                             color: ink.red)
                        .padding(15)
                }
            }
        } else {
            InstrumentPill(text: "Advanced — I trust this device",
                           style: .outline,
                           fullWidth: true) {
                showAdvanced = true
            }
        }
    }
}
