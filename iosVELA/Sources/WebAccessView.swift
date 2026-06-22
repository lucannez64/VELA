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

    private let ttlOptions: [(String, Int)] = [
        ("30 minutes", 30 * 60),
        ("1 hour", 60 * 60),
        ("8 hours", 8 * 60 * 60),
        ("24 hours", 24 * 60 * 60),
    ]

    var body: some View {
        Form {
            Section {
                Text("Temporarily open this vault in a browser — no install, no permanent device. "
                    + "Access expires automatically and can be revoked any time.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section("Web access code") {
                TextEditor(text: $code)
                    .frame(minHeight: 90)
                    .font(.system(.footnote, design: .monospaced))
                    .accessibilityIdentifier("webAccessCodeField")
            }

            Section("Duration") {
                Picker("Expires after", selection: $ttlSecs) {
                    ForEach(ttlOptions, id: \.1) { label, secs in
                        Text(label).tag(secs)
                    }
                }
            }

            Section {
                if showAdvanced {
                    Picker("Mode", selection: $mode) {
                        Text("Read-only").tag("ro")
                        Text("Read & write").tag("rw")
                    }
                    .pickerStyle(.segmented)
                    if mode == "rw" {
                        Text("Read & write sends this device's master key to the browser for the "
                            + "session. Only use it on a device you trust.")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                } else {
                    Button("Advanced — I trust this device") { showAdvanced = true }
                }
            }

            Section {
                Button {
                    account.grantWebAccess(codeJSON: code, mode: mode, ttlSecs: ttlSecs)
                } label: {
                    Text(account.busy ? "Approving…" : "Approve")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(account.busy || code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier("approveWebAccessButton")

                if !account.status.isEmpty {
                    Text(account.status).font(.callout).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Web Access")
    }
}
