import SwiftUI

/// Join an existing vault on this device using an enrollment code from a primary
/// device (the joining side of device enrollment). Mirrors Android's EnrollDevice.
struct EnrollView: View {
    @ObservedObject var vault: VaultViewModel
    @ObservedObject var account: AccountViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var serverURL = "https://vault.klyt.eu"
    @State private var code = ""
    @State private var usePassword = false
    @State private var password = ""
    @State private var confirm = ""
    @State private var codeConfirmed = false
    /// Shown to the enrolling user on the other device, so they can tell which
    /// device is asking. Editable, like the register and recover screens.
    @State private var deviceName = "iPhone"

    /// Out-of-band verification code for the pasted/scanned enrollment code.
    /// Neither device can otherwise prove the code wasn't substituted (a
    /// tampered QR, or simply the wrong code), so the user must confirm this
    /// matches what's shown on the enrolling device before joining.
    /// A v3 code has nothing to verify at this point: the value the user
    /// compares is derived from a key this device has not generated until it
    /// claims the grant. A v2-style digest of a v3 code would be a number that
    /// means nothing, confirmed by a toggle that attests to nothing.
    private var isV3Code: Bool {
        EnrollmentCode.looksLikeV3(code)
    }

    private var verificationCode: String? {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isV3Code else { return nil }
        let value = VelaCoreFFI.enrollmentVerificationCode(trimmed)
        return value.isEmpty ? nil : value
    }

    /// A non-v3 code is the legacy v1/v2 format, which embeds the device
    /// signing key and RMS transfer key *in the code itself*. Interception is
    /// therefore as bad as theft — the verification digest proves the code
    /// wasn't substituted, not that nobody copied it.
    private var hasLegacyCode: Bool {
        !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isV3Code
    }

    private var canJoin: Bool {
        guard !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        guard codeConfirmed || isV3Code else { return false }
        if usePassword { return password.count >= 8 && password == confirm }
        return true
    }

    var body: some View {
        NavigationStack {
            Form {
                if let fingerprint = account.joinFingerprint {
                    Section("Confirm on your other device") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Your other device is now showing several codes. Pick this one on it:")
                                .font(.callout)
                            Text(fingerprint)
                                .font(.system(.title2, design: .monospaced).bold())
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.vertical, 8)
                                .accessibilityIdentifier("joinFingerprint")
                            // Why picking it elsewhere means anything: only this
                            // device could have produced it.
                            Text("This code is computed on this device from the key it just generated for itself. Nobody else can produce it, which is what makes picking it on your other device mean something.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("Waiting for confirmation…")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Section("Server") {
                    TextField("Server URL", text: $serverURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .accessibilityIdentifier("enrollServerField")
                }
                Section("Enrollment code") {
                    TextField("Paste the code from your other device", text: $code, axis: .vertical)
                        .lineLimit(2...5)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("enrollCodeField")
                        .onChange(of: code) { _ in codeConfirmed = false }
                }
                if let verificationCode = verificationCode {
                    Section {
                        VStack(alignment: .leading, spacing: 6) {
                            Label("Verify this code", systemImage: "checkmark.shield")
                                .font(.subheadline.bold())
                                .foregroundStyle(.orange)
                            Text("Compare against the verification code shown on your other device's \"Enrollment Code\" dialog. If it doesn't match, stop.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(verificationCode)
                                .font(.system(.title3, design: .monospaced).bold())
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.vertical, 4)
                                .accessibilityIdentifier("enrollVerificationCode")
                            Toggle("It matches the code on my other device", isOn: $codeConfirmed)
                                .font(.caption)
                                .accessibilityIdentifier("enrollCodeConfirmedToggle")
                        }
                    }
                }
                if hasLegacyCode {
                    Section {
                        VStack(alignment: .leading, spacing: 6) {
                            Label("Legacy enrollment code", systemImage: "exclamationmark.triangle.fill")
                                .font(.subheadline.bold())
                                .foregroundStyle(.red)
                            Text("This is an older-style enrollment code, and it carries your vault's key material inside the code itself. Anyone who captured it — a photo, clipboard history, a message relay — can join your vault without your approval. The verification code below proves the code wasn't swapped, not that nobody copied it.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("Only continue if you handed this code over directly, device to device, just now. If it travelled by any other route, cancel and generate a fresh code on your other device.")
                                .font(.caption.bold())
                        }
                        .accessibilityIdentifier("legacyCodeWarning")
                    }
                }
                if isV3Code {
                    Section("This device") {
                        TextField("Device name", text: $deviceName)
                            .accessibilityIdentifier("enrollDeviceNameField")
                    }
                }
                Section("Secure on this device") {
                    Toggle("Protect with password", isOn: $usePassword)
                    if usePassword {
                        SecureField("Password (8+)", text: $password)
                            .accessibilityIdentifier("enrollPasswordField")
                        SecureField("Confirm password", text: $confirm)
                    } else {
                        Text("This device will unlock with Face ID / Touch ID.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section {
                    Button(isV3Code ? "Continue" : "Join") {
                        // Which flow runs is decided by the code's own prefix,
                        // never guessed: a v2 and a v3 install have to keep
                        // enrolling each other until old builds age out.
                        if isV3Code {
                            account.joinWithV3Code(
                                serverURL: serverURL, code: code,
                                deviceName: deviceName,
                                secure: usePassword ? .password : .biometric,
                                password: usePassword ? password : nil)
                        } else {
                            account.joinWithCode(
                                serverURL: serverURL, code: code,
                                secure: usePassword ? .password : .biometric,
                                password: usePassword ? password : nil)
                        }
                    }
                    .disabled(!canJoin || account.busy)
                    .accessibilityIdentifier("joinButton")
                }
                if !account.status.isEmpty {
                    Section { Text(account.status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Join device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onChange(of: vault.lockState) { state in
                if state == .unlocked { dismiss() } // joined successfully
            }
        }
        .preferredColorScheme(.dark)
    }
}
