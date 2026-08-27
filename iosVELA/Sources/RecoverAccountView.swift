import SwiftUI

/// Recover an account on a brand-new device when every enrolled device has
/// been lost (SPEC.md §4.3) — reconstructs the RMS from Share 1 (pasted from
/// wherever the user stored it during recovery setup) + Share 2 (released by
/// the server after a WebAuthn security-key assertion), then registers this
/// device and pulls the vault down. Mirrors `EnrollView`'s shape.
struct RecoverAccountView: View {
    @ObservedObject var vault: VaultViewModel
    @ObservedObject var account: AccountViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var serverURL = "https://vault.klyt.eu"
    @State private var userID = ""
    @State private var share1 = ""
    @State private var deviceName = "iPhone"
    @State private var usePassword = false
    @State private var password = ""
    @State private var confirm = ""
    @State private var foundICloudBackup = false
    @State private var share1Epoch: Int?
    @State private var share1EpochText = ""
    @State private var iCloudShare1 = ""
    @State private var share1UserID: String?
    @State private var share1SplitID = ""

    private var canRecover: Bool {
        guard !userID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        guard !share1.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        guard (Int(share1EpochText) ?? 0) >= 1 else { return false }
        if usePassword { return password.count >= 8 && password == confirm }
        return true
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("Server URL", text: $serverURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .accessibilityIdentifier("recoverServerField")
                }
                Section("Account") {
                    TextField("Account ID (UUID)", text: $userID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("recoverUserIDField")
                }
                Section("Share 1") {
                    if foundICloudBackup {
                        Label("Found in iCloud", systemImage: "checkmark.icloud")
                            .font(.caption).foregroundStyle(.green)
                    }
                    TextField("Paste your recovery Share 1", text: $share1, axis: .vertical)
                        .lineLimit(2...5)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("recoverShare1Field")
                        .onChange(of: share1) { value in
                            if foundICloudBackup && value != iCloudShare1 {
                                foundICloudBackup = false
                                share1UserID = nil
                                share1SplitID = ""
                                share1Epoch = nil
                                share1EpochText = ""
                            }
                        }
                    TextField("Recovery share epoch", text: $share1EpochText)
                        .keyboardType(.numberPad)
                        .accessibilityIdentifier("recoverShare1EpochField")
                        .onChange(of: share1EpochText) { value in
                            let digits = value.filter { $0.isNumber }
                            if digits != value { share1EpochText = digits }
                            share1Epoch = Int(digits)
                        }
                    TextField("Recovery split ID (blank for legacy)", text: $share1SplitID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("recoverShare1SplitIDField")
                    Text(
                        foundICloudBackup
                            ? "Backed up automatically to this iCloud account during recovery setup. Edit only if this isn't the right one."
                            : "No backup found in this iCloud account — paste it from wherever you stored it during recovery setup."
                    )
                    .font(.caption).foregroundStyle(.secondary)
                }
                Section("This device") {
                    TextField("Device name", text: $deviceName)
                        .accessibilityIdentifier("recoverDeviceNameField")
                    Toggle("Protect with password", isOn: $usePassword)
                    if usePassword {
                        SecureField("Password (8+)", text: $password)
                            .accessibilityIdentifier("recoverPasswordField")
                        SecureField("Confirm password", text: $confirm)
                    } else {
                        Text("This device will unlock with Face ID / Touch ID.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section {
                    Text("You'll be asked to verify with the security key you registered for recovery.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Recover account") {
                        account.restoreAccount(
                            serverURL: serverURL, userID: userID.trimmingCharacters(in: .whitespacesAndNewlines),
                            cloudUserID: share1UserID ?? userID.trimmingCharacters(in: .whitespacesAndNewlines),
                            cloudSplitID: share1SplitID.isEmpty ? nil : share1SplitID,
                            share1Base64: share1.trimmingCharacters(in: .whitespacesAndNewlines),
                            share1Epoch: share1Epoch,
                            secure: usePassword ? .password : .biometric,
                            password: usePassword ? password : nil,
                            deviceName: deviceName)
                    }
                    .disabled(!canRecover || account.busy)
                    .accessibilityIdentifier("recoverAccountButton")
                }
                if !account.status.isEmpty {
                    Section { Text(account.status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Recover account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onChange(of: vault.lockState) { state in
                if state == .unlocked { dismiss() } // recovered successfully
            }
            .onAppear {
                // iCloud Key-Value Storage sync is local/synchronous — no
                // consent screen or network round trip, unlike Android's
                // Drive OAuth flow — so this can just pre-fill on appear.
                guard let storedUserID = CloudRecoveryBackup.storedUserID() else { return }
                if let backup = CloudRecoveryBackup.download(userID: storedUserID) {
                    userID = storedUserID
                    share1UserID = backup.userID
                    share1SplitID = backup.splitID ?? ""
                    iCloudShare1 = backup.shareBase64
                    share1Epoch = backup.keyEpoch
                    share1EpochText = String(backup.keyEpoch)
                    foundICloudBackup = true
                    share1 = backup.shareBase64
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
