import SwiftUI

/// Phase 4 account screen: register/enroll this device with the VELA server,
/// authenticate, sync the vault, share items, and set up recovery.
struct AccountView: View {
    @ObservedObject var vm: AccountViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var serverURL = "https://vault.klyt.eu"
    @State private var deviceName = "iPhone"
    @State private var recipientUserID = ""
    @State private var selectedItemID = ""

    var body: some View {
        NavigationStack {
            Form {
                if let account = vm.account {
                    registeredSections(account)
                } else {
                    registerSection
                }

                if !vm.status.isEmpty {
                    Section {
                        Text(vm.status)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("accountStatus")
                    }
                }
            }
            .navigationTitle("Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .disabled(vm.busy)
        }
    }

    private var registerSection: some View {
        Section("Enroll this device") {
            TextField("Server URL", text: $serverURL)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                .accessibilityIdentifier("serverURLField")
            TextField("Device name", text: $deviceName)
                .accessibilityIdentifier("deviceNameField")
            Button("Register") { vm.register(serverURL: serverURL, deviceName: deviceName) }
                .accessibilityIdentifier("registerButton")
        }
    }

    @ViewBuilder
    private func registeredSections(_ account: AccountState) -> some View {
        Section("Device") {
            labeled("Server", account.serverURL)
            labeled("User", String(account.userID.prefix(8)) + "…")
            labeled("Device", String(account.deviceID.prefix(8)) + "…")
        }

        Section("Session") {
            Button("Authenticate") { vm.login() }
                .accessibilityIdentifier("authenticateButton")
            Button("Sync now") { vm.syncNow() }
                .accessibilityIdentifier("syncButton")
        }

        Section("Share an item") {
            if vm.vaultItems.isEmpty {
                Text("No items to share").foregroundStyle(.secondary)
            } else {
                Picker("Item", selection: $selectedItemID) {
                    Text("Select…").tag("")
                    ForEach(vm.vaultItems) { item in
                        Text(item.name).tag(item.id)
                    }
                }
                TextField("Recipient user id (UUID)", text: $recipientUserID)
                    .textInputAutocapitalization(.never)
                    .accessibilityIdentifier("recipientField")
                Button("Share") {
                    if let item = vm.vaultItems.first(where: { $0.id == selectedItemID }) {
                        vm.share(item: item, recipientUserID: recipientUserID)
                    }
                }
                .disabled(selectedItemID.isEmpty || recipientUserID.isEmpty)
                .accessibilityIdentifier("shareButton")
            }
        }

        Section("Recovery") {
            Button("Set up recovery (2-of-3)") { vm.setupRecovery() }
                .accessibilityIdentifier("recoveryButton")
            ForEach(Array(vm.recoveryShares.enumerated()), id: \.offset) { index, share in
                VStack(alignment: .leading) {
                    Text("Guardian share \(index + 1)").font(.caption).foregroundStyle(.secondary)
                    Text(share).font(.caption.monospaced()).textSelection(.enabled).lineLimit(2)
                }
            }
        }

        Section {
            Button("Sign out", role: .destructive) { vm.signOut() }
                .accessibilityIdentifier("signOutButton")
        }
    }

    private func labeled(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
        }
    }
}
