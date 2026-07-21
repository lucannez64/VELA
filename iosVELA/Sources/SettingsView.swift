import SwiftUI
import UIKit

/// The settings hub: server sync, sharing, devices, vault security, and about.
struct SettingsView: View {
    @ObservedObject var vm: VaultViewModel
    @ObservedObject var accountVM: AccountViewModel
    @Environment(\.dismiss) private var dismiss

    @AppStorage("vela.syncOnStartup") private var syncOnStartup = false
    @AppStorage("vela.backgroundSyncMinutes") private var backgroundSyncMinutes = 5
    @State private var confirmReset = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Server sync") {
                    NavigationLink {
                        AccountView(vm: accountVM)
                    } label: {
                        HStack {
                            Text("Account")
                            Spacer()
                            Text(accountVM.isRegistered ? "Enrolled" : "Not set up")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("accountLink")
                    if accountVM.isRegistered {
                        Button("Sync now") { accountVM.syncNow() }
                            .accessibilityIdentifier("settingsSyncButton")
                        Toggle("Sync on unlock & foreground", isOn: $syncOnStartup)
                        Stepper("Auto-sync every \(backgroundSyncMinutes) min",
                                value: $backgroundSyncMinutes, in: 1...60)
                            .onChange(of: backgroundSyncMinutes) { _ in
                                accountVM.startPeriodicSync() // apply the new interval
                            }
                    }
                }

                Section("Sharing & devices") {
                    NavigationLink("Sharing") { SharingView(vault: vm, account: accountVM) }
                        .accessibilityIdentifier("sharingLink")
                    NavigationLink("Devices") { DevicesView(account: accountVM) }
                        .accessibilityIdentifier("devicesLink")
                    NavigationLink("Web access") { WebAccessView(account: accountVM) }
                        .accessibilityIdentifier("webAccessLink")
                }

                Section("Tools") {
                    NavigationLink("Breach Monitor") { BreachMonitorView(vault: vm) }
                        .accessibilityIdentifier("breachLink")
                    NavigationLink("Activity Log") { AuditLogView() }
                        .accessibilityIdentifier("auditLink")
                }

                Section("Security") {
                    Button("Lock vault") {
                        vm.lock()
                        dismiss()
                    }
                    .accessibilityIdentifier("lockVaultButton")
                    Button("Reset local security", role: .destructive) { confirmReset = true }
                        .accessibilityIdentifier("resetButton")
                }

                Section("About") {
                    labeled("App", appVersion)
                    labeled("Core", VelaCoreFFI.version())
                    if let userID = accountVM.userID {
                        Button {
                            Clipboard.copySecurely(userID)
                        } label: {
                            HStack {
                                Text("User ID").foregroundStyle(.primary)
                                Spacer()
                                Text(userID.prefix(8) + "…").foregroundStyle(.secondary)
                                Image(systemName: "doc.on.doc")
                            }
                        }
                    }
                }

                if !accountVM.status.isEmpty {
                    Section { Text(accountVM.status).font(.callout).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Reset local security?", isPresented: $confirmReset) {
                Button("Reset", role: .destructive) {
                    vm.wipe()
                    accountVM.signOut()
                    dismiss()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This deletes the on-device vault and keys. Items synced to the server can be restored after re-enrolling.")
            }
        }
    }

    private var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        return v
    }

    private func labeled(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).font(.callout.monospaced()).foregroundStyle(.secondary)
        }
    }
}
