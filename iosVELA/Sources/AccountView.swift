import SwiftUI
import UIKit

/// Account: enroll this device with a VELA server, then authenticate, sync,
/// share an item and set up recovery.
struct AccountView: View {
    @ObservedObject var vm: AccountViewModel

    @Environment(\.ink) private var ink

    @State private var serverURL = "https://vault.klyt.eu"
    @State private var deviceName = "iPhone"
    @State private var recipientUserID = ""
    @State private var selectedItemID = ""
    @State private var confirmSignOut = false

    var body: some View {
        InstrumentScreenScaffold(backTitle: "More / Account") {
            if let account = vm.account {
                InstrumentHeading(eyebrow: "Your account", title: "Connected.",
                                  subtitle: "This device syncs your vault with your server, end-to-end encrypted.")
                    .arrive(1)
                registered(account)
            } else {
                InstrumentHeading(eyebrow: "Your account", title: "Sync across\nyour devices.",
                                  subtitle: "Enroll this iPhone with your VELA server. Your vault stays encrypted on every device.")
                    .arrive(1)
                register.arrive(2)
            }

            if !vm.status.isEmpty {
                FineText(vm.status, size: 10)
                    .padding(.top, 4)
                    .accessibilityIdentifier("accountStatus")
            }
        }
        .disabled(vm.busy)
        .alert("Sign out of this device?", isPresented: $confirmSignOut) {
            Button("Sign out", role: .destructive) { vm.signOut() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The vault stays on this iPhone, but it stops syncing until you enroll again.")
        }
    }

    // MARK: Not enrolled

    private var register: some View {
        VStack(alignment: .leading, spacing: 0) {
            LabeledInput(label: "Server", text: $serverURL, placeholder: "https://", id: "serverURLField", mono: true, keyboard: .URL)
            LabeledInput(label: "Device name", text: $deviceName, placeholder: "iPhone", id: "deviceNameField")
            InstrumentPill(text: vm.busy ? "Enrolling…" : "Enroll this device", icon: .arrow, style: .primary, fullWidth: true,
                           enabled: !serverURL.isEmpty && !deviceName.isEmpty) {
                vm.register(serverURL: serverURL, deviceName: deviceName)
            }
            .accessibilityIdentifier("registerButton")
            .padding(.top, 6)
        }
    }

    // MARK: Enrolled

    @ViewBuilder private func registered(_ account: AccountState) -> some View {
        GroupLabel(text: "01 / This device").arrive(2)
        InstrumentGroup {
            InstrumentFactRow(label: "Server", value: account.serverURL)
            GroupDivider()
            InstrumentFactRow(label: "User", value: String(account.userID.prefix(8)) + "…", copyValue: account.userID, onCopy: copy)
            GroupDivider()
            InstrumentFactRow(label: "Device", value: String(account.deviceID.prefix(8)) + "…")
        }
        .arrive(2)

        HStack(spacing: 9) {
            InstrumentPill(text: "Authenticate", icon: .key, fullWidth: true) { vm.login() }
                .accessibilityIdentifier("authenticateButton")
            InstrumentPill(text: "Sync now", icon: .refresh, style: .primary, fullWidth: true) {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                vm.syncNow()
            }
            .accessibilityIdentifier("syncButton")
        }
        .padding(.bottom, 12)
        .arrive(3)

        GroupLabel(text: "02 / Share an item").arrive(4)
        shareCard.arrive(4)

        GroupLabel(text: "03 / Recovery").arrive(5)
        recoveryCard.arrive(5)

        DangerPill(text: "Sign out", icon: .lock, fullWidth: true) { confirmSignOut = true }
            .accessibilityIdentifier("signOutButton")
            .padding(.top, 8)
            .arrive(6)
    }

    private var selectedItemName: String {
        vm.vaultItems.first { $0.id == selectedItemID }?.name ?? "Choose an item"
    }

    private var shareCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            if vm.vaultItems.isEmpty {
                FineText("No items to share yet.")
            } else {
                MonoLabel("Item").padding(.bottom, 8)
                Menu {
                    ForEach(vm.vaultItems) { item in
                        Button(item.name) { selectedItemID = item.id }
                    }
                } label: {
                    HStack {
                        Text(selectedItemName)
                            .font(InstrumentFont.body(12))
                            .foregroundColor(selectedItemID.isEmpty ? ink.faint : ink.text)
                            .lineLimit(1)
                        Spacer()
                        InstrumentIcon(name: .chev, size: 13, color: ink.muted).rotationEffect(.degrees(90))
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 48)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(ink.bg))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(ink.line2, lineWidth: 1))
                }
                .padding(.bottom, 14)
                LabeledInput(label: "Recipient user ID", text: $recipientUserID, placeholder: "UUID", id: "recipientField", mono: true)
                InstrumentPill(text: "Share", icon: .share, style: .primary, fullWidth: true,
                               enabled: !selectedItemID.isEmpty && !recipientUserID.isEmpty) {
                    if let item = vm.vaultItems.first(where: { $0.id == selectedItemID }) {
                        vm.share(item: item, recipientUserID: recipientUserID)
                    }
                }
                .accessibilityIdentifier("shareButton")
            }
        }
        .padding(15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .instrumentPanel(radius: 20, border: ink.line, fill: ink.panel)
        .padding(.bottom, 12)
    }

    private var recoveryCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            FineText("Share 1 backs up to iCloud automatically and Share 2 goes to a security key you register. Only Share 3 needs to be handed to someone you trust.", size: 10)
            InstrumentPill(text: "Set up recovery (2 of 3)", icon: .shield, fullWidth: true) { vm.setupRecovery() }
                .accessibilityIdentifier("recoveryButton")
            ForEach(Array(vm.recoveryShares.enumerated()), id: \.offset) { _, share in
                VStack(alignment: .leading, spacing: 6) {
                    MonoLabel("Share 3 · trusted contact", color: ink.violet, size: 8)
                    Text(share)
                        .font(InstrumentFont.mono(10))
                        .foregroundColor(ink.text)
                        .textSelection(.enabled)
                        .lineLimit(3)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .instrumentPanel(radius: 14, border: ink.line2, fill: ink.bg)
            }
        }
        .padding(15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .instrumentPanel(radius: 20, border: ink.line, fill: ink.panel)
        .padding(.bottom, 12)
    }

    private func copy(_ value: String) {
        Clipboard.copySecurely(value)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }
}
