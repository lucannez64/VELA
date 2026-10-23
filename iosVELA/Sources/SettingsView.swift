import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The settings hub: server sync, sharing, devices, tools, vault security and
/// about, in the Instrument layout. Presented as a sheet with its own stack.
struct SettingsView: View {
    @ObservedObject var vm: VaultViewModel
    @ObservedObject var accountVM: AccountViewModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.ink) private var ink
    @EnvironmentObject private var toast: ToastCenter

    @AppStorage("vela.syncOnStartup") private var syncOnStartup = false
    @AppStorage("vela.backgroundSyncMinutes") private var backgroundSyncMinutes = 5
    @State private var confirmReset = false
    @State private var copied = false
    @State private var showImporter = false
    @State private var importStatus: String?

    var body: some View {
        NavigationStack {
            ZStack {
                ink.bg.ignoresSafeArea()
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        Capsule().fill(ink.faint.opacity(0.5)).frame(width: 32, height: 4)
                            .frame(maxWidth: .infinity)
                            .padding(.bottom, 14)
                        HStack(alignment: .center) {
                            InstrumentHeading(eyebrow: "04 / Settings", title: "Make it yours.")
                            InstrumentIconButton(icon: .x, label: "Done", iconSize: 17) { dismiss() }
                                .accessibilityIdentifier("settingsDoneButton")
                        }
                        .arrive(0)

                        syncGroup.arrive(1)
                        devicesGroup.arrive(2)
                        toolsGroup.arrive(3)
                        securityGroup.arrive(4)
                        importGroup.arrive(5)
                        aboutGroup.arrive(6)

                        if !accountVM.status.isEmpty {
                            FineText(accountVM.status, size: 10).padding(.top, 4)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 10)
                    .padding(.bottom, 32)
                }
                .scrollIndicators(.hidden)
            }
            .toolbar(.hidden, for: .navigationBar)
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
        .tint(ink.violet)
        .overlay(ToastOverlay(center: toast, bottomInset: 24))
    }

    // MARK: Groups

    private var syncGroup: some View {
        VStack(alignment: .leading, spacing: 0) {
            GroupLabel(text: "01 / Sync")
            InstrumentGroup {
                NavigationLink {
                    AccountView(vm: accountVM)
                } label: {
                    InstrumentLinkLabel(icon: .user, label: "Account", meta: accountVM.isRegistered ? "Enrolled" : "Not set up")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("accountLink")
                if accountVM.isRegistered {
                    GroupDivider()
                    Button {
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        accountVM.syncNow()
                    } label: {
                        HStack(spacing: 12) {
                            InstrumentIcon(name: .refresh, size: 17, color: ink.muted)
                                .rotationEffect(.degrees(accountVM.busy ? 360 : 0))
                                .animation(accountVM.busy ? .linear(duration: 1).repeatForever(autoreverses: false) : .default,
                                           value: accountVM.busy)
                            Text(accountVM.busy ? "Syncing…" : "Sync now").font(InstrumentFont.body(12)).foregroundColor(ink.text)
                            Spacer()
                        }
                        .padding(.horizontal, 15)
                        .frame(minHeight: 55)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("settingsSyncButton")
                    GroupDivider()
                    InstrumentControlRow(label: "Sync on unlock & foreground") {
                        InstrumentToggle(isOn: $syncOnStartup, label: "Sync on unlock and foreground")
                    }
                    GroupDivider()
                    InstrumentControlRow(label: "Auto-sync every \(backgroundSyncMinutes) min") {
                        HStack(spacing: 6) {
                            InstrumentIconButton(icon: .back, label: "Less often", size: 34, iconSize: 13) {
                                stepInterval(-1)
                            }
                            .rotationEffect(.degrees(-90))
                            InstrumentIconButton(icon: .back, label: "More often", size: 34, iconSize: 13) {
                                stepInterval(1)
                            }
                            .rotationEffect(.degrees(90))
                        }
                    }
                }
            }
        }
    }

    private var devicesGroup: some View {
        VStack(alignment: .leading, spacing: 0) {
            GroupLabel(text: "02 / Sharing & devices")
            InstrumentGroup {
                NavigationLink { SharingView(vault: vm, account: accountVM) } label: {
                    InstrumentLinkLabel(icon: .share, label: "Sharing")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("sharingLink")
                GroupDivider()
                NavigationLink { DevicesView(account: accountVM) } label: {
                    InstrumentLinkLabel(icon: .device, label: "Devices")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("devicesLink")
                GroupDivider()
                NavigationLink { WebAccessView(account: accountVM) } label: {
                    InstrumentLinkLabel(icon: .globe, label: "Web access")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("webAccessLink")
            }
        }
    }

    private var toolsGroup: some View {
        VStack(alignment: .leading, spacing: 0) {
            GroupLabel(text: "03 / Tools")
            InstrumentGroup {
                NavigationLink { BreachMonitorView(vault: vm) } label: {
                    InstrumentLinkLabel(icon: .shield, label: "Breach watch")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("breachLink")
                GroupDivider()
                NavigationLink { AuditLogView() } label: {
                    InstrumentLinkLabel(icon: .pulse, label: "Activity")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("auditLink")
                GroupDivider()
                NavigationLink { CollectionsScreen(vm: vm) } label: {
                    InstrumentLinkLabel(icon: .grid, label: "Folders & tags", meta: vm.organization.enabled ? nil : "Off")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("settingsCollectionsLink")
            }
        }
    }

    private var securityGroup: some View {
        VStack(alignment: .leading, spacing: 0) {
            GroupLabel(text: "04 / Security")
            VStack(spacing: 10) {
                InstrumentPill(text: "Lock vault", icon: .lock, style: .primary, fullWidth: true) {
                    vm.lock()
                    dismiss()
                }
                .accessibilityIdentifier("lockVaultButton")
                DangerPill(text: "Reset local security", fullWidth: true) { confirmReset = true }
                    .accessibilityIdentifier("resetButton")
            }
            .padding(.bottom, 12)
        }
    }

    private var importGroup: some View {
        VStack(alignment: .leading, spacing: 0) {
            GroupLabel(text: "05 / Import")
            InstrumentGroup {
                Button {
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    showImporter = true
                } label: {
                    HStack(spacing: 12) {
                        InstrumentIcon(name: .vault, size: 17, color: ink.muted)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Import vault").font(InstrumentFont.body(12)).foregroundColor(ink.text)
                            FineText("Bitwarden, 1Password (.1pif/.1pux), KeePass, browsers or Proton Pass", size: 10)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 15)
                    .frame(minHeight: 55)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("importVaultButton")
                if let importStatus {
                    GroupDivider()
                    FineText(importStatus, size: 10).padding(.horizontal, 15).padding(.vertical, 10)
                }
            }
        }
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [.json, .commaSeparatedText, .zip, .data, .plainText],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                let accessing = url.startAccessingSecurityScopedResource()
                defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                do {
                    let data = try Data(contentsOf: url)
                    let summary = vm.importVault(data: data)
                    importStatus = summary.summary
                } catch {
                    importStatus = "Import failed: \(error.localizedDescription)"
                }
            case .failure(let error):
                importStatus = "Import failed: \(error.localizedDescription)"
            }
        }
    }

    private var aboutGroup: some View {
        VStack(alignment: .leading, spacing: 0) {
            GroupLabel(text: "05 / About")
            InstrumentGroup {
                InstrumentFactRow(label: "App", value: appVersion)
                GroupDivider()
                InstrumentFactRow(label: "Core", value: VelaCoreFFI.version())
                if let userID = accountVM.userID {
                    GroupDivider()
                    InstrumentFactRow(label: "User ID", value: String(userID.prefix(8)) + "…", copyValue: userID) { value in
                        Clipboard.copySecurely(value)
                        UINotificationFeedbackGenerator().notificationOccurred(.success)
                    }
                }
            }
        }
    }

    private func stepInterval(_ delta: Int) {
        let next = min(max(backgroundSyncMinutes + delta, 1), 60)
        guard next != backgroundSyncMinutes else { return }
        UISelectionFeedbackGenerator().selectionChanged()
        backgroundSyncMinutes = next
        accountVM.startPeriodicSync() // apply the new interval
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }
}
