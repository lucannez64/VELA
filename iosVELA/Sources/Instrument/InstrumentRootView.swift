import SwiftUI
import UIKit

/// Pushed screens inside the unlocked app.
enum InstrumentRoute: Hashable {
    case item(String)
    case sharing, devices, activity, breach, account, collections
}

/// The unlocked app: four tabs behind the floating dock, item detail and the
/// secondary screens pushed on one navigation stack, sheets for add/settings.
struct InstrumentRootView: View {
    @ObservedObject var vm: VaultViewModel
    @ObservedObject var accountVM: AccountViewModel
    @Binding var themeID: String

    @StateObject private var toast = ToastCenter()
    @State private var tab = InstrumentRootView.initialTab
    @State private var path: [InstrumentRoute] = []
    @State private var scope: VaultScope = .all
    @State private var recentIDs: [String] = []
    @State private var addSheet: AddRequest?
    @State private var showingSettings = false
    @State private var showingTheme = false

    @Environment(\.ink) private var ink
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private struct AddRequest: Identifiable {
        let id = UUID()
        let password: String?
    }

    private static let dockItems = [
        InstrumentDockItem(id: "overview", label: "Overview", icon: .grid),
        InstrumentDockItem(id: "vault", label: "Vault", icon: .vault),
        InstrumentDockItem(id: "generate", label: "Generate", icon: .dice),
        InstrumentDockItem(id: "more", label: "More", icon: .dots),
    ]

    /// Debug builds can open on a given tab (`VELA_TAB`) for CI screenshots.
    static var initialTab: String {
        #if DEBUG
        if let tab = ProcessInfo.processInfo.environment["VELA_TAB"],
           dockItems.contains(where: { $0.id == tab }) {
            return tab
        }
        #endif
        return "overview"
    }

    private var sync: InstrumentSyncState {
        if !accountVM.isRegistered { return .local }
        if accountVM.busy { return .syncing }
        if accountVM.status.localizedCaseInsensitiveContains("failed") { return .failed }
        return .synced
    }

    var body: some View {
        NavigationStack(path: $path) {
            ZStack(alignment: .bottom) {
                ink.bg.ignoresSafeArea()
                currentTab
                    .id(tab)
                    .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: 8)))
                InstrumentDock(items: Self.dockItems, selection: $tab)
                    .background(
                        // Content fades out under the dock instead of showing below it.
                        LinearGradient(colors: [ink.bg.opacity(0), ink.bg, ink.bg], startPoint: .top, endPoint: .bottom)
                            .padding(.top, -24)
                            .ignoresSafeArea(edges: .bottom)
                            .allowsHitTesting(false)
                    )
            }
            .onAppear(perform: applyDebugLaunch)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: InstrumentRoute.self) { route in
                destination(route)
            }
        }
        .tint(ink.violet)
        .environmentObject(toast)
        .overlay(ToastOverlay(center: toast, bottomInset: path.isEmpty ? 83 : 24))
        .sheet(item: $addSheet) { request in
            AddEditItemView(vm: vm, prefillPassword: request.password)
                .environment(\.ink, ink)
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView(vm: vm, accountVM: accountVM)
                .environmentObject(toast)
                .environment(\.ink, ink)
        }
        .sheet(isPresented: $showingTheme) {
            ThemeSheet(selection: $themeID) { showingTheme = false }
                .presentationDetents([.height(380)])
                .environment(\.ink, (InstrumentThemeID(rawValue: themeID) ?? .night).palette)
        }
        .onChange(of: vm.errorMessage) { message in
            if let message { toast.show(message) }
        }
    }

    @ViewBuilder private var currentTab: some View {
        switch tab {
        case "vault":
            VaultScreen(items: vm.items, organization: vm.organization, sync: sync, scope: $scope,
                        onItem: openItem, onAdd: { add() }, onLock: lock)
        case "generate":
            GeneratorScreen(sync: sync) { password in add(password: password) }
        case "more":
            MoreScreen(
                accountLabel: accountLabel,
                favorites: vm.items.filter(\.favorite).count,
                attention: vm.items.accountsNeedingAttention.count,
                themeName: (InstrumentThemeID(rawValue: themeID) ?? .night).title,
                collectionsMeta: vm.organization.enabled ? "\(vm.organization.folders.count + vm.organization.tags.count)" : "Off",
                sync: sync,
                onOpen: openMore,
                onLock: lock
            )
        default:
            OverviewScreen(
                items: vm.items,
                recentIDs: recentIDs,
                sync: sync,
                onItem: openItem,
                onVault: { switchTab("vault", scope: .all) },
                onFavorites: { switchTab("vault", scope: .favorites) },
                onAttention: { switchTab("vault", scope: .attention) },
                onGenerate: { switchTab("generate") },
                onLock: lock
            )
        }
    }

    @ViewBuilder private func destination(_ route: InstrumentRoute) -> some View {
        switch route {
        case .item(let id):
            ItemDetailScreen(vm: vm, itemID: id, onShare: { path.append(.sharing) })
        case .sharing:
            SharingView(vault: vm, account: accountVM)
        case .devices:
            DevicesView(account: accountVM)
        case .activity:
            AuditLogView()
        case .breach:
            BreachMonitorView(vault: vm)
        case .account:
            AccountView(vm: accountVM)
        case .collections:
            CollectionsScreen(vm: vm)
        }
    }

    /// Debug builds: `VELA_OPEN=<item name>` opens an item, `VELA_SHEET=add`
    /// opens the editor, so CI can screenshot those surfaces.
    private func applyDebugLaunch() {
        #if DEBUG
        let env = ProcessInfo.processInfo.environment
        if let name = env["VELA_OPEN"], let item = vm.items.first(where: { $0.name == name }), path.isEmpty {
            path.append(.item(item.id))
        }
        if env["VELA_ROUTE"] == "collections", path.isEmpty {
            path.append(.collections)
        }
        if env["VELA_SHEET"] == "settings" { showingSettings = true }
        if env["VELA_SHEET"] == "add", addSheet == nil {
            addSheet = AddRequest(password: nil)
        }
        #endif
    }

    private var accountLabel: String {
        if let account = accountVM.account { return account.userID }
        return "Local account · This device"
    }

    private func openItem(_ item: VaultItem) {
        recentIDs.removeAll { $0 == item.id }
        recentIDs.insert(item.id, at: 0)
        path.append(.item(item.id))
    }

    private func add(password: String? = nil) {
        addSheet = AddRequest(password: password)
    }

    private func lock() {
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        vm.lock()
    }

    private func switchTab(_ id: String, scope newScope: VaultScope? = nil) {
        withAnimation(.spring(response: 0.36, dampingFraction: 0.82)) {
            if let newScope { scope = newScope }
            tab = id
        }
    }

    private func openMore(_ destination: MoreDestination) {
        switch destination {
        case .favorites: switchTab("vault", scope: .favorites)
        case .attention: switchTab("vault", scope: .attention)
        case .sharing: path.append(.sharing)
        case .breach: path.append(.breach)
        case .devices: path.append(.devices)
        case .activity: path.append(.activity)
        case .account: path.append(.account)
        case .collections: path.append(.collections)
        case .settings: showingSettings = true
        case .theme: showingTheme = true
        }
    }
}
