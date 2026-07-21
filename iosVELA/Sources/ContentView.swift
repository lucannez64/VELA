import SwiftUI

struct ContentView: View {
    @StateObject private var vm: VaultViewModel
    @StateObject private var accountVM: AccountViewModel
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let vault = VaultViewModel()
        let account = AccountViewModel(vault: vault)
        // Wire the update callback so that when a vault item changes, the account
        // layer re-seals and pushes updated capsules to all share recipients.
        vault.onItemUpdated = { [weak account] item in
            await account?.pushShareUpdates(for: item)
        }
        _vm = StateObject(wrappedValue: vault)
        _accountVM = StateObject(wrappedValue: account)
    }

    var body: some View {
        ZStack {
            Group {
                switch vm.lockState {
                case .unlocked:
                    VaultListView(vm: vm, accountVM: accountVM)
                case .locked:
                    UnlockView(vm: vm, accountVM: accountVM)
                case .noVault:
                    WelcomeView(vm: vm, accountVM: accountVM)
                }
            }
            .preferredColorScheme(.dark)
            .onChange(of: vm.lockState) { newValue in
                if newValue == .unlocked {
                    if autoSyncEnabled, accountVM.isRegistered { accountVM.syncNow() } // sync-on-unlock
                    accountVM.startPeriodicSync()
                } else {
                    accountVM.stopPeriodicSync()
                }
            }
            .onChange(of: scenePhase) { phase in
                switch phase {
                case .active:
                    // Security model (Android parity): reload decrypted items kept in
                    // the session, then refresh and resume the periodic sync.
                    vm.reloadFromSession()
                    if vm.lockState == .unlocked, autoSyncEnabled, accountVM.isRegistered {
                        accountVM.syncNow()
                    }
                    if vm.lockState == .unlocked { accountVM.startPeriodicSync() }
                case .background:
                    // Drop decrypted plaintext from memory (keep the RMS session
                    // for a bounded grace period — see VaultViewModel.clearMemory).
                    vm.clearMemory()
                    accountVM.stopPeriodicSync()
                default:
                    break
                }
            }

            // Privacy overlay: covers vault contents the instant the scene goes
            // inactive/background (app switcher gesture, notification pull-down,
            // incoming call, or backgrounding), so the OS task-switcher snapshot
            // and screen recordings never capture item contents. `.inactive`
            // fires before `.background`, closing the gap where the snapshot is
            // taken before our background handler has a chance to clear state.
            if scenePhase != .active {
                Rectangle()
                    .fill(.ultraThinMaterial)
                    .ignoresSafeArea()
                    .transition(.opacity)
            }
        }
    }

    private var autoSyncEnabled: Bool {
        UserDefaults.standard.bool(forKey: "vela.syncOnStartup")
    }
}
