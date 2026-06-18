import SwiftUI

struct ContentView: View {
    @StateObject private var vm: VaultViewModel
    @StateObject private var accountVM: AccountViewModel
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let vault = VaultViewModel()
        _vm = StateObject(wrappedValue: vault)
        _accountVM = StateObject(wrappedValue: AccountViewModel(vault: vault))
    }

    var body: some View {
        Group {
            switch vm.lockState {
            case .unlocked:
                VaultListView(vm: vm, accountVM: accountVM)
            case .locked:
                UnlockView(vm: vm)
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
                // Drop decrypted plaintext from memory (keep the RMS session).
                vm.clearMemory()
                accountVM.stopPeriodicSync()
            default:
                break
            }
        }
    }

    private var autoSyncEnabled: Bool {
        UserDefaults.standard.bool(forKey: "vela.syncOnStartup")
    }
}
