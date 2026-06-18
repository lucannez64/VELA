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
                WelcomeView(vm: vm)
            }
        }
        .preferredColorScheme(.dark)
        .onChange(of: vm.lockState) { newValue in
            // Sync-on-unlock (Settings toggle).
            if newValue == .unlocked, autoSyncEnabled, accountVM.isRegistered {
                accountVM.syncNow()
            }
        }
        .onChange(of: scenePhase) { phase in
            // Sync-on-foreground: refresh when returning to an unlocked vault.
            if phase == .active, vm.lockState == .unlocked, autoSyncEnabled, accountVM.isRegistered {
                accountVM.syncNow()
            }
        }
    }

    private var autoSyncEnabled: Bool {
        UserDefaults.standard.bool(forKey: "vela.syncOnStartup")
    }
}
