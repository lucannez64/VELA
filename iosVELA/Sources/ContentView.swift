import SwiftUI

struct ContentView: View {
    @StateObject private var vm: VaultViewModel
    @StateObject private var accountVM: AccountViewModel

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
            if newValue == .unlocked,
               UserDefaults.standard.bool(forKey: "vela.syncOnStartup"),
               accountVM.isRegistered {
                accountVM.syncNow()
            }
        }
    }
}
