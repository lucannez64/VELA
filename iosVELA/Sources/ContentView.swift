import SwiftUI

struct ContentView: View {
    @StateObject private var vm = VaultViewModel()

    var body: some View {
        Group {
            switch vm.lockState {
            case .unlocked:
                VaultListView(vm: vm)
            case .locked:
                UnlockView(vm: vm)
            case .noVault:
                WelcomeView(vm: vm)
            }
        }
        .preferredColorScheme(.dark)
    }
}
