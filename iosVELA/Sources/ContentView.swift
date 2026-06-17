import SwiftUI

struct ContentView: View {
    @StateObject private var vm = VaultViewModel()

    var body: some View {
        Group {
            if vm.isUnlocked {
                VaultListView(vm: vm)
            } else {
                WelcomeView(vm: vm)
            }
        }
        .preferredColorScheme(.dark)
    }
}
