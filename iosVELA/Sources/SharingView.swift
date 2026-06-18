import SwiftUI

/// Received + sent shares with accept/decline/revoke.
struct SharingView: View {
    @StateObject private var vm: SharingViewModel

    init(vault: VaultViewModel, account: AccountViewModel) {
        _vm = StateObject(wrappedValue: SharingViewModel(vault: vault, account: account))
    }

    var body: some View {
        List {
            Section("Received") {
                if vm.received.isEmpty {
                    Text("No incoming shares").foregroundStyle(.secondary)
                } else {
                    ForEach(vm.received) { share in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(share.itemName).font(.body)
                            Text("\(share.itemType) · from \(share.from.prefix(8))…")
                                .font(.caption).foregroundStyle(.secondary)
                            HStack {
                                Button("Accept") { vm.accept(share) }
                                    .buttonStyle(.borderedProminent).tint(.green)
                                    .disabled(share.item == nil)
                                Button("Decline", role: .destructive) { vm.decline(share) }
                                    .buttonStyle(.bordered)
                            }
                            .font(.callout)
                        }
                        .padding(.vertical, 2)
                    }
                }
            }

            Section("Sent") {
                if vm.sent.isEmpty {
                    Text("Nothing shared yet").foregroundStyle(.secondary)
                } else {
                    ForEach(vm.sent) { share in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(share.itemName).font(.body)
                                Text("to \(share.to.prefix(8))…").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Revoke", role: .destructive) { vm.revoke(share) }
                                .buttonStyle(.bordered)
                        }
                    }
                }
            }

            if !vm.status.isEmpty {
                Section { Text(vm.status).font(.callout).foregroundStyle(.secondary) }
            }
        }
        .navigationTitle("Sharing")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { vm.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .accessibilityIdentifier("refreshSharesButton")
            }
        }
        .onAppear { vm.refresh() }
    }
}
