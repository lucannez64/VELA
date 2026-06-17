import SwiftUI

struct VaultListView: View {
    @ObservedObject var vm: VaultViewModel
    @State private var showingAdd = false

    var body: some View {
        NavigationStack {
            Group {
                if vm.items.isEmpty {
                    emptyState
                } else {
                    List {
                        ForEach(vm.items) { item in
                            NavigationLink(value: item.id) {
                                row(item)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Vault")
            .navigationDestination(for: String.self) { id in
                if let item = vm.items.first(where: { $0.id == id }) {
                    ItemDetailView(vm: vm, item: item)
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showingAdd = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showingAdd) {
                AddItemView(vm: vm)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.fill")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("No items yet")
                .font(.title3.bold())
            Text("Add your first login to get started.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func row(_ item: VaultItem) -> some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(.green.opacity(0.2))
                    .frame(width: 36, height: 36)
                Text(String(item.name.prefix(1)).uppercased())
                    .font(.headline)
                    .foregroundStyle(.green)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).font(.body)
                Text(item.username).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
