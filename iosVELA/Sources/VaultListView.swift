import SwiftUI

struct VaultListView: View {
    @ObservedObject var vm: VaultViewModel
    @ObservedObject var accountVM: AccountViewModel
    @State private var showingAdd = false
    @State private var showingSettings = false
    @State private var query = ""
    @State private var filterKind: ItemKind?

    private var filtered: [VaultItem] {
        ItemFilter.apply(vm.items, query: query, kind: filterKind)
    }

    var body: some View {
        NavigationStack {
            Group {
                if vm.items.isEmpty {
                    emptyState
                } else if filtered.isEmpty {
                    noMatches
                } else {
                    List {
                        ForEach(filtered) { item in
                            NavigationLink(value: item.id) {
                                row(item)
                            }
                            .accessibilityIdentifier("row-\(item.name)")
                        }
                    }
                }
            }
            .navigationTitle("Vault")
            .searchable(text: $query, prompt: "Search")
            .navigationDestination(for: String.self) { id in
                if let item = vm.items.first(where: { $0.id == id }) {
                    ItemDetailView(vm: vm, item: item)
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityIdentifier("settingsButton")
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    filterMenu
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showingAdd = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityIdentifier("addItemButton")
                }
            }
            .sheet(isPresented: $showingAdd) {
                AddEditItemView(vm: vm)
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView(vm: vm, accountVM: accountVM)
            }
        }
    }

    private var filterMenu: some View {
        Menu {
            Button { filterKind = nil } label: {
                Label("All items", systemImage: filterKind == nil ? "checkmark" : "")
            }
            ForEach(ItemKind.allCases) { kind in
                Button { filterKind = kind } label: {
                    Label(kind.displayName, systemImage: filterKind == kind ? "checkmark" : kind.systemImage)
                }
            }
        } label: {
            Image(systemName: filterKind == nil ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
        }
        .accessibilityIdentifier("filterButton")
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.fill")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("No items yet")
                .font(.title3.bold())
            Text("Add your first item to get started.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var noMatches: some View {
        VStack(spacing: 8) {
            Image(systemName: "magnifyingglass").font(.system(size: 36)).foregroundStyle(.secondary)
            Text("No matches").font(.headline)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func row(_ item: VaultItem) -> some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(.green.opacity(0.2))
                    .frame(width: 36, height: 36)
                Image(systemName: item.kind.systemImage)
                    .font(.headline)
                    .foregroundStyle(.green)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).font(.body)
                Text(item.subtitle).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
