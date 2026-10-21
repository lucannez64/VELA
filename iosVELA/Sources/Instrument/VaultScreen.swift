import SwiftUI
import UIKit

/// Preset filters the Overview tiles open the vault with.
enum VaultScope: Equatable {
    case all, favorites, attention
}

/// Vault tab: heading with add button, search, type chips and the item list.
struct VaultScreen: View {
    let items: [VaultItem]
    var organization = VaultOrganization()
    let sync: InstrumentSyncState
    @Binding var scope: VaultScope
    let onItem: (VaultItem) -> Void
    let onAdd: () -> Void
    let onLock: () -> Void

    @Environment(\.ink) private var ink
    @State private var query = ""
    @State private var type: String? = nil
    /// nil = all, "" = unfiled, otherwise a folder id.
    @State private var folderFilter: String? = nil
    @State private var tagFilter: String? = nil

    private struct TypeChip: Identifiable {
        let type: String?
        let label: String
        var id: String { label }
    }

    private static let types: [TypeChip] = [
        TypeChip(type: nil, label: "All"), TypeChip(type: "login", label: "Logins"),
        TypeChip(type: "creditCard", label: "Cards"), TypeChip(type: "secureNote", label: "Notes"),
        TypeChip(type: "passkey", label: "Passkeys"), TypeChip(type: "identity", label: "Identities"),
    ]

    private var attention: Set<String> { items.accountsNeedingAttention }

    private var filtered: [VaultItem] {
        let q = query.trimmingCharacters(in: .whitespaces)
        let attentionIDs = attention
        return items.filter { item in
            let matches = q.isEmpty
                || item.name.localizedCaseInsensitiveContains(q)
                || item.subtitle.localizedCaseInsensitiveContains(q)
                || (item.url ?? "").localizedCaseInsensitiveContains(q)
            let typeOK = type == nil || item.item_type == type
            let scopeOK: Bool
            switch scope {
            case .all: scopeOK = true
            case .favorites: scopeOK = item.favorite
            case .attention: scopeOK = attentionIDs.contains(item.id)
            }
            let folderOK: Bool
            if let folderFilter {
                folderOK = folderFilter.isEmpty
                    ? !organization.contains(folder: item.folderId)
                    : (item.folderId == folderFilter
                       || organization.path(of: item.folderId).hasPrefix(organization.path(of: folderFilter) + " / "))
            } else {
                folderOK = true
            }
            let tagOK = tagFilter == nil || (item.tagIds ?? []).contains(tagFilter ?? "")
            return matches && typeOK && scopeOK && folderOK && tagOK
        }
        .sorted { lhs, rhs in
            if lhs.favorite != rhs.favorite { return lhs.favorite }
            return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }
    }

    private var title: String {
        switch scope {
        case .attention: return "A little attention."
        case .favorites: return "Favourites."
        case .all: return "All the essentials."
        }
    }

    var body: some View {
        let rows = filtered
        let attentionIDs = attention
        return ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                InstrumentBrand(sync: sync, onLock: onLock).arrive(0)
                HStack(alignment: .center) {
                    InstrumentHeading(eyebrow: "01 / Your vault", title: title)
                    InstrumentIconButton(icon: .plus, label: "Add item", action: onAdd)
                        .accessibilityIdentifier("addItemButton")
                }
                .arrive(1)
                InstrumentSearchField(text: $query)
                    .padding(.top, 18)
                    .padding(.bottom, 14)
                    .arrive(2)
                ScrollView(.horizontal) {
                    HStack(spacing: 6) {
                        ForEach(Self.types) { entry in
                            InstrumentChip(text: entry.label, selected: entry.type == type && scope == .all) {
                                withAnimation(.instrument(0.3)) {
                                    type = entry.type
                                    scope = .all
                                }
                            }
                            .accessibilityIdentifier("chip-\(entry.label)")
                        }
                        if scope == .favorites {
                            InstrumentChip(text: "Favourites ×", selected: true) {
                                withAnimation(.instrument(0.3)) { scope = .all }
                            }
                        }
                        if scope == .attention {
                            InstrumentChip(text: "Attention ×", selected: true) {
                                withAnimation(.instrument(0.3)) { scope = .all }
                            }
                        }
                    }
                    .padding(.vertical, 3)
                    .padding(.horizontal, 2)
                }
                .scrollIndicators(.hidden)
                .padding(.horizontal, -2)
                .padding(.bottom, 4)
                .arrive(3)
                if organization.enabled && (!organization.folders.isEmpty || !organization.tags.isEmpty) {
                    collectionFilter.padding(.top, 6).arrive(3)
                }
                SectionHead(label: "Saved items") {
                    Text(rows.count < 10 ? "0\(rows.count)" : "\(rows.count)")
                        .font(InstrumentFont.mono(11))
                        .foregroundColor(ink.violet)
                        .contentTransition(.numericText())
                        .animation(.instrument(0.3), value: rows.count)
                }
                .arrive(4)
                if rows.isEmpty {
                    emptyState.arrive(5)
                } else {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { index, item in
                        InstrumentItemRow(icon: item.glyph, title: item.name, subtitle: item.rowSubtitle,
                                          needsReview: attentionIDs.contains(item.id), favorite: item.favorite) {
                            onItem(item)
                        }
                        .accessibilityIdentifier("row-\(item.name)")
                        .transition(.opacity.combined(with: .offset(y: 6)))
                        .arrive(5 + index)
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 100)
            .animation(.instrument(0.3), value: rows.map(\.id))
        }
        .scrollIndicators(.hidden)
        .scrollDismissesKeyboard(.immediately)
    }

    private var filterLabel: String {
        var parts: [String] = []
        if let folderFilter { parts.append(folderFilter.isEmpty ? "Unfiled" : organization.path(of: folderFilter)) }
        if let tagFilter, let name = organization.tagName(tagFilter) { parts.append("# " + name) }
        return parts.isEmpty ? "All folders & tags" : parts.joined(separator: " · ")
    }

    private var collectionFilter: some View {
        HStack(spacing: 8) {
            Menu {
                Button("All folders & tags") { setFilter(folder: nil, tag: nil) }
                Section("Folders") {
                    Button("Unfiled") { setFilter(folder: "", tag: tagFilter) }
                    ForEach(organization.sortedFolders) { folder in
                        Button(organization.path(of: folder.id)) { setFilter(folder: folder.id, tag: tagFilter) }
                    }
                }
                if !organization.tags.isEmpty {
                    Section("Tags") {
                        ForEach(organization.tags) { tag in
                            Button("# " + tag.name) { setFilter(folder: folderFilter, tag: tag.id) }
                        }
                    }
                }
            } label: {
                HStack(spacing: 8) {
                    InstrumentIcon(name: .grid, size: 14, color: ink.violet)
                    Text(filterLabel).font(InstrumentFont.body(11)).foregroundColor(ink.text).lineLimit(1)
                    InstrumentIcon(name: .chev, size: 12, color: ink.muted).rotationEffect(.degrees(90))
                }
                .padding(.horizontal, 14)
                .frame(minHeight: 40)
                .overlay(Capsule().stroke(folderFilter != nil || tagFilter != nil ? ink.violet : ink.line2, lineWidth: 1))
                .contentShape(Capsule())
            }
            .accessibilityIdentifier("collectionFilter")
            if folderFilter != nil || tagFilter != nil {
                InstrumentIconButton(icon: .x, label: "Clear filter", size: 36, iconSize: 13) {
                    setFilter(folder: nil, tag: nil)
                }
            }
        }
    }

    private func setFilter(folder: String?, tag: String?) {
        UISelectionFeedbackGenerator().selectionChanged()
        withAnimation(.instrument(0.3)) {
            folderFilter = folder
            tagFilter = tag
        }
    }

    private var emptyState: some View {
        VStack(spacing: 0) {
            Text(items.isEmpty ? "A place for your essentials." : "No matches.")
                .font(InstrumentFont.body(14))
                .foregroundColor(ink.text)
            FineText(items.isEmpty ? "Save your first login, card or private note." : "Try another name or item type.",
                     alignment: .center)
                .padding(.top, 12)
            if items.isEmpty {
                InstrumentPill(text: "Add an item", icon: .plus, action: onAdd).padding(.top, 18)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 8)
        .padding(.vertical, 32)
    }
}
