import SwiftUI

/// Home tab: greeting, sunrise hero with the item count, quick tiles, the
/// attention card and recently opened items.
struct OverviewScreen: View {
    let items: [VaultItem]
    let recentIDs: [String]
    let sync: InstrumentSyncState
    let onItem: (VaultItem) -> Void
    let onVault: () -> Void
    let onFavorites: () -> Void
    let onAttention: () -> Void
    let onGenerate: () -> Void
    let onLock: () -> Void

    @Environment(\.ink) private var ink

    private var attention: Set<String> { items.accountsNeedingAttention }

    private var recent: [VaultItem] {
        let byID = Dictionary(items.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var seen = Set<String>()
        var result: [VaultItem] = []
        let opened = recentIDs.compactMap { byID[$0] }
        let newest = items.sorted { $0.updatedAt > $1.updatedAt }
        for item in opened + newest where !seen.contains(item.id) {
            seen.insert(item.id)
            result.append(item)
            if result.count == 3 { break }
        }
        return result
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                InstrumentBrand(sync: sync, onLock: onLock).arrive(0)
                InstrumentHeading(eyebrow: "Your private space", title: Greeting.now()).arrive(1)
                hero.arrive(2, distance: 14)
                HStack(spacing: 10) {
                    InstrumentTile(icon: .star, title: "\(items.filter(\.favorite).count)", caption: "Favourites", action: onFavorites)
                        .accessibilityIdentifier("favoritesTile")
                    InstrumentTile(icon: .dice, title: "Generate", caption: "Something hard to guess.", action: onGenerate)
                        .accessibilityIdentifier("generateTile")
                }
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 12)
                .arrive(3)
                if !attention.isEmpty {
                    attentionCard(count: attention.count).padding(.top, 16).arrive(4)
                }
                SectionHead(label: "01 / Recently opened") {
                    TextAction(text: "View all ↗", action: onVault)
                }
                .arrive(5)
                if items.isEmpty {
                    emptyState.arrive(6)
                } else {
                    ForEach(Array(recent.enumerated()), id: \.element.id) { index, item in
                        InstrumentItemRow(icon: item.glyph, title: item.name, subtitle: item.rowSubtitle,
                                          needsReview: attention.contains(item.id), favorite: item.favorite) {
                            onItem(item)
                        }
                        .accessibilityIdentifier("recent-\(item.name)")
                        .arrive(6 + index)
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 100)
        }
        .scrollIndicators(.hidden)
    }

    private var countText: String {
        items.count < 10 ? "0\(items.count)" : "\(items.count)"
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 0) {
            MonoLabel("One vault. Only yours.", color: Color(hex: 0xB2ACC3))
            Text("A little peace\nof mind.")
                .font(InstrumentFont.display(29))
                .tracking(-0.9)
                .foregroundColor(Color(hex: 0xF3F2EF))
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 10)
            HStack(alignment: .bottom) {
                DotMatrix(value: countText, color: Color(hex: 0xE9DCFF))
                Spacer(minLength: 12)
                FineText("Items in your vault\nEncrypted on this device.", size: 10,
                         color: Color(rgba: 0xE6DDF5C7), alignment: .trailing)
            }
            .padding(.top, 26)
        }
        .padding(22)
        .frame(maxWidth: .infinity, minHeight: 207, alignment: .topLeading)
        .background(SunriseBackground())
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private func attentionCard(count: Int) -> some View {
        Button(action: onAttention) {
            HStack(spacing: 10) {
                InstrumentIcon(name: .shield, size: 20, color: ink.red)
                VStack(alignment: .leading, spacing: 3) {
                    Text(count == 1 ? "1 account needs attention" : "\(count) accounts need attention")
                        .font(InstrumentFont.medium(14))
                        .foregroundColor(ink.text)
                    FineText("A small check makes a difference.", size: 10)
                }
                Spacer(minLength: 0)
                InstrumentIcon(name: .chev, size: 16, color: ink.muted)
            }
            .padding(15)
            .frame(maxWidth: .infinity)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(ink.red.opacity(0.04)))
            .instrumentPanel(radius: 18, border: ink.red.opacity(0.24), fill: ink.panel)
            .contentShape(RoundedRectangle(cornerRadius: 18))
        }
        .buttonStyle(PressScaleStyle())
        .accessibilityIdentifier("attentionCard")
    }

    private var emptyState: some View {
        VStack(spacing: 0) {
            Text("A place for your essentials.")
                .font(InstrumentFont.display(18))
                .foregroundColor(ink.text)
            FineText("Add a login, card or private note from your vault.", alignment: .center)
                .padding(.top, 12)
            InstrumentPill(text: "Open vault", icon: .vault, action: onVault)
                .padding(.top, 16)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
    }
}
