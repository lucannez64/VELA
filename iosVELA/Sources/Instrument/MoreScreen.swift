import SwiftUI
import UIKit

enum MoreDestination: Hashable {
    case favorites, attention, sharing, breach, devices, activity, settings, theme, account
}

/// More tab: profile card and grouped menus, ending with "Lock vault".
struct MoreScreen: View {
    let accountLabel: String
    let favorites: Int
    let attention: Int
    let themeName: String
    let sync: InstrumentSyncState
    let onOpen: (MoreDestination) -> Void
    let onLock: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                InstrumentBrand(sync: sync, onLock: onLock).arrive(0)
                profileCard.padding(.top, 3).padding(.bottom, 25).arrive(1)

                GroupLabel(text: "01 / Vault").arrive(2)
                InstrumentGroup {
                    InstrumentMenuRow(icon: .star, label: "Favourites", meta: "\(favorites)") { onOpen(.favorites) }
                    GroupDivider()
                    InstrumentMenuRow(icon: .shield, label: "Needs attention", meta: attention > 0 ? "\(attention)" : nil) { onOpen(.attention) }
                }
                .arrive(2)

                GroupLabel(text: "02 / Security").arrive(3)
                InstrumentGroup {
                    InstrumentMenuRow(icon: .share, label: "Sharing") { onOpen(.sharing) }
                        .accessibilityIdentifier("sharingLink")
                    GroupDivider()
                    InstrumentMenuRow(icon: .shield, label: "Breach watch") { onOpen(.breach) }
                        .accessibilityIdentifier("breachLink")
                }
                .arrive(3)

                GroupLabel(text: "03 / This device").arrive(4)
                InstrumentGroup {
                    InstrumentMenuRow(icon: .device, label: "Devices") { onOpen(.devices) }
                        .accessibilityIdentifier("devicesLink")
                    GroupDivider()
                    InstrumentMenuRow(icon: .pulse, label: "Activity") { onOpen(.activity) }
                        .accessibilityIdentifier("auditLink")
                    GroupDivider()
                    InstrumentMenuRow(icon: .palette, label: "Theme", meta: themeName) { onOpen(.theme) }
                        .accessibilityIdentifier("themeLink")
                    GroupDivider()
                    InstrumentMenuRow(icon: .gear, label: "Settings") { onOpen(.settings) }
                        .accessibilityIdentifier("settingsButton")
                }
                .arrive(4)

                InstrumentPill(text: "Lock vault", icon: .lock, style: .primary, fullWidth: true, action: onLock)
                    .accessibilityIdentifier("moreLockButton")
                    .padding(.top, 12)
                    .arrive(5)
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 100)
        }
        .scrollIndicators(.hidden)
    }

    private var profileCard: some View {
        Button { onOpen(.account) } label: {
            HStack(spacing: 12) {
                InstrumentAvatar(icon: .user, large: true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Your private vault")
                        .font(InstrumentFont.display(18))
                        .foregroundColor(ink.text)
                    Text(accountLabel)
                        .font(InstrumentFont.body(10))
                        .foregroundColor(ink.muted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    MonoLabel("This phone · Personal vault", color: ink.faint, size: 8)
                }
                Spacer(minLength: 0)
                InstrumentIcon(name: .chev, size: 15, color: ink.muted)
            }
            .padding(17)
            .frame(maxWidth: .infinity)
            .instrumentPanel(radius: 22, border: ink.line, fill: ink.panel)
            .contentShape(RoundedRectangle(cornerRadius: 22))
        }
        .buttonStyle(PressScaleStyle())
        .accessibilityIdentifier("accountLink")
    }
}

/// Theme picker sheet: the prototype's 2×2 grid of swatch cards.
struct ThemeSheet: View {
    @Binding var selection: String
    let onClose: () -> Void

    @Environment(\.ink) private var ink

    private func swatches(_ theme: InstrumentThemeID) -> [Color] {
        let p = theme.palette
        return [p.panel, p.violet, p.lime]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Capsule().fill(ink.faint.opacity(0.5)).frame(width: 32, height: 4)
                .frame(maxWidth: .infinity)
                .padding(.bottom, 14)
            HStack {
                Text("Theme")
                    .font(InstrumentFont.display(22))
                    .tracking(-0.6)
                    .foregroundColor(ink.text)
                Spacer()
                InstrumentIconButton(icon: .x, label: "Close", iconSize: 17, action: onClose)
            }
            .padding(.bottom, 8)
            FineText("Every theme keeps the same calm layout. Pick the one that suits the light around you.")
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 9), GridItem(.flexible(), spacing: 9)], spacing: 9) {
                ForEach(InstrumentThemeID.allCases) { theme in
                    let on = theme.rawValue == selection
                    Button {
                        UISelectionFeedbackGenerator().selectionChanged()
                        withAnimation(.instrument(0.3)) { selection = theme.rawValue }
                    } label: {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 5) {
                                ForEach(0..<3, id: \.self) { i in
                                    RoundedRectangle(cornerRadius: 5).fill(swatches(theme)[i]).frame(width: 13, height: 13)
                                }
                            }
                            Text(theme.title).font(InstrumentFont.body(11)).foregroundColor(ink.text)
                        }
                        .padding(13)
                        .frame(maxWidth: .infinity, minHeight: 89, alignment: .topLeading)
                        .background(RoundedRectangle(cornerRadius: 18).fill(ink.panel))
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(on ? ink.violet : ink.line2, lineWidth: on ? 2 : 1))
                        .contentShape(RoundedRectangle(cornerRadius: 18))
                    }
                    .buttonStyle(PressScaleStyle())
                    .accessibilityIdentifier("theme-\(theme.rawValue)")
                    .accessibilityAddTraits(on ? .isSelected : [])
                }
            }
            .padding(.vertical, 15)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 20)
        .padding(.top, 10)
        .background(ink.bg.ignoresSafeArea())
    }
}
