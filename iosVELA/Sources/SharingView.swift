import SwiftUI
import UIKit

/// Received and sent shares, with accept / decline / revoke.
struct SharingView: View {
    @StateObject private var vm: SharingViewModel

    @Environment(\.ink) private var ink

    init(vault: VaultViewModel, account: AccountViewModel) {
        _vm = StateObject(wrappedValue: SharingViewModel(vault: vault, account: account))
    }

    var body: some View {
        InstrumentScreenScaffold(backTitle: "Security / Sharing") {
            HStack(alignment: .center) {
                InstrumentHeading(eyebrow: "02 / Security", title: "Shared with care.",
                                  subtitle: "Items others sent you, and what you've shared. End-to-end encrypted.")
                InstrumentIconButton(icon: .refresh, label: "Refresh") { vm.refresh() }
                    .accessibilityIdentifier("refreshSharesButton")
            }
            .arrive(1)

            GroupLabel(text: "01 / Received · \(vm.received.count)").arrive(2)
            InstrumentGroup {
                if vm.received.isEmpty {
                    empty("Nothing waiting for you.")
                }
                ForEach(Array(vm.received.enumerated()), id: \.element.id) { index, share in
                    if index > 0 { GroupDivider() }
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 11) {
                            InstrumentAvatar(icon: .share)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(share.itemName).font(InstrumentFont.medium(13)).foregroundColor(ink.text).lineLimit(1)
                                Text("\(share.itemType) · from \(share.from.prefix(8))…")
                                    .font(InstrumentFont.body(10)).foregroundColor(ink.muted).lineLimit(1)
                            }
                            Spacer(minLength: 0)
                        }
                        HStack(spacing: 8) {
                            InstrumentPill(text: "Accept", icon: .check, style: .signal, enabled: share.item != nil) {
                                UINotificationFeedbackGenerator().notificationOccurred(.success)
                                vm.accept(share)
                            }
                            InstrumentPill(text: "Decline") { vm.decline(share) }
                        }
                    }
                    .padding(15)
                }
            }
            .arrive(3)

            GroupLabel(text: "02 / Sent · \(vm.sent.count)").arrive(4)
            InstrumentGroup {
                if vm.sent.isEmpty {
                    empty("You haven't shared anything yet.")
                }
                ForEach(Array(vm.sent.enumerated()), id: \.element.id) { index, share in
                    if index > 0 { GroupDivider() }
                    HStack(spacing: 11) {
                        InstrumentAvatar(icon: .user)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(share.itemName).font(InstrumentFont.medium(13)).foregroundColor(ink.text).lineLimit(1)
                            Text("to \(share.to.prefix(8))…").font(InstrumentFont.body(10)).foregroundColor(ink.muted)
                        }
                        Spacer(minLength: 8)
                        DangerPill(text: "Revoke", icon: nil) { vm.revoke(share) }
                    }
                    .padding(15)
                }
            }
            .arrive(5)

            if !vm.status.isEmpty {
                FineText(vm.status, size: 10).padding(.top, 4)
            }
        }
        .onAppear { vm.refresh() }
        .disabled(vm.busy)
    }

    private func empty(_ text: String) -> some View {
        FineText(text).padding(15).frame(maxWidth: .infinity, alignment: .leading)
    }
}
