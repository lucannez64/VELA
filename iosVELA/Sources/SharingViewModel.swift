import Foundation
import SwiftUI

/// Drives the sharing screen: received inbox (accept/decline) and sent linked
/// shares (revoke). Mirrors the Android SharingRepository — capsules are
/// opened with this device's share key and admitted only when they are signed
/// v2 envelopes addressed to this account by the sender the server reports
/// (shows "Unverified share", which cannot be accepted, otherwise).
@MainActor
final class SharingViewModel: ObservableObject {
    struct ReceivedShare: Identifiable {
        let id: String
        let from: String
        let itemName: String
        let itemType: String
        let item: VaultItem?
        /// Fingerprint of the sending device's key, for out-of-band comparison.
        let senderFingerprint: String?
    }
    struct SentShare: Identifiable {
        let id: String
        let to: String
        let itemName: String
    }

    @Published var received: [ReceivedShare] = []
    @Published var sent: [SentShare] = []
    @Published var status = ""
    @Published var busy = false

    private unowned let vault: VaultViewModel
    private let account: AccountViewModel

    init(vault: VaultViewModel, account: AccountViewModel) {
        self.vault = vault
        self.account = account
    }

    func refresh() {
        run("Loading shares") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            guard let identityHandle = account.identityHandle() else {
                throw Fail("no share key — re-register the device")
            }
            let inbox = try await client.shareInbox()
            let linked = try await client.linkedShares()
            await account.adoptToken(from: client)

            let myUserID = account.account?.userID ?? ""
            received = inbox.items.map { item in
                let admitted = VelaCoreFFI.identityAdmitShare(
                    handle: identityHandle, capsuleBase64: item.capsule,
                    recipientUserID: myUserID, attributedSenderUserID: item.sender_user_id)
                let decoded = admitted.flatMap { decodeItem($0.itemJSON) }
                return ReceivedShare(id: item.id, from: item.sender_user_id,
                                     itemName: decoded?.name ?? "Unverified share",
                                     itemType: decoded?.kind.displayName ?? "Item", item: decoded,
                                     senderFingerprint: admitted?.senderFingerprint)
            }
            sent = linked
                .filter { $0.sender_user_id == myUserID }
                .map { share in SentShare(id: share.id, to: share.recipient_user_id, itemName: "Shared item") }
            return "\(received.count) received · \(sent.count) sent"
        }
    }

    func accept(_ share: ReceivedShare) {
        run("Accepting") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            guard let item = share.item else {
                throw Fail("this share is not a signed envelope from its sender and cannot be added")
            }
            vault.add(item)
            try await client.deleteInboxItem(share.id)
            await account.adoptToken(from: client)
            received.removeAll { $0.id == share.id }
            AuditLog.shared.record("share_received", item.name)
            return "Added \(item.name)"
        }
    }

    func decline(_ share: ReceivedShare) {
        run("Declining") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            try await client.deleteInboxItem(share.id)
            await account.adoptToken(from: client)
            received.removeAll { $0.id == share.id }
            AuditLog.shared.record("share_declined")
            return "Declined"
        }
    }

    func revoke(_ share: SentShare) {
        run("Revoking") { [self] in
            guard let client = account.makeClient() else { throw Fail("register first") }
            try await client.deleteLinkedShare(share.id)
            await account.adoptToken(from: client)
            sent.removeAll { $0.id == share.id }
            AuditLog.shared.record("share_revoked")
            return "Revoked"
        }
    }

    private func decodeItem(_ itemJSON: String) -> VaultItem? {
        try? JSONDecoder().decode(VaultItem.self, from: Data(itemJSON.utf8))
    }

    private func run(_ label: String, _ work: @escaping () async throws -> String) {
        // Without this guard, a double-tap (e.g. "Accept"/"Revoke" fired
        // twice) would run both concurrently.
        guard !busy else { return }
        busy = true
        status = "\(label)…"
        Task { @MainActor in
            do { status = try await work() }
            catch { status = "\(label) failed: \(error.localizedDescription)" }
            busy = false
        }
    }

    private struct Fail: LocalizedError {
        let message: String
        init(_ m: String) { message = m }
        var errorDescription: String? { message }
    }
}
