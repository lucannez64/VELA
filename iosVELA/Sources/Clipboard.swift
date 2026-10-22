import UIKit

/// Copies a value to the clipboard with an expiration and no Handoff sync, so
/// a copied secret does not persist on the system clipboard or sync to the
/// user's other devices. Shared by `CopyButton` here and the user ID copy in
/// SettingsView.
enum Clipboard {
    static func copySecurely(_ value: String) {
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: value]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(20)]
        )
    }
}
