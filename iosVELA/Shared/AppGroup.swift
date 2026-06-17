import Foundation

/// The shared container that lets the AutoFill extension read the same vault the
/// app writes. Both targets declare the `group.com.vela.vault` App Group; the RMS
/// is shared separately via a common keychain access group (see the entitlements).
enum AppGroup {
    static let identifier = "group.com.vela.vault"

    /// Directory holding `vault.enc` (and, in the file fallback, `rms.bin`).
    ///
    /// Uses the App Group container when provisioned, else the app-local
    /// Application Support directory — so unsigned Simulator/CI builds, where the
    /// group container isn't created, still work (the extension just sees an
    /// app-local vault there, which is fine because CI never crosses processes).
    static func vaultDirectory() -> URL {
        let fm = FileManager.default
        let base: URL
        if let shared = fm.containerURL(forSecurityApplicationGroupIdentifier: identifier) {
            base = shared
        } else {
            base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        }
        let dir = base.appendingPathComponent("vela", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}
