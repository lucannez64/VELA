import Foundation

/// Marks files as excluded from device backups.
///
/// `.completeFileProtection` only guards files at rest on the device — it does
/// nothing for iTunes/Finder/iCloud backups, which would otherwise carry
/// `vault.enc`, the PBKDF2-wrapped RMS blob (`rms_password.blob`), and
/// `account.json` (which holds a live PASETO session token). An unencrypted
/// backup would make the password-wrapped RMS offline-brute-forceable and the
/// bearer token directly usable. Call this after every write; the attribute is
/// persisted with the file's resource values.
enum BackupExclusion {
    static func exclude(_ url: URL) {
        var mutableURL = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutableURL.setResourceValues(values)
    }
}
