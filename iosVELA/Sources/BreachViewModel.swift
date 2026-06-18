import Foundation
import SwiftUI

/// Drives the breach monitor: k-anonymity password checks over stored logins,
/// and an email breach lookup.
@MainActor
final class BreachViewModel: ObservableObject {
    struct PasswordResult: Identifiable {
        let id: String
        let name: String
        let breached: Bool
        let count: Int
    }

    @Published var passwordResults: [PasswordResult] = []
    @Published var emailBreaches: [EmailBreach] = []
    @Published var status = ""
    @Published var busy = false

    private unowned let vault: VaultViewModel

    init(vault: VaultViewModel) { self.vault = vault }

    func checkAllPasswords() {
        run("Checking passwords") { [self] in
            var results: [PasswordResult] = []
            for item in vault.items where item.item_type == "login" {
                guard let password = item.password, !password.isEmpty else { continue }
                let result = try await BreachService.checkPassword(password)
                results.append(PasswordResult(id: item.id, name: item.name,
                                              breached: result.breached, count: result.count))
            }
            passwordResults = results
            let exposed = results.filter { $0.breached }.count
            AuditLog.shared.record("breach_passwords_checked", "\(exposed) exposed")
            return exposed == 0 ? "All \(results.count) passwords are secure" : "\(exposed) compromised password(s)"
        }
    }

    func checkEmail(_ email: String) {
        let trimmed = email.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        run("Checking email") { [self] in
            let breaches = try await BreachService.checkEmail(trimmed)
            emailBreaches = breaches
            AuditLog.shared.record("breach_email_checked", "\(trimmed): \(breaches.count) breach(es)")
            return breaches.isEmpty ? "No breaches found for \(trimmed)" : "\(breaches.count) breach(es) found"
        }
    }

    private func run(_ label: String, _ work: @escaping () async throws -> String) {
        busy = true
        status = "\(label)…"
        Task { @MainActor in
            do { status = try await work() }
            catch { status = "\(label) failed: \(error.localizedDescription)" }
            busy = false
        }
    }
}
