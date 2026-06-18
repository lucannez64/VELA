import SwiftUI

/// Breach monitor: check stored passwords against Pwned Passwords (k-anonymity)
/// and look up an email in Have I Been Pwned.
struct BreachMonitorView: View {
    @StateObject private var vm: BreachViewModel
    @State private var email = ""

    init(vault: VaultViewModel) {
        _vm = StateObject(wrappedValue: BreachViewModel(vault: vault))
    }

    var body: some View {
        List {
            Section("Stored passwords") {
                Button("Check stored passwords") { vm.checkAllPasswords() }
                    .disabled(vm.busy)
                    .accessibilityIdentifier("checkPasswordsButton")
                ForEach(vm.passwordResults) { result in
                    HStack {
                        Image(systemName: result.breached ? "exclamationmark.triangle.fill" : "checkmark.shield.fill")
                            .foregroundStyle(result.breached ? Color.red : Color.green)
                        Text(result.name)
                        Spacer()
                        Text(result.breached ? "Exposed \(result.count)×" : "Safe")
                            .font(.caption)
                            .foregroundStyle(result.breached ? Color.red : Color.secondary)
                    }
                }
            }

            Section("Email monitoring") {
                HStack {
                    TextField("email@example.com", text: $email)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("breachEmailField")
                    Button("Check") { vm.checkEmail(email) }
                        .disabled(vm.busy || email.isEmpty)
                }
                ForEach(vm.emailBreaches) { breach in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(breach.title.isEmpty ? breach.name : breach.title).font(.body)
                        Text("\(breach.domain) · \(breach.breachDate)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            Section {
                Text("Passwords are checked privately: only the first 5 characters of each SHA-1 hash are sent (k-anonymity).")
                    .font(.caption).foregroundStyle(.secondary)
                if !vm.status.isEmpty {
                    Text(vm.status).font(.callout).accessibilityIdentifier("breachStatus")
                }
            }
        }
        .navigationTitle("Breach Monitor")
        .navigationBarTitleDisplayMode(.inline)
    }
}
