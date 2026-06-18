import SwiftUI

/// Local activity log (on-device, never synced).
struct AuditLogView: View {
    @State private var entries: [AuditEntry] = []

    var body: some View {
        List {
            if entries.isEmpty {
                Text("No activity yet").foregroundStyle(.secondary)
            }
            ForEach(entries) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    Text(label(for: entry.action)).font(.body)
                    HStack {
                        if let detail = entry.detail, !detail.isEmpty {
                            Text(detail).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(displayDate(entry.timestamp)).font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Activity Log")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Clear") {
                    AuditLog.shared.clear()
                    entries = []
                }
                .disabled(entries.isEmpty)
            }
        }
        .onAppear { entries = AuditLog.shared.entries() }
    }

    /// Human-readable action label (e.g. "vault_unlocked" → "Vault unlocked").
    private func label(for action: String) -> String {
        let words = action.split(separator: "_").map(String.init)
        guard let first = words.first else { return action }
        return ([first.capitalized] + words.dropFirst()).joined(separator: " ")
    }

    private func displayDate(_ iso: String) -> String {
        guard let date = ISO8601DateFormatter().date(from: iso) else { return iso }
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f.string(from: date)
    }
}
