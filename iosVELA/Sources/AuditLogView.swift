import SwiftUI

/// Local activity log (on-device, never synced).
struct AuditLogView: View {
    @State private var entries: [AuditEntry] = []

    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    BackHead(title: "More / Activity") { dismiss() }
                        .arrive(0)

                    HStack(alignment: .center) {
                        InstrumentHeading(eyebrow: "03 / This device",
                                          title: "Recent activity.",
                                          subtitle: "What happened in your vault, on this device.")
                        TextAction(text: "Clear") { clear() }
                            .disabled(entries.isEmpty)
                            .opacity(entries.isEmpty ? 0.4 : 1)
                    }
                    .arrive(1)

                    InstrumentGroup {
                        if entries.isEmpty {
                            FineText("No activity yet.").padding(15)
                        } else {
                            ForEach(entries.indices, id: \.self) { index in
                                if index > 0 { GroupDivider() }
                                entryRow(entries[index])
                            }
                        }
                    }
                    .arrive(2)
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
        }
        .toolbar(.hidden, for: .navigationBar)
        .onAppear { entries = AuditLog.shared.entries() }
    }

    private func clear() {
        AuditLog.shared.clear()
        entries = []
    }

    private func entryRow(_ entry: AuditEntry) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            MonoLabel(displayDate(entry.timestamp), color: ink.faint, size: 8)
            Text(label(for: entry.action))
                .font(InstrumentFont.body(12))
                .foregroundColor(ink.text)
                .fixedSize(horizontal: false, vertical: true)
            if let detail = entry.detail, !detail.isEmpty {
                FineText(detail, size: 10)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 15)
        .padding(.vertical, 12)
        .frame(minHeight: 55)
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
