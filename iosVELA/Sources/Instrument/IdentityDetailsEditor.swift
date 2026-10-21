import SwiftUI

/// Edit known identity fields in place, retaining every unrecognised property.
struct IdentityDetailsEditor: View {
    @Binding var details: PreservedJSON
    @Environment(\.ink) private var ink

    static let contacts: [(String, String)] = [
        ("middleName", "Middle name"), ("preferredName", "Preferred name"),
        ("email", "Email"), ("phone", "Phone"), ("company", "Company"), ("jobTitle", "Job title"),
    ]
    static let addressFields: [(String, String)] = [
        ("label", "Label"), ("line1", "Street"), ("line2", "Address line 2"),
        ("city", "City"), ("region", "State / region"), ("postalCode", "Postal code"),
        ("countryCode", "Country code (e.g. FR)"),
    ]

    private var addresses: [PreservedJSON] {
        if case .array(let records) = details.objectValue?["addresses"] { return records }
        return []
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            MonoLabel("Contact details").padding(.top, 20)
            ForEach(Self.contacts, id: \.0) { key, label in
                LabeledInput(label: label, text: contact(key), keyboard: key == "email" ? .emailAddress : .default)
            }
            MonoLabel("Addresses").padding(.top, 16)
            ForEach(addresses.indices, id: \.self) { index in
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(Self.addressFields, id: \.0) { key, label in
                        LabeledInput(label: label, text: address(index, key))
                    }
                    Button("Remove address", role: .destructive) {
                        var records = addresses
                        records.remove(at: index)
                        setAddresses(records)
                    }
                    .font(InstrumentFont.body(12))
                }
                .padding(15)
                .instrumentPanel(radius: 17, border: ink.line, fill: ink.panel)
            }
            if addresses.count < 16 {
                InstrumentPill(text: "Add address", icon: .plus) {
                    setAddresses(addresses + [.object(["id": .string(UUID().uuidString.lowercased())])])
                }
                .accessibilityIdentifier("addIdentityAddressButton")
            }
        }
    }

    private func contact(_ key: String) -> Binding<String> {
        Binding(get: { details.objectValue?[key]?.stringValue ?? "" }, set: { value in
            var object = details.objectValue ?? [:]
            object[key] = .string(value)
            details = .object(object)
        })
    }

    private func address(_ index: Int, _ key: String) -> Binding<String> {
        Binding(get: {
            guard addresses.indices.contains(index) else { return "" }
            return addresses[index].objectValue?[key]?.stringValue ?? ""
        }, set: { value in
            var records = addresses
            guard records.indices.contains(index) else { return }
            var record = records[index].objectValue ?? [:]
            record[key] = .string(key == "countryCode" ? value.uppercased() : value)
            records[index] = .object(record)
            setAddresses(records)
        })
    }

    private func setAddresses(_ records: [PreservedJSON]) {
        var object = details.objectValue ?? [:]
        object["addresses"] = .array(records)
        details = .object(object)
    }
}
