import SwiftUI
import UIKit

/// Editor section for schema-2 data: folder, tags, custom fields and (for
/// logins) other websites. Values are validated by the core on save.
struct RichFieldsSection: View {
    let organization: VaultOrganization
    let showWebsites: Bool
    @Binding var folderID: String
    @Binding var tagIDs: [String]
    @Binding var customFields: [CustomFieldDraft]
    @Binding var extraURLs: [AdditionalURLDraft]
    let onEnable: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionLabel("Organise")
            if organization.enabled {
                folderPicker
                tagPicker.padding(.top, 12)
            } else {
                enableCard
            }

            sectionLabel("Custom fields")
            ForEach($customFields) { $field in
                CustomFieldRow(field: $field) {
                    withAnimation(.instrument(0.25)) { customFields.removeAll { $0.id == field.id } }
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
            Menu {
                ForEach(CustomFieldKind.allCases, id: \.rawValue) { kind in
                    Button(kind.title) {
                        withAnimation(.instrument(0.25)) { customFields.append(CustomFieldDraft(kind: kind)) }
                    }
                }
            } label: {
                addLabel("Add field")
            }
            .accessibilityIdentifier("addCustomFieldButton")

            if showWebsites {
                sectionLabel("Other websites")
                ForEach($extraURLs) { $entry in
                    WebsiteRow(entry: $entry) {
                        withAnimation(.instrument(0.25)) { extraURLs.removeAll { $0.id == entry.id } }
                    }
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }
                Button {
                    withAnimation(.instrument(0.25)) { extraURLs.append(AdditionalURLDraft()) }
                } label: {
                    addLabel("Add website")
                }
                .buttonStyle(PressScaleStyle())
                .accessibilityIdentifier("addWebsiteButton")
            }
        }
    }

    private func sectionLabel(_ text: String) -> some View {
        MonoLabel(text, color: ink.faint)
            .padding(.top, 26)
            .padding(.bottom, 10)
    }

    private func addLabel(_ text: String) -> some View {
        HStack(spacing: 8) {
            InstrumentIcon(name: .plus, size: 14, color: ink.violet)
            Text(text).font(InstrumentFont.body(12)).foregroundColor(ink.text)
        }
        .frame(maxWidth: .infinity, minHeight: 44)
        .overlay(Capsule().stroke(ink.line2, style: StrokeStyle(lineWidth: 1, dash: [4, 3])))
        .contentShape(Capsule())
    }

    private var enableCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                InstrumentIcon(name: .grid, size: 18, color: ink.violet)
                Text("Folders and tags").font(InstrumentFont.medium(13)).foregroundColor(ink.text)
            }
            FineText("Group items into folders, tag them, and add your own fields. This upgrades your vault once.", size: 10)
            InstrumentPill(text: "Turn on", icon: .spark, style: .signal, action: onEnable)
                .accessibilityIdentifier("enableCollectionsButton")
        }
        .padding(15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .instrumentPanel(radius: 17, border: ink.line, fill: ink.panel)
    }

    private var folderPicker: some View {
        Menu {
            Button("Unfiled") { folderID = "" }
            ForEach(organization.sortedFolders) { folder in
                Button(organization.path(of: folder.id)) { folderID = folder.id }
            }
        } label: {
            HStack(spacing: 10) {
                InstrumentIcon(name: .vault, size: 16, color: ink.violet)
                VStack(alignment: .leading, spacing: 3) {
                    MonoLabel("Folder", size: 8)
                    Text(folderID.isEmpty ? "Unfiled" : organization.path(of: folderID))
                        .font(InstrumentFont.body(12))
                        .foregroundColor(folderID.isEmpty ? ink.faint : ink.text)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                InstrumentIcon(name: .chev, size: 14, color: ink.muted).rotationEffect(.degrees(90))
            }
            .padding(.horizontal, 12)
            .frame(minHeight: 52)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(ink.panel))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(ink.line2, lineWidth: 1))
        }
        .accessibilityIdentifier("folderPicker")
    }

    @ViewBuilder private var tagPicker: some View {
        if organization.tags.isEmpty {
            FineText("No tags yet. Create them in More → Folders & tags.", size: 10)
        } else {
            ScrollView(.horizontal) {
                HStack(spacing: 6) {
                    ForEach(organization.tags) { tag in
                        let on = tagIDs.contains(tag.id)
                        InstrumentChip(text: on ? "# \(tag.name) ✓" : "# \(tag.name)", selected: on) {
                            UISelectionFeedbackGenerator().selectionChanged()
                            withAnimation(.instrument(0.2)) {
                                if on { tagIDs.removeAll { $0 == tag.id } } else { tagIDs.append(tag.id) }
                            }
                        }
                        .accessibilityIdentifier("tag-\(tag.name)")
                    }
                }
                .padding(.vertical, 2)
            }
            .scrollIndicators(.hidden)
        }
    }
}

/// One custom field: name, value (text, hidden or switch), remove.
private struct CustomFieldRow: View {
    @Binding var field: CustomFieldDraft
    let onRemove: () -> Void

    @Environment(\.ink) private var ink
    @State private var reveal = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                MonoLabel(field.kind?.title ?? "Field", color: ink.violet, size: 8)
                Spacer()
                InstrumentIconButton(icon: .trash, label: "Remove field", size: 32, iconSize: 14, bordered: false,
                                     tint: ink.muted, action: onRemove)
            }
            if field.isEditable {
                TextField("", text: $field.label, prompt: Text("Field name").foregroundColor(ink.faint))
                    .font(InstrumentFont.medium(12))
                    .foregroundColor(ink.text)
                    .tint(ink.violet)
                    .accessibilityLabel("Field name")
                    .accessibilityIdentifier("customFieldLabel")
                Rectangle().fill(ink.line).frame(height: 1)
                valueEditor
            } else {
                Text(field.label).font(InstrumentFont.medium(12)).foregroundColor(ink.text)
                FineText("Added by a newer VELA. Kept as is.", size: 10)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .instrumentPanel(radius: 14, border: ink.line2, fill: ink.panel)
        .padding(.bottom, 9)
    }

    @ViewBuilder private var valueEditor: some View {
        switch field.kind {
        case .boolean:
            HStack {
                Text(field.flag ? "On" : "Off").font(InstrumentFont.body(12)).foregroundColor(ink.muted)
                Spacer()
                InstrumentToggle(isOn: $field.flag, label: field.label.isEmpty ? "Value" : field.label)
            }
        case .concealed:
            HStack {
                Group {
                    if reveal {
                        TextField("", text: $field.text, prompt: Text("Value").foregroundColor(ink.faint))
                    } else {
                        SecureField("", text: $field.text, prompt: Text("Value").foregroundColor(ink.faint))
                    }
                }
                .font(InstrumentFont.mono(12))
                .foregroundColor(ink.text)
                .textInputAutocapitalization(.never)
                .disableAutocorrection(true)
                .accessibilityIdentifier("customFieldValue")
                InstrumentIconButton(icon: reveal ? .eyeoff : .eye, label: reveal ? "Hide value" : "Show value",
                                     size: 32, iconSize: 15, bordered: false, tint: ink.muted) { reveal.toggle() }
            }
        default:
            TextField("", text: $field.text, prompt: Text("Value").foregroundColor(ink.faint), axis: .vertical)
                .lineLimit(1...6)
                .font(InstrumentFont.body(12))
                .foregroundColor(ink.text)
                .tint(ink.violet)
                .accessibilityIdentifier("customFieldValue")
        }
    }
}

/// One extra website for a login, with whole-site or exact matching.
private struct WebsiteRow: View {
    @Binding var entry: AdditionalURLDraft
    let onRemove: () -> Void

    @Environment(\.ink) private var ink

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                InstrumentIcon(name: .globe, size: 15, color: ink.violet)
                TextField("", text: $entry.url, prompt: Text("https://").foregroundColor(ink.faint))
                    .font(InstrumentFont.body(12))
                    .foregroundColor(ink.text)
                    .tint(ink.violet)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .accessibilityLabel("Website")
                    .accessibilityIdentifier("extraWebsiteField")
                InstrumentIconButton(icon: .trash, label: "Remove website", size: 32, iconSize: 14, bordered: false,
                                     tint: ink.muted, action: onRemove)
            }
            if entry.mode != nil {
                HStack(spacing: 6) {
                    ForEach(URLMatchMode.allCases, id: \.rawValue) { mode in
                        InstrumentChip(text: mode.title, selected: entry.match == mode.rawValue) {
                            withAnimation(.instrument(0.2)) { entry.match = mode.rawValue }
                        }
                    }
                }
            } else {
                FineText("Matching rule from a newer VELA. Kept as is.", size: 10)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .instrumentPanel(radius: 14, border: ink.line2, fill: ink.panel)
        .padding(.bottom, 9)
    }
}
