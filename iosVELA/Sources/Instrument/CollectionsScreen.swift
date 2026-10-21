import SwiftUI
import UIKit

/// Folders & tags: turn schema 2 on, then create, rename, nest and delete
/// folders and tags. Every change goes through the core's `mutate`.
struct CollectionsScreen: View {
    @ObservedObject var vm: VaultViewModel

    @EnvironmentObject private var toast: ToastCenter
    @Environment(\.ink) private var ink
    @Environment(\.dismiss) private var dismiss

    @State private var prompt: NamePrompt?
    @State private var promptText = ""
    @State private var confirmEnable = false
    @State private var pendingDelete: PendingDelete?

    private enum NamePrompt: Identifiable {
        case newFolder(parentID: String?)
        case renameFolder(RichFolder)
        case newTag
        case renameTag(RichTag)

        var id: String {
            switch self {
            case .newFolder(let parent): return "new-folder-\(parent ?? "")"
            case .renameFolder(let folder): return "rename-\(folder.id)"
            case .newTag: return "new-tag"
            case .renameTag(let tag): return "rename-tag-\(tag.id)"
            }
        }

        var title: String {
            switch self {
            case .newFolder(let parent): return parent == nil ? "New folder" : "New subfolder"
            case .renameFolder: return "Rename folder"
            case .newTag: return "New tag"
            case .renameTag: return "Rename tag"
            }
        }
    }

    private enum PendingDelete: Identifiable {
        case folder(RichFolder)
        case tag(RichTag)

        var id: String {
            switch self {
            case .folder(let folder): return "folder-\(folder.id)"
            case .tag(let tag): return "tag-\(tag.id)"
            }
        }
    }

    private var org: VaultOrganization { vm.organization }

    var body: some View {
        ZStack {
            ink.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    BackHead(title: "More / Folders & tags") { dismiss() }.arrive(0)
                    InstrumentHeading(eyebrow: "01 / Vault", title: "Everything in\nits place.",
                                      subtitle: "Folders and tags sync to every device. Deleting one never deletes items.")
                        .arrive(1)
                    if org.enabled {
                        foldersSection.arrive(2)
                        tagsSection.arrive(3)
                    } else {
                        enableCard.arrive(2)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 10)
                .padding(.bottom, 32)
            }
            .scrollIndicators(.hidden)
        }
        .toolbar(.hidden, for: .navigationBar)
        .alert(prompt?.title ?? "", isPresented: Binding(get: { prompt != nil }, set: { if !$0 { prompt = nil } })) {
            TextField("Name", text: $promptText)
            Button("Save") { commitPrompt() }
            Button("Cancel", role: .cancel) { prompt = nil }
        }
        .alert("Turn on folders and custom fields?", isPresented: $confirmEnable) {
            Button("Turn on") { enable() }
            Button("Not now", role: .cancel) {}
        } message: {
            Text("This upgrades your vault format. Other devices need an up-to-date VELA to sync changes afterwards.")
        }
        .confirmationDialog(deleteTitle, isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
                            titleVisibility: .visible) {
            Button("Delete", role: .destructive) { commitDelete() }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("Items stay in your vault. They just lose this label.")
        }
    }

    // MARK: Sections

    private var enableCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            InstrumentIcon(name: .grid, size: 22, color: ink.violet)
            Text("Organise your vault")
                .font(InstrumentFont.display(20))
                .foregroundColor(ink.text)
            FineText("Folders, tags, custom fields and extra websites. Turning this on upgrades your vault once; devices on an older VELA can still read it but must update to make changes.")
            InstrumentPill(text: "Turn on folders & tags", icon: .spark, style: .primary, fullWidth: true) {
                confirmEnable = true
            }
            .accessibilityIdentifier("enableCollectionsButton")
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .instrumentPanel(radius: 22, border: ink.line, fill: ink.panel)
    }

    private var foldersSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                GroupLabel(text: "01 / Folders · \(org.folders.count)")
                InstrumentIconButton(icon: .plus, label: "New folder", size: 36, iconSize: 15) {
                    ask(.newFolder(parentID: nil))
                }
                .accessibilityIdentifier("newFolderButton")
            }
            InstrumentGroup {
                if org.folders.isEmpty {
                    FineText("No folders yet.").padding(15).frame(maxWidth: .infinity, alignment: .leading)
                }
                ForEach(Array(org.sortedFolders.enumerated()), id: \.element.id) { index, folder in
                    if index > 0 { GroupDivider() }
                    row(icon: .vault, title: org.path(of: folder.id), count: count(folder: folder.id)) {
                        Button("New subfolder") { ask(.newFolder(parentID: folder.id)) }
                        Button("Rename") { ask(.renameFolder(folder), text: folder.name) }
                        Menu("Move to") {
                            Button("Top level") { move(folder, to: nil) }
                            ForEach(org.sortedFolders.filter { $0.id != folder.id }) { target in
                                Button(org.path(of: target.id)) { move(folder, to: target.id) }
                            }
                        }
                        Button("Delete", role: .destructive) { pendingDelete = .folder(folder) }
                    }
                    .accessibilityIdentifier("folder-\(folder.name)")
                }
            }
        }
    }

    private var tagsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                GroupLabel(text: "02 / Tags · \(org.tags.count)")
                InstrumentIconButton(icon: .plus, label: "New tag", size: 36, iconSize: 15) { ask(.newTag) }
                    .accessibilityIdentifier("newTagButton")
            }
            InstrumentGroup {
                if org.tags.isEmpty {
                    FineText("No tags yet.").padding(15).frame(maxWidth: .infinity, alignment: .leading)
                }
                ForEach(Array(org.tags.enumerated()), id: \.element.id) { index, tag in
                    if index > 0 { GroupDivider() }
                    row(icon: .link, title: "# \(tag.name)", count: vm.items.filter { ($0.tagIds ?? []).contains(tag.id) }.count) {
                        Button("Rename") { ask(.renameTag(tag), text: tag.name) }
                        Button("Delete", role: .destructive) { pendingDelete = .tag(tag) }
                    }
                    .accessibilityIdentifier("tag-\(tag.name)")
                }
            }
        }
    }

    private func row<Actions: View>(icon: InstrumentIconName, title: String, count: Int,
                                    @ViewBuilder actions: () -> Actions) -> some View {
        HStack(spacing: 12) {
            InstrumentIcon(name: icon, size: 17, color: ink.violet)
            Text(title).font(InstrumentFont.body(12)).foregroundColor(ink.text).lineLimit(1)
            Spacer(minLength: 8)
            Text(count < 10 ? "0\(count)" : "\(count)").font(InstrumentFont.mono(9)).foregroundColor(ink.muted)
            Menu {
                actions()
            } label: {
                InstrumentIcon(name: .dots, size: 16, color: ink.muted)
                    .frame(width: 36, height: 36)
                    .contentShape(Rectangle())
            }
            .accessibilityLabel("Actions for \(title)")
        }
        .padding(.leading, 15)
        .padding(.trailing, 6)
        .frame(minHeight: 55)
    }

    private func count(folder id: String) -> Int {
        vm.items.filter { $0.folderId == id }.count
    }

    private var deleteTitle: String {
        switch pendingDelete {
        case .some(.folder(let folder)): return "Delete folder \(folder.name)?"
        case .some(.tag(let tag)): return "Delete tag \(tag.name)?"
        case .none: return ""
        }
    }

    // MARK: Actions

    private func ask(_ next: NamePrompt, text: String = "") {
        promptText = text
        prompt = next
    }

    private func commitPrompt() {
        guard let current = prompt else { return }
        let name = promptText.trimmingCharacters(in: .whitespaces)
        prompt = nil
        guard !name.isEmpty else { return }
        switch current {
        case .newFolder(let parent): run(.createFolder(name: name, parentID: parent), done: "Folder created.")
        case .renameFolder(let folder): run(.updateFolder(id: folder.id, name: name, parentID: folder.parentID), done: "Folder renamed.")
        case .newTag: run(.createTag(name: name), done: "Tag created.")
        case .renameTag(let tag): run(.renameTag(id: tag.id, name: name), done: "Tag renamed.")
        }
    }

    private func move(_ folder: RichFolder, to parent: String?) {
        run(.updateFolder(id: folder.id, name: folder.name, parentID: parent), done: "Folder moved.")
    }

    private func commitDelete() {
        guard let current = pendingDelete else { return }
        pendingDelete = nil
        switch current {
        case .folder(let folder): run(.deleteFolder(id: folder.id), done: "Folder deleted.")
        case .tag(let tag): run(.deleteTag(id: tag.id), done: "Tag deleted.")
        }
    }

    private func run(_ action: VaultViewModel.OrganizationAction, done: String) {
        do {
            try withAnimation(.instrument(0.3)) { try vm.mutateOrganization(action) }
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            toast.show(done)
        } catch {
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            toast.show(error.localizedDescription)
        }
    }

    private func enable() {
        do {
            try vm.enableCollections()
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            toast.show("Folders and tags are on.")
        } catch {
            toast.show(error.localizedDescription)
        }
    }
}
