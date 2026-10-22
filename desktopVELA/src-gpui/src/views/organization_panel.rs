use crate::{
    background::GuardedSpawn,
    fonts,
    icon::icon,
    modal,
    theme::Palette,
    ui::{self, primary_button, secondary_button as button},
    views::rich_editor::folder_path,
};
use gpui::{
    div, prelude::*, px, Context, Div, Entity, EventEmitter, IntoElement, MouseButton, Render,
    Window,
};
use gpui_elements::editable_text::{EditableTextState, StringStorage};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use vela_desktop_core::{
    commands::organization::{self, AssignItems, OrganizationAction},
    rich_items::OrganizationData,
    vault::VaultItem,
    AppState, Uuid,
};

pub enum OrganizationPanelEvent {
    Changed,
    Filter,
}
impl EventEmitter<OrganizationPanelEvent> for OrganizationPanel {}
#[derive(Clone, Copy, PartialEq)]
enum Dialog {
    Setup,
    Navigate,
    Manage,
    Move,
    Tags,
}
pub struct OrganizationPanel {
    state: Arc<AppState>,
    pub selected: BTreeSet<String>,
    pub revision: u64,
    tag_changes: BTreeMap<Uuid, bool>,
    folder: Option<String>,
    tag: Option<Uuid>,
    descendants: bool,
    dialog: Option<Dialog>,
    tag_mode: bool,
    target: Option<Uuid>,
    parent: Option<Uuid>,
    choose_parent: bool,

    name: Entity<EditableTextState>,
    busy: bool,
    error: Option<String>,
    confirm_delete: bool,
}
impl OrganizationPanel {
    pub fn new(state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        Self {
            state,
            selected: BTreeSet::new(),
            revision: 0,
            tag_changes: BTreeMap::new(),
            folder: None,
            tag: None,
            descendants: true,
            dialog: None,
            tag_mode: false,
            target: None,
            parent: None,
            choose_parent: false,

            name: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            busy: false,
            error: None,
            confirm_delete: false,
        }
    }
    pub fn toggle(&mut self, id: String, cx: &mut Context<Self>) {
        if !self.selected.remove(&id) {
            self.selected.insert(id);
        }
        cx.emit(OrganizationPanelEvent::Filter);
        cx.notify();
    }
    fn changed(&mut self, cx: &mut Context<Self>) {
        self.revision = self.revision.wrapping_add(1);
        cx.emit(OrganizationPanelEvent::Filter);
        cx.notify();
    }
    fn open(&mut self, dialog: Dialog, cx: &mut Context<Self>) {
        self.dialog = Some(dialog);
        self.error = None;
        self.tag_changes.clear();
        self.target = None;
        self.parent = None;
        self.choose_parent = false;

        self.confirm_delete = false;
        self.name.update(cx, |s, cx| s.emplace("", cx));
        cx.notify();
    }
    fn close(&mut self, cx: &mut Context<Self>) {
        if !self.busy {
            self.dialog = None;
            self.error = None;
            cx.notify();
        }
    }
    fn activate(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.error = None;
        let state = self.state.clone();
        // Activation performs HTTP. GPUI's background executor has no Tokio reactor.
        let task = gpui_tokio::Tokio::spawn(cx, async move {
            organization::activate_rich_items(&state).await
        });
        cx.spawn(async move |this, cx| {
            let result = task
                .await
                .unwrap_or_else(|e| Err(format!("Activation interrupted: {e}")));
            this.update(cx, |this, cx| {
                this.busy = false;
                match result {
                    Ok(_) => {
                        this.dialog = None;
                        this.changed(cx);
                        cx.emit(OrganizationPanelEvent::Changed);
                    }
                    Err(e) => this.error = Some(e),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }
    pub fn matches(&self, item: &VaultItem, org: &OrganizationData) -> bool {
        let rich = &item.meta().rich;
        let folder = rich
            .folder_id
            .as_ref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .filter(|id| org.folder(*id).is_some());
        if let Some(filter) = &self.folder {
            if filter.is_empty() {
                if folder.is_some() {
                    return false;
                }
            } else {
                let target = Uuid::parse_str(filter).ok();
                let parents = org.display_parents();
                let mut cursor = folder;
                let mut matched = false;
                while let Some(id) = cursor {
                    if Some(id) == target {
                        matched = true;
                        break;
                    }
                    if !self.descendants {
                        break;
                    }
                    cursor = parents.get(&id).copied().flatten();
                }
                if !matched {
                    return false;
                }
            }
        }
        self.tag
            .map(|id| rich.tag_ids.as_ref().is_some_and(|tags| tags.contains(&id)))
            .unwrap_or(true)
    }
    fn save_record(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.name.read(cx).as_str().trim().is_empty() {
            return;
        }
        let name = self.name.read(cx).as_str().to_string();
        let action = match (self.tag_mode, self.target) {
            (true, Some(id)) => OrganizationAction::RenameTag { id, name },
            (true, None) => OrganizationAction::CreateTag { name },
            (false, Some(id)) => OrganizationAction::UpdateFolder {
                id,
                name,
                parent_id: self.parent,
            },
            (false, None) => OrganizationAction::CreateFolder {
                name,
                parent_id: self.parent,
            },
        };
        self.mutate(action, cx);
    }
    fn mutate(&mut self, action: OrganizationAction, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.error = None;
        let state = self.state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("organize vault", async move {
                    organization::mutate_organization(&state, action)
                })
                .await
                .unwrap_or_else(|| Err("Could not save changes. Please try again.".into()));
            this.update(cx, |this, cx| {
                this.busy = false;
                match result {
                    Ok(_) => {
                        this.dialog = None;
                        let vault = this.state.vault.read();
                        if this.folder.as_ref().is_some_and(|id| {
                            !id.is_empty()
                                && Uuid::parse_str(id)
                                    .ok()
                                    .is_none_or(|id| vault.organization.folder(id).is_none())
                        }) {
                            this.folder = None;
                        }
                        if this
                            .tag
                            .is_some_and(|id| vault.organization.tag(id).is_none())
                        {
                            this.tag = None;
                        }
                        drop(vault);
                        this.changed(cx);
                        cx.emit(OrganizationPanelEvent::Changed);
                    }
                    Err(e) => this.error = Some(e),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }
    fn assign(&mut self, kind: u8, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        if kind != 0 && kind != 4 && self.target.is_none() {
            self.error = Some("Choose a tag first.".into());
            cx.notify();
            return;
        }
        let changes = AssignItems {
            ids: self.selected.iter().cloned().collect(),
            folder_id: (kind == 0)
                .then(|| self.target.map(|id| id.to_string()).unwrap_or_default()),
            add_tags: if kind == 4 {
                self.tag_changes
                    .iter()
                    .filter_map(|(id, add)| add.then_some(*id))
                    .collect()
            } else if kind == 1 {
                self.target.into_iter().collect()
            } else {
                vec![]
            },
            remove_tags: if kind == 4 {
                self.tag_changes
                    .iter()
                    .filter_map(|(id, add)| (!add).then_some(*id))
                    .collect()
            } else if kind == 2 {
                self.target.into_iter().collect()
            } else {
                vec![]
            },
        };
        self.busy = true;
        self.error = None;
        let state = self.state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("assign vault items", async move {
                    organization::assign_items(&state, changes)
                })
                .await
                .unwrap_or_else(|| Err("Could not organize selected items.".into()));
            this.update(cx, |this, cx| {
                this.busy = false;
                match result {
                    Ok(()) => {
                        this.dialog = None;
                        this.selected.clear();
                        this.changed(cx);
                        cx.emit(OrganizationPanelEvent::Changed);
                    }
                    Err(e) => this.error = Some(e),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }
    pub fn selection_bar(entity: &Entity<Self>, cx: &mut gpui::App) -> Div {
        let p = crate::theme::current_palette(cx);
        let count = entity.read(cx).selected.len();
        let mut bar = div().flex().flex_wrap().items_center().gap_2();
        if count == 0 {
            return bar;
        }
        bar = bar
            .p_3()
            .rounded_xl()
            .bg(gpui::Hsla {
                a: 0.06,
                ..p.primary
            })
            .border_1()
            .border_color(gpui::Hsla {
                a: 0.15,
                ..p.primary
            })
            .child(div().flex_1().text_sm().child(format!("{count} selected")));
        for (id, label, symbol, dialog) in [
            (
                "move-selected",
                "Move to",
                "drive_file_move",
                Some(Dialog::Move),
            ),
            ("tag-selected", "Edit tags", "label", Some(Dialog::Tags)),
            ("clear-selection", "Clear", "close", None),
        ] {
            let entity = entity.clone();
            bar = bar.child(
                button(id.into(), label, &p)
                    .child(icon(symbol, px(16.), p.on_surface_variant))
                    .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                        entity.update(cx, |this, cx| {
                            if let Some(dialog) = dialog {
                                this.open(dialog, cx);
                            } else {
                                this.selected.clear();
                                cx.emit(OrganizationPanelEvent::Filter);
                                cx.notify();
                            }
                        });
                    }),
            );
        }
        bar
    }
    pub fn scope_control(entity: &Entity<Self>, cx: &mut gpui::App) -> Option<Div> {
        let panel = entity.read(cx);
        let target = panel
            .folder
            .as_ref()
            .and_then(|id| Uuid::parse_str(id).ok())?;
        if !panel
            .state
            .vault
            .read()
            .organization
            .display_parents()
            .values()
            .any(|parent| *parent == Some(target))
        {
            return None;
        }
        let enabled = panel.descendants;
        let p = crate::theme::current_palette(cx);
        let entity = entity.clone();
        Some(
            div().flex().items_center().child(
                div()
                    .id("include-subfolders")
                    .debug_selector(|| "include-subfolders".into())
                    .flex()
                    .items_center()
                    .gap_2()
                    .h_6()
                    .font_family(crate::fonts::LABEL)
                    .text_sm()
                    .text_color(p.on_surface_variant)
                    .cursor_pointer()
                    .child(icon(
                        if enabled {
                            "check_box"
                        } else {
                            "check_box_outline_blank"
                        },
                        px(18.),
                        if enabled { p.primary } else { p.outline },
                    ))
                    .child("Include subfolders")
                    .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                        entity.update(cx, |panel, cx| {
                            panel.descendants = !panel.descendants;
                            panel.changed(cx);
                        })
                    }),
            ),
        )
    }

    pub fn is_all_items(&self) -> bool {
        self.folder.is_none() && self.tag.is_none()
    }
    pub fn new_item_organization(&self) -> vela_desktop_core::rich_items::RichItemData {
        let mut rich = vela_desktop_core::rich_items::RichItemData::default();
        rich.folder_id = self.folder.clone().or_else(|| Some(String::new()));
        rich.tag_ids = Some(self.tag.into_iter().collect());
        rich
    }
    pub fn location_header(&self, p: &Palette) -> Div {
        let vault = self.state.vault.read();
        let org = &vault.organization;
        let title = self
            .tag
            .and_then(|id| org.tag(id).map(|t| t.name.clone()))
            .or_else(|| {
                self.folder.as_ref().map(|id| {
                    Uuid::parse_str(id)
                        .ok()
                        .and_then(|id| org.folder(id).map(|f| f.name.clone()))
                        .unwrap_or_else(|| "Unfiled".into())
                })
            })
            .unwrap_or_else(|| "All items".into());
        let count = vault
            .items
            .iter()
            .filter(|item| self.matches(item, org))
            .count();
        let subtitle = if self.tag.is_some() {
            format!("{count} items with this tag")
        } else if let Some(id) = self.folder.as_ref().filter(|id| !id.is_empty()) {
            format!(
                "{} · {count} items",
                Uuid::parse_str(id)
                    .ok()
                    .map(|id| folder_path(org, id))
                    .unwrap_or_default()
            )
        } else {
            format!("{count} items in your vault")
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .font_family(fonts::HEADLINE)
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_2xl()
                    .text_color(p.on_surface)
                    .child(title),
            )
            .child(
                div()
                    .font_family(fonts::BODY)
                    .text_sm()
                    .text_color(p.on_surface_variant)
                    .child(subtitle),
            )
    }
    fn edit_record(&mut self, tags: bool, target: Option<Uuid>, cx: &mut Context<Self>) {
        self.open(Dialog::Manage, cx);
        self.tag_mode = tags;
        self.target = target;
        if !tags && target.is_none() {
            self.parent = self.folder.as_ref().and_then(|id| Uuid::parse_str(id).ok());
        }
        if let Some(id) = target {
            let vault = self.state.vault.read();
            let name = if tags {
                vault.organization.tag(id).map(|t| t.name.clone())
            } else {
                vault.organization.folder(id).map(|f| f.name.clone())
            }
            .unwrap_or_default();
            self.parent = if tags {
                None
            } else {
                vault.organization.folder(id).and_then(|f| f.parent_id)
            };
            drop(vault);
            self.name.update(cx, |s, cx| s.emplace(&name, cx));
        }
        cx.notify();
    }
    fn section_header(
        &self,
        label: &'static str,
        tags: bool,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> Div {
        div()
            .flex()
            .items_center()
            .px_6()
            .pt_4()
            .pb_2()
            .child(
                fonts::tracked_text(label, px(10.), 0.1)
                    .flex_1()
                    .font_family(fonts::LABEL)
                    .text_color(p.outline),
            )
            .child(
                div()
                    .id(if tags { "new-tag" } else { "new-folder" })
                    .debug_selector(move || {
                        if tags {
                            "new-tag".into()
                        } else {
                            "new-folder".into()
                        }
                    })
                    .size(px(28.))
                    .rounded_lg()
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .hover(|el| el.bg(p.surface_container))
                    .child(icon("add", px(16.), p.on_surface_variant))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| this.edit_record(tags, None, cx)),
                    ),
            )
    }
    fn navigation(
        &self,
        org: &OrganizationData,
        active: bool,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut body = div()
            .flex()
            .flex_col()
            .pb_4()
            .font_family(fonts::BODY)
            .text_sm();
        for (key, label, value) in [
            ("all", "All items", None),
            ("unfiled", "Unfiled", Some(String::new())),
        ] {
            let selected = self.folder == value && self.tag.is_none();
            body = body.child(
                nav_row(
                    format!("org-filter-{key}"),
                    label.to_string(),
                    if key == "all" { "apps" } else { "inbox" },
                    selected,
                    0,
                    p,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        this.folder = value.clone();
                        this.tag = None;
                        if this.dialog == Some(Dialog::Navigate) {
                            this.dialog = None;
                        }
                        this.changed(cx);
                    }),
                ),
            );
        }
        if !active {
            return body
                .child(
                    div()
                        .px_6()
                        .pt_4()
                        .text_xs()
                        .text_color(p.on_surface_variant)
                        .child("Folders, tags and custom fields"),
                )
                .child(
                    button("manage-org".into(), "Set up your vault", p)
                        .mx_6()
                        .mt_3()
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|this, _, _, cx| this.open(Dialog::Setup, cx)),
                        ),
                );
        }
        body = body.child(self.section_header("FOLDERS", false, p, cx));
        let mut folders: Vec<_> = org
            .folders
            .iter()
            .map(|f| (f.id, folder_path(org, f.id), f.name.clone()))
            .collect();
        folders.sort_by_key(|(_, path, _)| path.to_lowercase());
        for (id, path, name) in folders {
            let selected = self.folder.as_deref() == Some(&id.to_string()) && self.tag.is_none();
            let depth = path.matches(" / ").count().min(4);
            body = body.child(
                nav_row(
                    format!("org-folder-{id}"),
                    name,
                    "folder",
                    selected,
                    depth,
                    p,
                )
                .when(selected, |el| {
                    el.child(
                        div()
                            .id(gpui::SharedString::from(format!("edit-folder-{id}")))
                            .cursor_pointer()
                            .p_1()
                            .rounded_md()
                            .hover(|el| el.bg(p.surface_container_high))
                            .child(icon("more_horiz", px(16.), p.on_surface_variant))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |this, _, _, cx| {
                                    cx.stop_propagation();
                                    this.edit_record(false, Some(id), cx);
                                }),
                            ),
                    )
                })
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        this.folder = Some(id.to_string());
                        this.tag = None;
                        if this.dialog == Some(Dialog::Navigate) {
                            this.dialog = None;
                        }
                        this.changed(cx);
                    }),
                ),
            );
        }
        if org.folders.is_empty() {
            body = body.child(
                div()
                    .px_6()
                    .py_2()
                    .text_xs()
                    .text_color(p.outline)
                    .child("Create your first folder with +"),
            );
        }
        body = body.child(self.section_header("TAGS", true, p, cx));
        let mut tags = org.tags.clone();
        tags.sort_by_key(|t| t.name.to_lowercase());
        for tag in tags {
            let id = tag.id;
            let selected = self.tag == Some(id);
            body = body.child(
                nav_row(format!("org-tag-{id}"), tag.name, "label", selected, 0, p)
                    .when(selected, |el| {
                        el.child(
                            div()
                                .id(gpui::SharedString::from(format!("edit-tag-{id}")))
                                .cursor_pointer()
                                .p_1()
                                .rounded_md()
                                .hover(|el| el.bg(p.surface_container_high))
                                .child(icon("more_horiz", px(16.), p.on_surface_variant))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |this, _, _, cx| {
                                        cx.stop_propagation();
                                        this.edit_record(true, Some(id), cx);
                                    }),
                                ),
                        )
                    })
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.tag = Some(id);
                            this.folder = None;
                            if this.dialog == Some(Dialog::Navigate) {
                                this.dialog = None;
                            }
                            this.changed(cx);
                        }),
                    ),
            );
        }
        if org.tags.is_empty() {
            body = body.child(
                div()
                    .px_6()
                    .py_2()
                    .text_xs()
                    .text_color(p.outline)
                    .child("Create your first tag with +"),
            );
        }
        body
    }
    fn dialog_content(
        &self,
        dialog: Dialog,
        org: &OrganizationData,
        p: &Palette,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut body = div().flex().flex_col().gap_4();
        if dialog == Dialog::Setup {
            return body.child(div().text_lg().child("A place for everything"))
                .child("Organize your vault with folders and tags, and add custom fields, extra websites and identity details.")
                .child(div().text_sm().text_color(p.on_surface_variant).child("An encrypted safety copy is saved on this device before activation. Mobile and browser access becomes read-only during rollout. Older desktop apps must upgrade before syncing changes."));
        }
        if dialog == Dialog::Navigate {
            return self.navigation(org, true, p, cx);
        }
        if dialog == Dialog::Move || dialog == Dialog::Tags {
            body = body.child(
                div()
                    .text_sm()
                    .text_color(p.on_surface_variant)
                    .child(format!(
                        "Choose {} for {} selected items.",
                        if dialog == Dialog::Move {
                            "a destination"
                        } else {
                            "tags"
                        },
                        self.selected.len()
                    )),
            );
            let records: Vec<_> = if dialog == Dialog::Move {
                std::iter::once((None, "Unfiled".to_string()))
                    .chain(
                        org.folders
                            .iter()
                            .map(|f| (Some(f.id), folder_path(org, f.id))),
                    )
                    .collect()
            } else {
                org.tags
                    .iter()
                    .map(|t| (Some(t.id), t.name.clone()))
                    .collect()
            };
            let vault = self.state.vault.read();
            for (id, label) in records {
                let matches = vault
                    .items
                    .iter()
                    .filter(|item| self.selected.contains(item.id()))
                    .filter(|item| {
                        id.is_some_and(|id| {
                            item.meta()
                                .rich
                                .tag_ids
                                .as_ref()
                                .is_some_and(|tags| tags.contains(&id))
                        })
                    })
                    .count();
                let all = matches == self.selected.len();
                let selected = if dialog == Dialog::Move {
                    self.target == id
                } else {
                    id.and_then(|id| self.tag_changes.get(&id).copied())
                        .unwrap_or(all)
                };
                let mixed = dialog == Dialog::Tags
                    && matches > 0
                    && !all
                    && !id.is_some_and(|id| self.tag_changes.contains_key(&id));
                body = body.child(
                    ui::choice_row_with_state(
                        format!("assignment-{id:?}"),
                        label,
                        if mixed { None } else { Some(selected) },
                        dialog == Dialog::Tags,
                        p,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            if dialog == Dialog::Tags {
                                if let Some(id) = id {
                                    this.tag_changes.insert(id, !selected);
                                }
                            } else {
                                this.target = id;
                            }
                            cx.notify();
                        }),
                    ),
                );
            }
            if dialog == Dialog::Tags && org.tags.is_empty() {
                body = body.child("Use + beside Tags to create your first tag.");
            }
            return body;
        }
        body = body.child(ui::labeled_field(
            p,
            if self.target.is_some() {
                "Name"
            } else if self.tag_mode {
                "Tag name"
            } else {
                "Folder name"
            },
            ui::text_field("organization-name", &self.name, p).placeholder("Name"),
        ));
        if !self.tag_mode {
            body = body.child(ui::labeled_field(
                p,
                "Parent folder",
                ui::select_trigger(
                    "choose-parent-folder".into(),
                    self.parent
                        .map(|id| folder_path(org, id))
                        .unwrap_or_else(|| "Top level".into()),
                    p,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        this.choose_parent = !this.choose_parent;
                        cx.notify();
                    }),
                ),
            ));
            if self.choose_parent {
                for (id, label) in std::iter::once((None, "Top level".to_string())).chain(
                    org.folders
                        .iter()
                        .filter(|f| {
                            let parents = org.display_parents();
                            let mut cursor = Some(f.id);
                            while let Some(id) = cursor {
                                if Some(id) == self.target {
                                    return false;
                                }
                                cursor = parents.get(&id).copied().flatten();
                            }
                            true
                        })
                        .map(|f| (Some(f.id), folder_path(org, f.id))),
                ) {
                    body = body.child(
                        ui::choice_row(
                            format!("parent-{id:?}"),
                            label,
                            self.parent == id,
                            false,
                            p,
                        )
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.parent = id;
                                this.choose_parent = false;
                                cx.notify();
                            }),
                        ),
                    );
                }
            }
        }
        if let Some(id) = self.target {
            body = body.child(
                button(
                    "delete-org".into(),
                    if self.confirm_delete {
                        "Delete permanently"
                    } else {
                        "Delete collection…"
                    },
                    p,
                )
                .text_color(p.error)
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        if this.confirm_delete {
                            this.mutate(
                                if this.tag_mode {
                                    OrganizationAction::DeleteTag { id }
                                } else {
                                    OrganizationAction::DeleteFolder { id }
                                },
                                cx,
                            );
                        } else {
                            this.confirm_delete = true;
                            cx.notify();
                        }
                    }),
                ),
            );
        }
        if self.confirm_delete {
            body=body.child(div().text_sm().text_color(p.error).child("No items will be deleted. Folder items become unfiled and subfolders move up. A deleted tag is removed from all items."));
        }
        body
    }
}
impl Render for OrganizationPanel {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let p = crate::theme::current_palette(cx);
        let vault = self.state.vault.read();
        let active = vault.schema_version == Some(2);
        let org = vault.organization.clone();
        drop(vault);
        let compact = window.viewport_size().width < px(crate::layout::SIDEBAR_BREAKPOINT);
        let mut root = div().min_w_0().text_color(p.on_surface);
        if compact {
            root = root.flex().items_center().max_w_full().child(
                button("collections".into(), "Folders & tags", &p)
                    .child(icon("expand_more", px(18.), p.on_surface_variant))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.open(
                                if active {
                                    Dialog::Navigate
                                } else {
                                    Dialog::Setup
                                },
                                cx,
                            )
                        }),
                    ),
            );
        } else {
            root = root
                .w_full()
                .border_t_1()
                .border_color(gpui::Hsla {
                    a: 0.05,
                    ..p.outline_variant
                })
                .child(self.navigation(&org, active, &p, cx));
        }
        if let Some(dialog) = self.dialog {
            let title = match dialog {
                Dialog::Setup => "Set up collections",
                Dialog::Navigate => "Collections",
                Dialog::Manage => match (self.tag_mode, self.target.is_some()) {
                    (false, false) => "New folder",
                    (false, true) => "Edit folder",
                    (true, false) => "New tag",
                    (true, true) => "Edit tag",
                },
                Dialog::Move => "Move items",
                Dialog::Tags => "Edit tags",
            };
            let header = modal::header(
                title,
                modal::close_button("close-collections", &p).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| this.close(cx)),
                ),
                &p,
            );
            let mut body = self.dialog_content(dialog, &org, &p, cx);
            if let Some(e) = &self.error {
                body = body.child(div().text_sm().text_color(p.error).child(e.clone()));
            }
            let mut footer = div().flex().flex_wrap().justify_end().gap_2();
            if self.busy {
                footer = footer.child("Saving…");
            } else {
                footer = footer.child(
                    button("cancel-collections".into(), "Cancel", &p).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _, _, cx| this.close(cx)),
                    ),
                );
                match dialog {
                    Dialog::Setup => {
                        footer = footer.child(
                            primary_button("enable-rich-items".into(), "Enable collections", &p)
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| this.activate(cx)),
                                ),
                        )
                    }
                    Dialog::Manage => {
                        footer = footer.child(
                            primary_button(
                                "save-org".into(),
                                if self.target.is_some() {
                                    "Save changes"
                                } else {
                                    "Create"
                                },
                                &p,
                            )
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _, _, cx| {
                                    this.save_record(cx);
                                }),
                            ),
                        )
                    }
                    Dialog::Move => {
                        footer = footer.child(
                            primary_button("apply-move".into(), "Move here", &p).on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _, _, cx| this.assign(0, cx)),
                            ),
                        )
                    }
                    Dialog::Tags => {
                        footer = footer.child(
                            primary_button("apply-tags".into(), "Apply tags", &p).on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _, _, cx| this.assign(4, cx)),
                            ),
                        );
                    }
                    Dialog::Navigate => {}
                }
            }
            let frame = modal::frame(
                "collections-dialog",
                480.,
                if dialog == Dialog::Manage { 420. } else { 560. },
                header,
                modal::scroll_body("collections-content", body),
                footer,
                &p,
            )
            .map(|el| crate::keyboard::trap_tab(el, "collections-trap", window, cx))
            .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _, cx| {
                if this.dialog == Some(Dialog::Manage) {
                    this.save_record(cx);
                }
            }))
            .on_key_down(cx.listener(|this, event: &gpui::KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" {
                    cx.stop_propagation();
                    this.close(cx);
                }
            }));
            root = root.child(modal::present(
                window,
                modal::backdrop("collections-backdrop").child(frame),
            ));
        }
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{size, Modifiers, TestAppContext};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::{Duration, Instant},
    };

    #[gpui::test]
    fn activation_uses_network_runtime_and_keeps_errors_recoverable(cx: &mut TestAppContext) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        cx.update(|cx| gpui_tokio::init_from_handle(cx, runtime.handle().clone()));
        for success in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(8);
                loop {
                    if let Ok((mut stream, _)) = listener.accept() {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        let mut data = [0; 4096];
                        let n = stream.read(&mut data).unwrap();
                        let request = String::from_utf8_lossy(&data[..n]);
                        assert!(request.starts_with("POST /vault/schema "));
                        let (status, body) = if success {
                            ("200 OK", r#"{"supported_schema":2}"#)
                        } else {
                            ("404 Not Found", "{}")
                        };
                        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                        return;
                    }
                    assert!(Instant::now() < deadline, "activation did not reach server");
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let directory = tempfile::tempdir().unwrap();
            let state = Arc::new(AppState::for_test(directory.path()));
            state.unlock_for_test(&vela_desktop_core::crypto::Crypto::generate_rms());
            *state.server_url.write() = format!("http://{address}");
            state
                .session
                .write()
                .set_server_token("synthetic-token".into());
            let (host, cx) = cx.add_window_view(|_, cx| {
                ui::fonts(cx);
                let child = cx.new(|cx| {
                    let mut panel = OrganizationPanel::new(state.clone(), cx);
                    panel.open(Dialog::Setup, cx);
                    panel
                });
                ui::Host { child }
            });
            cx.simulate_resize(size(px(945.), px(600.)));
            cx.run_until_parked();
            let panel = host.read_with(cx, |host, _| host.child.clone());
            let enable = ui::bounds(cx, "enable-rich-items");
            cx.simulate_mouse_move(enable.center(), None, Modifiers::default());
            cx.simulate_click(enable.center(), Modifiers::default());
            cx.run_until_parked();
            let deadline = Instant::now() + Duration::from_secs(8);
            while panel.read_with(cx, |panel, _| panel.busy) {
                assert!(Instant::now() < deadline, "activation did not finish");
                runtime.block_on(async {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                });
                cx.run_until_parked();
            }
            // Report a local activation failure before waiting for a request
            // that never reached the mock server (for example, a backup error).
            panel.read_with(cx, |panel, _| {
                if success {
                    assert!(panel.error.is_none(), "activation failed: {:?}", panel.error);
                    assert!(panel.dialog.is_none());
                } else {
                    assert!(panel.dialog == Some(Dialog::Setup));
                    assert!(
                        panel.error.as_ref().is_some_and(|error| error.contains("Update the VELA server")),
                        "expected recoverable server error, got {:?}",
                        panel.error
                    );
                }
            });
            server.join().unwrap();
            assert_eq!(state.vault.read().schema_version == Some(2), success);
            assert!(directory
                .path()
                .join("vault.before-rich-items.enc")
                .exists());
        }
    }

    #[gpui::test]
    fn bulk_tag_editor_applies_explicit_changes_and_preserves_mixed_tags(cx: &mut TestAppContext) {
        let demo = crate::demo::DemoVault::new().unwrap();
        let (ids, important, family, review) = {
            let vault = demo.state.vault.read();
            (
                vault
                    .items
                    .iter()
                    .filter(|item| ["Personal email", "Project dashboard"].contains(&item.name()))
                    .map(|item| item.id().to_string())
                    .collect::<BTreeSet<_>>(),
                vault
                    .organization
                    .tags
                    .iter()
                    .find(|t| t.name == "Important")
                    .unwrap()
                    .id,
                vault
                    .organization
                    .tags
                    .iter()
                    .find(|t| t.name == "Family")
                    .unwrap()
                    .id,
                vault
                    .organization
                    .tags
                    .iter()
                    .find(|t| t.name == "Review later")
                    .unwrap()
                    .id,
            )
        };
        let (host, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            let child = cx.new(|cx| {
                let mut panel = OrganizationPanel::new(demo.state.clone(), cx);
                panel.selected = ids;
                panel.open(Dialog::Tags, cx);
                panel
            });
            ui::Host { child }
        });
        cx.simulate_resize(size(px(1280.), px(820.)));
        cx.run_until_parked();
        for id in [important, family] {
            let selector: &'static str =
                Box::leak(format!("assignment-{:?}", Some(id)).into_boxed_str());
            let bounds = ui::bounds(cx, selector);
            cx.simulate_mouse_move(bounds.center(), None, Modifiers::default());
            cx.simulate_click(bounds.center(), Modifiers::default());
            cx.run_until_parked();
        }
        let apply = ui::bounds(cx, "apply-tags");
        cx.simulate_mouse_move(apply.center(), None, Modifiers::default());
        cx.simulate_click(apply.center(), Modifiers::default());
        cx.run_until_parked();
        let vault = demo.state.vault.read();
        for name in ["Personal email", "Project dashboard"] {
            let item = vault.items.iter().find(|item| item.name() == name).unwrap();
            let tags = item.meta().rich.tag_ids.as_ref().unwrap();
            assert!(tags.contains(&important) && tags.contains(&family));
            assert_eq!(tags.contains(&review), name == "Project dashboard");
        }
        let panel = host.read_with(cx, |host, _| host.child.clone());
        assert!(panel.read_with(cx, |panel, _| panel.selected.is_empty()
            && panel.dialog.is_none()));
    }

    #[gpui::test]
    fn collection_dialog_actions_stay_visible_at_small_sizes(cx: &mut TestAppContext) {
        let directory = tempfile::tempdir().unwrap();
        let state = ui::state(&directory);
        state.vault.write().schema_version = Some(2);
        let (host, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            let child = cx.new(|cx| OrganizationPanel::new(state, cx));
            ui::Host { child }
        });
        for (width, height) in [(945., 382.), (360., 260.), (1450., 900.)] {
            let panel = host.read_with(cx, |host, _| host.child.clone());
            panel.update(cx, |panel, cx| panel.open(Dialog::Manage, cx));
            cx.simulate_resize(size(px(width), px(height)));
            cx.run_until_parked();
            let close = ui::bounds(cx, "close-collections");
            let footer = ui::bounds(cx, "collections-dialog-footer");
            assert!(close.top() >= px(0.) && footer.bottom() <= px(height));
            let body = ui::bounds(cx, "collections-content");
            cx.simulate_event(gpui::ScrollWheelEvent {
                position: body.center(),
                delta: gpui::ScrollDelta::Pixels(gpui::point(px(0.), px(-2000.))),
                ..Default::default()
            });
            cx.run_until_parked();
            assert_eq!(ui::bounds(cx, "close-collections"), close);
            cx.simulate_mouse_move(close.center(), None, Modifiers::default());
            cx.simulate_click(close.center(), Modifiers::default());
            cx.run_until_parked();
            assert!(panel.read_with(cx, |panel, _| panel.dialog.is_none()));
        }
    }
}

fn nav_row(
    id: String,
    label: String,
    icon_name: &'static str,
    selected: bool,
    depth: usize,
    p: &Palette,
) -> gpui::Stateful<Div> {
    let selector = id.clone();
    ui::navigation_row(gpui::SharedString::from(id), selected, p)
        .debug_selector(move || selector.clone())
        .py_2()
        .pr_5()
        .pl(px(24. + depth as f32 * 16.))
        .min_h(px(36.))
        .w_full()
        .hover(|el| el.bg(p.surface_container))
        .cursor_pointer()
        .child(icon(
            icon_name,
            px(16.),
            if selected {
                p.primary
            } else {
                p.on_surface_variant
            },
        ))
        .child(div().flex_1().min_w_0().text_ellipsis().child(label))
}
