use crate::ui::{choice_row as choice, secondary_button as button};
use crate::{theme::Palette, ui};
use gpui::{
    div, prelude::*, Context, Entity, IntoElement, MouseButton, Render, SharedString, Window,
};
use gpui_elements::editable_text::{EditableTextState, StringStorage};
use std::{collections::BTreeMap, sync::Arc};
use vela_desktop_core::{rich_items::*, AppState, Uuid};

struct FieldRow {
    original: CustomField,
    label: Entity<EditableTextState>,
    value: Entity<EditableTextState>,
    revealed: bool,
}
struct UrlRow {
    original: AdditionalUrl,
    value: Entity<EditableTextState>,
}
struct AddressRow {
    original: PostalAddress,
    values: Vec<Entity<EditableTextState>>,
}
pub struct RichEditor {
    state: Arc<AppState>,
    original: RichItemData,
    kind: String,
    folder: String,
    tags: Vec<Uuid>,
    fields: Vec<FieldRow>,
    urls: Vec<UrlRow>,
    identity: IdentityDetails,
    contacts: Vec<Entity<EditableTextState>>,
    addresses: Vec<AddressRow>,
    folder_picker: bool,
    tag_picker: bool,
    field_menu: Option<usize>,
}

const CONTACTS: [&str; 6] = [
    "Middle name",
    "Preferred name",
    "Email",
    "Phone",
    "Company",
    "Job title",
];
const ADDRESS: [&str; 7] = [
    "Label",
    "Address line 1",
    "Address line 2",
    "City",
    "Region",
    "Postal code",
    "Country code",
];

pub fn input(cx: &mut Context<RichEditor>, value: &str) -> Entity<EditableTextState> {
    cx.new(|cx| {
        let mut s = EditableTextState::new(StringStorage::default(), cx);
        s.emplace(value, cx);
        s
    })
}

fn field_with_font(
    label: &str,
    state: &Entity<EditableTextState>,
    p: &Palette,
    concealed: bool,
    mono: bool,
) -> gpui::Div {
    ui::labeled_field(
        p,
        label,
        ui::text_field(
            SharedString::from(format!("rich-input-{:?}", state.entity_id())),
            state,
            p,
        )
        .mask_char(concealed.then_some('*'))
        .when(mono, |el| el.font_family(crate::fonts::MONO)),
    )
    .flex_1()
}

fn field(
    label: &str,
    state: &Entity<EditableTextState>,
    p: &Palette,
    concealed: bool,
) -> gpui::Div {
    field_with_font(label, state, p, concealed, concealed)
}

impl RichEditor {
    pub fn new(
        state: Arc<AppState>,
        original: RichItemData,
        kind: &str,
        cx: &mut Context<Self>,
    ) -> Self {
        let fields = original
            .custom_fields
            .as_ref()
            .map(|fs| {
                fs.iter()
                    .map(|f| FieldRow {
                        original: f.clone(),
                        label: input(cx, &f.label),
                        value: input(
                            cx,
                            f.value
                                .0
                                .as_str()
                                .unwrap_or(if f.value.0.as_bool() == Some(true) {
                                    "true"
                                } else {
                                    "false"
                                }),
                        ),
                        revealed: false,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let urls = original
            .additional_urls
            .as_ref()
            .map(|us| {
                us.iter()
                    .map(|u| UrlRow {
                        original: u.clone(),
                        value: input(cx, &u.url),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let identity = original.identity_details.clone().unwrap_or_default();
        let contacts = [
            &identity.middle_name,
            &identity.preferred_name,
            &identity.email,
            &identity.phone,
            &identity.company,
            &identity.job_title,
        ]
        .iter()
        .map(|v| input(cx, v.as_deref().unwrap_or("")))
        .collect();
        let addresses = identity
            .addresses
            .iter()
            .map(|a| Self::address(a.clone(), cx))
            .collect();
        Self {
            folder_picker: false,
            tag_picker: false,
            field_menu: None,
            state,
            folder: original.folder_id.clone().unwrap_or_default(),
            tags: original.tag_ids.clone().unwrap_or_default(),
            original,
            kind: kind.into(),
            fields,
            urls,
            identity,
            contacts,
            addresses,
        }
    }

    fn address(original: PostalAddress, cx: &mut Context<Self>) -> AddressRow {
        let values = [
            &original.label,
            &original.line1,
            &original.line2,
            &original.city,
            &original.region,
            &original.postal_code,
            &original.country_code,
        ]
        .iter()
        .map(|v| input(cx, v.as_deref().unwrap_or("")))
        .collect();
        AddressRow { original, values }
    }

    pub fn set_kind(&mut self, kind: &str) -> bool {
        if self.kind == kind {
            false
        } else {
            self.kind = kind.into();
            true
        }
    }

    pub fn value(&self, cx: &gpui::App) -> RichItemData {
        if self.state.vault.read().schema_version != Some(2) {
            return self.original.clone();
        }
        let mut rich = self.original.clone();
        rich.folder_id = Some(self.folder.clone());
        rich.tag_ids = Some(self.tags.clone());
        rich.custom_fields = Some(
            self.fields
                .iter()
                .map(|f| {
                    let mut field = f.original.clone();
                    if !matches!(field.kind, CustomFieldType::Unknown(_)) {
                        field.label = f.label.read(cx).as_str().into();
                        field.value = SensitiveValue(if field.kind == CustomFieldType::Boolean {
                            serde_json::json!(f.value.read(cx).as_str() == "true")
                        } else {
                            serde_json::json!(f.value.read(cx).as_str())
                        });
                    }
                    field
                })
                .collect(),
        );
        if self.kind == "login" {
            rich.additional_urls = Some(
                self.urls
                    .iter()
                    .map(|u| {
                        let mut v = u.original.clone();
                        if !matches!(v.match_mode, UrlMatch::Unknown(_)) {
                            v.url = u.value.read(cx).as_str().into();
                        }
                        v
                    })
                    .collect(),
            );
        }
        if self.kind == "identity" {
            let mut d = self.identity.clone();
            let values: Vec<Option<String>> = self
                .contacts
                .iter()
                .map(|s| {
                    let s = s.read(cx).as_str();
                    (!s.is_empty()).then(|| s.to_string())
                })
                .collect();
            d.middle_name = values[0].clone();
            d.preferred_name = values[1].clone();
            d.email = values[2].clone();
            d.phone = values[3].clone();
            d.company = values[4].clone();
            d.job_title = values[5].clone();
            d.addresses = self
                .addresses
                .iter()
                .map(|row| {
                    let mut a = row.original.clone();
                    let v: Vec<Option<String>> = row
                        .values
                        .iter()
                        .map(|s| {
                            let s = s.read(cx).as_str();
                            (!s.is_empty()).then(|| s.to_string())
                        })
                        .collect();
                    a.label = v[0].clone();
                    a.line1 = v[1].clone();
                    a.line2 = v[2].clone();
                    a.city = v[3].clone();
                    a.region = v[4].clone();
                    a.postal_code = v[5].clone();
                    a.country_code = v[6].clone();
                    a
                })
                .collect();
            rich.identity_details = Some(d);
        }
        rich
    }
}

impl Render for RichEditor {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let p = crate::modal::palette(cx);
        let vault = self.state.vault.read();
        if vault.schema_version != Some(2) {
            return div().text_sm().text_color(p.on_surface_variant).child("Enable folders and richer items in the vault to add organization and custom fields.").into_any_element();
        }
        let org = vault.organization.clone();
        drop(vault);
        let mut body = div()
            .text_color(p.on_surface)
            .font_family(crate::fonts::LABEL)
            .flex()
            .flex_col()
            .gap_3()
            .pt_5()
            .border_t_1()
            .border_color(gpui::Hsla {
                a: 0.1,
                ..p.outline_variant
            });
        body = body.child(ui::section_heading("Organization", &p));
        let folder_label = Uuid::parse_str(&self.folder)
            .ok()
            .filter(|id| org.folder(*id).is_some())
            .map(|id| folder_path(&org, id))
            .unwrap_or_else(|| "Unfiled".into());
        body = body.child(ui::labeled_field(
            &p,
            "Folder",
            ui::select_trigger("rich-folder-picker".into(), folder_label, &p).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.folder_picker = !this.folder_picker;
                    this.tag_picker = false;
                    cx.notify();
                }),
            ),
        ));
        if self.folder_picker {
            let mut folders = div().flex().flex_col().gap_2().child(
                choice(
                    "rich-unfiled".into(),
                    "Unfiled",
                    self.folder.is_empty(),
                    false,
                    &p,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        this.folder.clear();
                        this.folder_picker = false;
                        cx.notify();
                    }),
                ),
            );
            for f in &org.folders {
                let id = f.id.to_string();
                let label = folder_path(&org, f.id);
                folders = folders.child(
                    choice(
                        format!("rich-folder-{id}"),
                        label,
                        self.folder == id,
                        false,
                        &p,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.folder = id.clone();
                            this.folder_picker = false;
                            cx.notify();
                        }),
                    ),
                );
            }
            body = body.child(
                div()
                    .id("folder-options")
                    .max_h(gpui::px(180.))
                    .overflow_y_scroll()
                    .child(folders.flex_col()),
            );
        }
        let tag_label = self
            .tags
            .iter()
            .filter_map(|id| org.tag(*id).map(|t| t.name.clone()))
            .collect::<Vec<_>>()
            .join(", ");
        body = body.child(ui::labeled_field(
            &p,
            "Tags",
            ui::select_trigger(
                "rich-tag-picker".into(),
                if tag_label.is_empty() {
                    "Add tags…".to_string()
                } else {
                    tag_label
                },
                &p,
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.tag_picker = !this.tag_picker;
                    this.folder_picker = false;
                    cx.notify();
                }),
            ),
        ));
        if self.tag_picker {
            let mut tags = div().flex().flex_col().gap_2();
            for t in &org.tags {
                let id = t.id;
                tags = tags.child(
                    choice(
                        format!("rich-tag-{id}"),
                        t.name.clone(),
                        self.tags.contains(&id),
                        true,
                        &p,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            if this.tags.contains(&id) {
                                this.tags.retain(|t| *t != id);
                            } else {
                                this.tags.push(id);
                            }
                            cx.notify();
                        }),
                    ),
                );
            }
            body = body.child(
                div()
                    .id("tag-options")
                    .max_h(gpui::px(180.))
                    .overflow_y_scroll()
                    .child(tags.flex_col()),
            );
            if org.tags.is_empty() {
                body = body.child(
                    div()
                        .text_sm()
                        .child("Use + beside Tags in the vault sidebar."),
                );
            }
        }
        body = body.child(ui::section_heading("Custom fields", &p).mt_3());
        for (i, row) in self.fields.iter().enumerate() {
            if matches!(row.original.kind, CustomFieldType::Unknown(_)) {
                body = body.child(div().child(format!(
                    "{} — unsupported field preserved",
                    row.original.label
                )));
                continue;
            }
            let mut controls = div().flex().flex_wrap().gap_2();
            if self.field_menu == Some(i) {
                for (key, kind) in [
                    ("Text", CustomFieldType::Text),
                    ("Concealed", CustomFieldType::Concealed),
                    ("Boolean", CustomFieldType::Boolean),
                ] {
                    controls = controls.child(
                        choice(
                            format!("field-type-{i}-{key}"),
                            key,
                            row.original.kind == kind,
                            false,
                            &p,
                        )
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.fields[i].original.kind = kind.clone();
                                this.fields[i].revealed = false;
                                this.field_menu = None;
                                cx.notify();
                            }),
                        ),
                    );
                }
            }
            let mut content = ui::field_card(&p)
                .child(field("Label", &row.label, &p, false))
                .child(
                    ui::select_trigger(
                        format!("field-options-{i}"),
                        format!("{:?}", row.original.kind),
                        &p,
                    )
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.field_menu = if this.field_menu == Some(i) {
                                None
                            } else {
                                Some(i)
                            };
                            cx.notify();
                        }),
                    ),
                )
                .child(controls);
            if row.original.kind == CustomFieldType::Boolean {
                let checked = row.value.read(cx).as_str() == "true";
                content = content.child(ui::toggle_row(
                    &p,
                    format!("bool-{i}"),
                    checked,
                    "Enabled",
                    "",
                    cx.listener(move |this, _, _, cx| {
                        this.fields[i].value.update(cx, |s, cx| {
                            s.emplace(if checked { "false" } else { "true" }, cx)
                        });
                        cx.notify();
                    }),
                ));
            } else {
                let mut value_row = div().flex().items_end().gap_2().child(field_with_font(
                    "Value",
                    &row.value,
                    &p,
                    row.original.kind == CustomFieldType::Concealed && !row.revealed,
                    row.original.kind == CustomFieldType::Concealed,
                ));
                if row.original.kind == CustomFieldType::Concealed {
                    value_row = value_row.child(
                        ui::icon_button(
                            format!("reveal-field-{i}"),
                            if row.revealed {
                                "visibility_off"
                            } else {
                                "visibility"
                            },
                            gpui::px(18.),
                            p.on_surface_variant,
                        )
                        .mb_2()
                        .hover(|el| el.bg(p.surface_container_highest))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.fields[i].revealed = !this.fields[i].revealed;
                                cx.notify();
                            }),
                        ),
                    );
                }
                content = content.child(value_row);
            }
            if self.field_menu == Some(i) {
                let mut actions = div().flex().flex_wrap().gap_2();
                if i > 0 {
                    actions = actions.child(
                        button(format!("up-field-{i}"), "Move up", &p).on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.fields.swap(i, i - 1);
                                this.field_menu = None;
                                cx.notify();
                            }),
                        ),
                    );
                }
                if i + 1 < self.fields.len() {
                    actions = actions.child(
                        button(format!("down-field-{i}"), "Move down", &p).on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.fields.swap(i, i + 1);
                                this.field_menu = None;
                                cx.notify();
                            }),
                        ),
                    );
                }
                actions = actions.child(
                    button(format!("remove-field-{i}"), "Remove field", &p).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.fields.remove(i);
                            this.field_menu = None;
                            cx.notify();
                        }),
                    ),
                );
                content = content.child(actions);
            }
            body = body.child(content);
        }
        body = body.child(
            button("add-rich-field".into(), "Add custom field", &p).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    if this.fields.len() < MAX_CUSTOM_FIELDS {
                        this.fields.push(FieldRow {
                            original: CustomField {
                                id: Uuid::new_v4(),
                                label: String::new(),
                                kind: CustomFieldType::Concealed,
                                value: SensitiveValue(serde_json::json!("")),
                                extra: BTreeMap::new(),
                            },
                            label: input(cx, ""),
                            value: input(cx, ""),
                            revealed: false,
                        });
                        cx.notify();
                    }
                }),
            ),
        );
        if self.kind == "login" {
            body = body
                .child(ui::section_heading("Additional sites", &p))
                .child(
                    div()
                        .text_sm()
                        .child("Stored with this login. Autofill currently uses the primary URL."),
                );
            for (i, row) in self.urls.iter().enumerate() {
                if matches!(row.original.match_mode, UrlMatch::Unknown(_)) {
                    body = body.child(div().child("Unsupported URL rule preserved"));
                    continue;
                }
                body = body.child(field("HTTPS URL", &row.value, &p, false)).child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            button(
                                format!("url-mode-{i}"),
                                format!("Match: {:?}", row.original.match_mode),
                                &p,
                            )
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |this, _, _, cx| {
                                    this.urls[i].original.match_mode =
                                        if this.urls[i].original.match_mode == UrlMatch::Origin {
                                            UrlMatch::Exact
                                        } else {
                                            UrlMatch::Origin
                                        };
                                    cx.notify();
                                }),
                            ),
                        )
                        .child(
                            button(format!("remove-url-{i}"), "Remove URL", &p).on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |this, _, _, cx| {
                                    this.urls.remove(i);
                                    cx.notify();
                                }),
                            ),
                        ),
                );
            }
            body = body.child(button("add-url".into(), "Add site", &p).on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    if this.urls.len() < MAX_ADDITIONAL_URLS {
                        this.urls.push(UrlRow {
                            original: AdditionalUrl {
                                id: Uuid::new_v4(),
                                url: String::new(),
                                match_mode: UrlMatch::Origin,
                                extra: BTreeMap::new(),
                            },
                            value: input(cx, ""),
                        });
                        cx.notify();
                    }
                }),
            ));
        }
        if self.kind == "identity" {
            body = body.child(ui::section_heading("Contact and addresses", &p));
            for (i, label) in CONTACTS.iter().enumerate() {
                body = body.child(field(label, &self.contacts[i], &p, false));
            }
            for (i, address) in self.addresses.iter().enumerate() {
                let mut card =
                    ui::field_card(&p).child(ui::form_label(&format!("Address {}", i + 1), &p));
                for (j, label) in ADDRESS.iter().enumerate() {
                    card = card.child(field(label, &address.values[j], &p, false));
                }
                body = body.child(card.child(
                    button(format!("remove-address-{i}"), "Remove address", &p).on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.addresses.remove(i);
                            cx.notify();
                        }),
                    ),
                ));
            }
            body = body.child(
                button("add-address".into(), "Add address", &p).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        if this.addresses.len() < MAX_ADDRESSES {
                            let mut original = PostalAddress::default();
                            original.id = Uuid::new_v4();
                            let address = Self::address(original, cx);
                            this.addresses.push(address);
                            cx.notify();
                        }
                    }),
                ),
            );
        }
        body.into_any_element()
    }
}

pub fn folder_path(org: &OrganizationData, id: Uuid) -> String {
    let parents = org.display_parents();
    let mut names = Vec::new();
    let mut cursor = Some(id);
    while let Some(id) = cursor {
        if let Some(f) = org.folder(id) {
            names.push(f.name.clone());
            cursor = parents.get(&id).copied().flatten();
        } else {
            break;
        }
    }
    names.reverse();
    names.join(" / ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{px, size, Modifiers, TestAppContext};

    #[gpui::test]
    fn compact_pickers_assign_without_exposing_all_options(cx: &mut TestAppContext) {
        let directory = tempfile::tempdir().unwrap();
        let state = ui::state(&directory);
        let (folder, tag) = {
            let mut vault = state.vault.write();
            vault.schema_version = Some(2);
            let folder = vault
                .organization
                .create_folder("Personal", None, "fixture", chrono::Utc::now())
                .unwrap();
            let tag = vault
                .organization
                .create_tag("Important", "fixture", chrono::Utc::now())
                .unwrap();
            (folder, tag)
        };
        let (host, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            let child = cx.new(|cx| RichEditor::new(state, RichItemData::default(), "login", cx));
            ui::Host { child }
        });
        cx.simulate_resize(size(px(640.), px(900.)));
        cx.run_until_parked();
        assert!(cx.debug_bounds("rich-unfiled").is_none());
        for selector in [
            "rich-folder-picker".to_string(),
            format!("rich-folder-{folder}"),
            "rich-tag-picker".into(),
            format!("rich-tag-{tag}"),
        ] {
            let selector: &'static str = Box::leak(selector.into_boxed_str());
            let bounds = cx.debug_bounds(selector).unwrap();
            cx.simulate_mouse_move(bounds.center(), None, Modifiers::default());
            cx.simulate_click(bounds.center(), Modifiers::default());
            cx.run_until_parked();
        }
        let editor = host.read_with(cx, |host, _| host.child.clone());
        editor.read_with(cx, |editor, cx| {
            let value = editor.value(cx);
            assert_eq!(value.folder_id, Some(folder.to_string()));
            assert_eq!(value.tag_ids, Some(vec![tag]));
            assert!(!editor.folder_picker);
            assert!(editor.tag_picker);
        });
    }
}
