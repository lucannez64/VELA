//! Port of `desktopVELA/src/components/AddItemModal.tsx` — add/edit item
//! form (login/card/secure note), embeds `PasswordGenerator`.
//!
//! Submit calls the real `vela_desktop_core::commands::vault::add_item` —
//! a genuine vault write against the real account.

use std::sync::Arc;

use chrono::Utc;
use gpui::{
    div, prelude::*, px, Context, Entity, EventEmitter, IntoElement, MouseButton, Render,
    SharedString, Window,
};
use gpui_elements::editable_text::{text_area, EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::add_item;
use vela_desktop_core::vault::{VaultItem, VaultMeta};
use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::theme::Palette;
use crate::ui::{self, labeled_field, toggle_row};
use crate::views::password_generator::{PasswordGenerator, PasswordGeneratorEvent};

#[derive(Clone, Copy, PartialEq)]
enum ItemKind {
    Login,
    CreditCard,
    SecureNote,
    Identity,
}

pub enum AddItemModalEvent {
    Close,
    /// A new item was actually saved — the owning `VaultBrowser` should
    /// reload its item list to show it.
    Created,
    /// An existing item was actually updated — the owner should reload/
    /// navigate back to reflect the change.
    Updated,
}
impl EventEmitter<AddItemModalEvent> for AddItemModal {}

pub struct AddItemModal {
    app_state: Arc<AppState>,
    rich_editor: Entity<crate::views::rich_editor::RichEditor>,
    first_name: Entity<EditableTextState>,
    last_name: Entity<EditableTextState>,
    ssn: Entity<EditableTextState>,
    kind: ItemKind,
    choosing_kind: bool,
    name: Entity<EditableTextState>,
    username: Entity<EditableTextState>,
    password: Entity<EditableTextState>,
    url: Entity<EditableTextState>,
    totp: Entity<EditableTextState>,
    notes: Entity<EditableTextState>,
    card_number: Entity<EditableTextState>,
    card_exp: Entity<EditableTextState>,
    card_cvv: Entity<EditableTextState>,
    card_pin: Entity<EditableTextState>,
    cardholder_name: Entity<EditableTextState>,
    secure_note_content: Entity<EditableTextState>,
    generator: Option<Entity<PasswordGenerator>>,
    _generator_subscription: Option<gpui::Subscription>,
    saving: bool,
    error: Option<SharedString>,
    /// M9a sign-in behaviour flags (login items only). Booleans here, sent as
    /// `Some(..)` on submit, so what the user sees ticked is exactly what gets
    /// saved — unlike an editor that omits the fields, which means
    /// "unchanged" and preserves the old value via `preserving_app_ids`.
    needs_reauth: bool,
    allow_downgrade: bool,
    /// `Some(original_meta)` when editing an existing item — preserves its
    /// id/created_at/favorite/shared/share_recipient (none of which the form
    /// itself edits) and makes `submit` call `update_item` instead of
    /// `add_item`.
    editing: Option<VaultMeta>,
}

impl AddItemModal {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify())
            .detach();
        let field = |cx: &mut Context<Self>| {
            cx.new(|cx| EditableTextState::new(StringStorage::default(), cx))
        };
        let rich_editor = cx.new(|cx| {
            crate::views::rich_editor::RichEditor::new(
                app_state.clone(),
                Default::default(),
                "login",
                cx,
            )
        });
        Self {
            rich_editor,
            first_name: field(cx),
            last_name: field(cx),
            ssn: field(cx),
            app_state,
            kind: ItemKind::Login,
            name: field(cx),
            username: field(cx),
            password: field(cx),
            url: field(cx),
            totp: field(cx),
            notes: field(cx),
            card_number: field(cx),
            card_exp: field(cx),
            card_cvv: field(cx),
            card_pin: field(cx),
            cardholder_name: field(cx),
            secure_note_content: field(cx),
            generator: None,
            _generator_subscription: None,
            saving: false,
            error: None,
            needs_reauth: false,
            allow_downgrade: false,
            editing: None,
            choosing_kind: true,
        }
    }

    pub fn new_in_collection(
        app_state: Arc<AppState>,
        rich: vela_desktop_core::rich_items::RichItemData,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut this = Self::new(app_state, cx);
        this.rich_editor = cx.new(|cx| {
            crate::views::rich_editor::RichEditor::new(this.app_state.clone(), rich, "login", cx)
        });
        this
    }

    /// Pre-fills the form from an existing item and switches `submit` to
    /// call `update_item` instead of `add_item`.
    pub fn new_edit(app_state: Arc<AppState>, item: VaultItem, cx: &mut Context<Self>) -> Self {
        let mut this = Self::new(app_state, cx);
        this.rich_editor = cx.new(|cx| {
            crate::views::rich_editor::RichEditor::new(
                this.app_state.clone(),
                item.meta().rich.clone(),
                if item.item_type() == vela_desktop_core::vault::ItemType::Identity {
                    "identity"
                } else if item.item_type() == vela_desktop_core::vault::ItemType::Login {
                    "login"
                } else {
                    "other"
                },
                cx,
            )
        });
        this.editing = Some(item.meta().clone());
        this.choosing_kind = false;
        this.name.update(cx, |s, cx| s.emplace(item.name(), cx));
        if let Some(notes) = item.notes() {
            this.notes.update(cx, |s, cx| s.emplace(notes, cx));
        }
        match &item {
            VaultItem::Login {
                url,
                username,
                pass,
                totp,
                credential_change_needs_reauth,
                allow_second_factor_downgrade,
                ..
            } => {
                this.kind = ItemKind::Login;
                this.url.update(cx, |s, cx| s.emplace(url, cx));
                this.username.update(cx, |s, cx| s.emplace(username, cx));
                this.password.update(cx, |s, cx| s.emplace(pass, cx));
                if let Some(totp) = totp {
                    this.totp.update(cx, |s, cx| s.emplace(totp, cx));
                }
                this.needs_reauth = credential_change_needs_reauth.unwrap_or(false);
                this.allow_downgrade = allow_second_factor_downgrade.unwrap_or(false);
            }
            VaultItem::CreditCard {
                number,
                exp,
                cvv,
                pin,
                cardholder_name,
                ..
            } => {
                this.kind = ItemKind::CreditCard;
                this.card_number.update(cx, |s, cx| s.emplace(number, cx));
                this.card_exp.update(cx, |s, cx| s.emplace(exp, cx));
                this.card_cvv.update(cx, |s, cx| s.emplace(cvv, cx));
                if let Some(pin) = pin {
                    this.card_pin.update(cx, |s, cx| s.emplace(pin, cx));
                }
                if let Some(name) = cardholder_name {
                    this.cardholder_name.update(cx, |s, cx| s.emplace(name, cx));
                }
            }
            VaultItem::SecureNote { content, .. } => {
                this.kind = ItemKind::SecureNote;
                this.secure_note_content
                    .update(cx, |s, cx| s.emplace(content, cx));
            }
            VaultItem::Identity {
                first_name,
                last_name,
                ssn,
                ..
            } => {
                this.kind = ItemKind::Identity;
                this.first_name
                    .update(cx, |s, cx| s.emplace(first_name, cx));
                this.last_name.update(cx, |s, cx| s.emplace(last_name, cx));
                this.ssn.update(cx, |s, cx| s.emplace(ssn, cx));
            }
            _ => {}
        }
        this
    }

    fn toggle_generator(&mut self, cx: &mut Context<Self>) {
        if self.generator.take().is_some() {
            self._generator_subscription = None;
            cx.notify();
            return;
        }
        let generator = cx.new(PasswordGenerator::new);
        let subscription = cx.subscribe(&generator, |this, _gen, event, cx| match event {
            PasswordGeneratorEvent::Use(password) => {
                this.password.update(cx, |state, cx| {
                    state.emplace(password, cx);
                });
                this.generator = None;
                this._generator_subscription = None;
                cx.notify();
            }
            PasswordGeneratorEvent::Close => {
                this.generator = None;
                this._generator_subscription = None;
                cx.notify();
            }
        });
        self.generator = Some(generator);
        self._generator_subscription = Some(subscription);
        cx.notify();
    }

    fn submit(&mut self, cx: &mut Context<Self>) {
        let name = self.name.read(cx).as_str().to_string();
        if name.trim().is_empty() {
            self.error = Some("Item name is required".into());
            cx.notify();
            return;
        }
        let notes = {
            let n = self.notes.read(cx).as_str().to_string();
            (!n.trim().is_empty()).then_some(n)
        };
        let now = Utc::now();
        let mut meta = match &self.editing {
            // Preserve everything the form doesn't itself edit.
            Some(original) => VaultMeta {
                rich: Default::default(),
                id: original.id.clone(),
                name,
                notes,
                created_at: original.created_at,
                updated_at: now,
                last_modified_device: original.last_modified_device.clone(),
                favorite: original.favorite,
                shared: original.shared,
                share_recipient: original.share_recipient.clone(),
            },
            None => VaultMeta {
                rich: Default::default(),
                id: String::new(), // replaced by add_item's own new UUID
                name,
                notes,
                created_at: now,
                updated_at: now,
                last_modified_device: None,
                favorite: false,
                shared: false,
                share_recipient: None,
            },
        };
        meta.rich = self.rich_editor.read(cx).value(cx);
        let item = match self.kind {
            ItemKind::Login => {
                let totp = {
                    let t = self.totp.read(cx).as_str().to_string();
                    (!t.trim().is_empty()).then_some(t)
                };
                // A user can enable the switch and then clear the TOTP field.
                // Do not persist a hidden downgrade opt-in with no code.
                let allow_downgrade = totp.is_some() && self.allow_downgrade;
                VaultItem::Login {
                    meta,
                    url: self.url.read(cx).as_str().to_string(),
                    username: self.username.read(cx).as_str().to_string(),
                    pass: self.password.read(cx).as_str().to_string(),
                    totp,
                    app_ids: Vec::new(),
                    credential_change_needs_reauth: Some(self.needs_reauth),
                    allow_second_factor_downgrade: Some(allow_downgrade),
                }
            }
            ItemKind::CreditCard => VaultItem::CreditCard {
                meta,
                number: self.card_number.read(cx).as_str().to_string(),
                exp: self.card_exp.read(cx).as_str().to_string(),
                cvv: self.card_cvv.read(cx).as_str().to_string(),
                pin: {
                    let p = self.card_pin.read(cx).as_str().to_string();
                    (!p.trim().is_empty()).then_some(p)
                },
                cardholder_name: {
                    let c = self.cardholder_name.read(cx).as_str().to_string();
                    (!c.trim().is_empty()).then_some(c)
                },
            },
            ItemKind::Identity => VaultItem::Identity {
                meta,
                first_name: self.first_name.read(cx).as_str().into(),
                last_name: self.last_name.read(cx).as_str().into(),
                ssn: self.ssn.read(cx).as_str().into(),
            },
            ItemKind::SecureNote => VaultItem::SecureNote {
                title: meta.name.clone(),
                meta,
                content: self.secure_note_content.read(cx).as_str().to_string(),
            },
        };

        self.saving = true;
        self.error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        let is_edit = self.editing.is_some();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                if is_edit {
                    vela_desktop_core::commands::vault::update_item(&app_state, item)
                        .await
                        .map(|_| ())
                } else {
                    add_item(&app_state, item).await.map(|_| ())
                }
            })
            .await
            .unwrap_or_else(|_| Err("Saving the item failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.saving = false;
                match result {
                    Ok(()) => cx.emit(if is_edit {
                        AddItemModalEvent::Updated
                    } else {
                        AddItemModalEvent::Created
                    }),
                    Err(e) => this.error = Some(format!("Failed to save item: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

impl Render for AddItemModal {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::modal::palette(cx);
        let choosing = palette.instrument && self.choosing_kind;

        let mut body = div().flex().flex_col().gap_4().child(labeled_field(
            &palette,
            "NAME *",
            ui::text_field("field-name", &self.name, &palette).placeholder("Item name"),
        ));

        body = match self.kind {
            ItemKind::Login => body
                .child(labeled_field(
                    &palette,
                    "USERNAME",
                    ui::text_field("field-username", &self.username, &palette)
                        .placeholder("username@email.com"),
                ))
                .child(
                    div()
                        .relative()
                        .child(labeled_field(
                            &palette,
                            "PASSWORD",
                            // Real masking via the vendored `gpui_elements`
                            // patch's `.mask_char()`. The original's password
                            // field is a plain `type="password"` with no
                            // reveal toggle here (unlike SetupScreen's shared
                            // `passwordVisible`), so this stays permanently
                            // masked to match.
                            ui::text_field("field-password", &self.password, &palette)
                                .placeholder("Password")
                                // Single-byte ASCII mask char — see
                                // biometric_gate.rs's `mask_char` comment for
                                // why '•' (multi-byte in UTF-8) misplaces the
                                // caret against ordinary ASCII passwords.
                                .mask_char(Some('*'))
                                .font_family(fonts::MONO),
                        ))
                        .child(
                            div()
                                .id("toggle-generate")
                                .absolute()
                                .top_8()
                                .right_2()
                                .px_2()
                                .py_1()
                                .rounded_md()
                                .bg(palette.surface_container_high)
                                .font_family(fonts::LABEL)
                                .text_xs()
                                .text_color(palette.primary)
                                .cursor_pointer()
                                .child("Generate")
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.toggle_generator(cx);
                                })),
                        ),
                )
                // The generator popover is a normal-flow sibling (pushes the
                // fields below it down when open) rather than absolutely
                // positioned over them. The original floats it above
                // everything via a real CSS `z-index` (`z-50` in
                // PasswordGenerator.tsx) — gpui has no z-index/stacking-
                // context equivalent, so an absolutely-positioned popover
                // here would paint *behind* the later fields (Website URL,
                // TOTP Secret, ...) instead of above them, since gpui's
                // paint order otherwise follows plain tree order. This was
                // confirmed as a real, confusing overlap bug, not a
                // hypothetical one.
                .when_some(self.generator.clone(), |el, generator| el.child(generator))
                .child(labeled_field(
                    &palette,
                    "WEBSITE URL",
                    ui::text_field("field-url", &self.url, &palette)
                        .placeholder("https://example.com"),
                ))
                .child(labeled_field(
                    &palette,
                    "TOTP SECRET",
                    ui::text_field("field-totp", &self.totp, &palette)
                        .placeholder("Base32 secret or OTPAUTH URL")
                        .font_family(fonts::MONO),
                ))
                // M9a sign-in behaviour (same controls as the webview UI's
                // AddItemModal "Sign-in behaviour" block). Without these the
                // flags could only be set from the Tauri front end, and the
                // gpui build shipped as Linux's UI could not express them.
                .when(self.kind == ItemKind::Login, |el| {
                    let has_totp = !self.totp.read(cx).as_str().trim().is_empty();
                    el.child(
                        div().flex().flex_col().gap_2()
                            .child(
                                div()
                                    .child(fonts::tracked_text("SIGN-IN BEHAVIOUR", px(12.), 0.1))
                                    .font_family(fonts::LABEL)
                                    .text_xs()
                                    .text_color(palette.outline),
                            )
                            .child(toggle_row(
                                &palette,
                                "needs-reauth",
                                self.needs_reauth,
                                "This site asks for my current password before changing it",
                                "If it does, signing out ends a stolen session's power.",
                                cx.listener(|this, _, _, cx| {
                                    this.needs_reauth = !this.needs_reauth;
                                    cx.notify();
                                }),
                            ))
                            // Only meaningful once there is a code to answer
                            // with; showing an unusable switch invites ticking
                            // it "just in case" (the webview UI hides it the
                            // same way).
                            .when(has_totp, |el| {
                                el.child(toggle_row(
                                    &palette,
                                    "allow-downgrade",
                                    self.allow_downgrade,
                                    "Use my authenticator code even when this site asks for a security key",
                                    "Deliberately takes the weaker of the two factors the site offered. A security key cannot be phished; a code can.",
                                    cx.listener(|this, _, _, cx| {
                                        this.allow_downgrade = !this.allow_downgrade;
                                        cx.notify();
                                    }),
                                ))
                            }),
                    )
                })
                .child(labeled_field(
                    &palette,
                    "NOTES",
                    text_area("field-notes")
                        .state(self.notes.downgrade())
                        .placeholder("Additional notes...")
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h(px(72.))
                        .max_h(px(96.))
                        .whitespace_normal()
                        .overflow_y_scroll(),
                )),
            ItemKind::CreditCard => body
                .child(labeled_field(
                    &palette,
                    "CARD NUMBER",
                    ui::text_field("field-card-number", &self.card_number, &palette)
                        .placeholder("•••• •••• •••• ••••")
                        .font_family(fonts::MONO),
                ))
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(labeled_field(
                            &palette,
                            "EXPIRY",
                            ui::text_field("field-card-exp", &self.card_exp, &palette)
                                .placeholder("MM/YY")
                                .font_family(fonts::MONO)
                                .flex_1(),
                        ))
                        .child(labeled_field(
                            &palette,
                            "CVV",
                            ui::text_field("field-card-cvv", &self.card_cvv, &palette)
                                .placeholder("•••")
                                .font_family(fonts::MONO)
                                .flex_1(),
                        ))
                        .child(labeled_field(
                            &palette,
                            "PIN",
                            ui::text_field("field-card-pin", &self.card_pin, &palette)
                                .placeholder("••••")
                                .font_family(fonts::MONO)
                                .flex_1(),
                        )),
                )
                .child(labeled_field(
                    &palette,
                    "CARDHOLDER NAME",
                    ui::text_field("field-cardholder", &self.cardholder_name, &palette)
                        .placeholder("JOHN DOE"),
                )),
            ItemKind::Identity => body
                .child(labeled_field(&palette,"FIRST NAME",ui::text_field("identity-first",&self.first_name,&palette)))
                .child(labeled_field(&palette,"LAST NAME",ui::text_field("identity-last",&self.last_name,&palette)))
                .child(labeled_field(&palette,"IDENTITY NUMBER / SSN",ui::text_field("identity-ssn",&self.ssn,&palette).mask_char(Some('*')))),
            ItemKind::SecureNote => body.child(labeled_field(
                &palette,
                "CONTENT",
                text_area("field-secure-note")
                    .state(self.secure_note_content.downgrade())
                    .placeholder("Your secure note content...")
                    .font_family(fonts::MONO)
                    .bg(palette.surface_container_highest)
                    .text_color(palette.on_surface)
                    .rounded_lg()
                    .p_3()
                    .w_full()
                    .min_h(px(160.))
                    .max_h(px(240.))
                    .whitespace_normal()
                    .overflow_y_scroll(),
            )),
        };

        let rich_kind = match self.kind {
            ItemKind::Login => "login",
            ItemKind::Identity => "identity",
            _ => "other",
        };
        self.rich_editor.update(cx, |rich, cx| {
            if rich.set_kind(rich_kind) {
                cx.notify();
            }
        });
        body = body.child(self.rich_editor.clone());
        let close = crate::modal::close_button("close-modal", &palette).on_mouse_down(
            MouseButton::Left,
            cx.listener(|_this, _, _, cx| {
                cx.emit(AddItemModalEvent::Close);
            }),
        );
        let header = crate::modal::header(
            if self.editing.is_some() {
                "Edit Item"
            } else {
                "Add New Item"
            },
            close,
            &palette,
        );
        let tabs = div()
            .flex()
            .gap_2()
            .flex_shrink_0()
            .pb_4()
            .child(kind_tab(
                &palette,
                "Login",
                self.kind == ItemKind::Login,
                window,
                cx,
                |this, cx| {
                    this.kind = ItemKind::Login;
                    cx.notify();
                },
            ))
            .child(kind_tab(
                &palette,
                "Card",
                self.kind == ItemKind::CreditCard,
                window,
                cx,
                |this, cx| {
                    this.kind = ItemKind::CreditCard;
                    cx.notify();
                },
            ))
            .child(kind_tab(
                &palette,
                "Secure Note",
                self.kind == ItemKind::SecureNote,
                window,
                cx,
                |this, cx| {
                    this.kind = ItemKind::SecureNote;
                    cx.notify();
                },
            ));
        let tabs = tabs.child(kind_tab(
            &palette,
            "Identity",
            self.kind == ItemKind::Identity,
            window,
            cx,
            |this, cx| {
                this.kind = ItemKind::Identity;
                cx.notify();
            },
        ));
        let content = div()
            .when(palette.instrument, |el| el.child(
                div().pt(px(8.)).pb(px(24.))
                    .child(crate::instrument::mono("01 / ITEM DETAILS", palette.on_surface_variant))
                    .child(div().mt(px(12.)).font_family(fonts::HEADLINE).text_size(px(34.)).child(
                        if self.editing.is_some() { "Make it current." } else { "Give it a place." }))
                    .child(div().mt(px(8.)).text_size(px(13.)).text_color(palette.on_surface_variant)
                        .child("Choose a type and add the details you want to keep in your vault."))))
            .child(tabs)
            .child(body)
            .when_some(self.error.clone(), |el, error| {
                el.child(
                    div()
                        .mt_3()
                        .text_sm()
                        .text_color(palette.error)
                        .child(error),
                )
            });
        let content = if choosing {
            let choices = [
                (ItemKind::Login, "Login", "Username, password and sign-in details", "key"),
                (ItemKind::CreditCard, "Card", "Payment details, always close at hand", "credit_card"),
                (ItemKind::SecureNote, "Secure Note", "Private notes and recovery codes", "note"),
                (ItemKind::Identity, "Identity", "Personal details for your forms", "person"),
            ];
            let mut grid = div().flex().flex_col().gap(px(12.));
            for row in choices.chunks(2) {
                grid = grid.child(div().flex().gap(px(12.)).children(row.iter().map(|(kind, label, description, glyph)| {
                    let kind = *kind;
                    div().id(SharedString::from(format!("choose-{label}"))).debug_selector(move || format!("choose-{label}"))
                        .flex_1().min_w_0().p(px(18.)).rounded(px(20.)).bg(palette.surface_container_high)
                        .border_1().border_color(palette.outline_variant).cursor_pointer()
                        .hover(|el| el.border_color(palette.primary))
                        .child(crate::instrument::icons::icon(glyph, px(24.), palette.on_surface))
                        .child(div().mt(px(26.)).text_size(px(16.)).child(*label))
                        .child(div().mt(px(6.)).text_size(px(12.)).line_height(px(18.)).text_color(palette.on_surface_variant).child(*description))
                        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                            this.kind = kind; this.choosing_kind = false; cx.notify();
                        }))
                })));
            }
            div().pt(px(12.))
                .child(div().font_family(fonts::HEADLINE).text_size(px(34.)).child("What are you saving?"))
                .child(div().mt(px(10.)).mb(px(24.)).text_size(px(13.)).text_color(palette.on_surface_variant)
                    .child("Pick a type. You can add custom fields to any of them."))
                .child(grid)
        } else { content };
        let footer = div()
            .flex()
            .gap_4()
            .flex_shrink_0()
            .when(palette.instrument, |el| el.justify_end().gap(px(8.)))
            .child(
                ui::secondary_button("cancel".into(), "Cancel", &palette)
                    .flex_1()
                    .when(palette.instrument, |el| el.flex_initial())
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _, _, cx| {
                            if !this.saving {
                                cx.emit(AddItemModalEvent::Close);
                            }
                        }),
                    ),
            )
            .when(!choosing, |el| el.child(
                ui::primary_button(
                    "submit".into(),
                    if self.saving {
                        "Saving…"
                    } else if self.editing.is_some() {
                        "Save Changes"
                    } else {
                        "Create Item"
                    },
                    &palette,
                )
                .flex_1()
                .when(palette.instrument, |el| el.flex_initial())
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| this.submit(cx)),
                ),
            ));
        let overlay = crate::modal::backdrop("add-item-backdrop")
            .when(palette.instrument, |el| el.justify_end())
            .font_family(fonts::LABEL)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|_, _, _, cx| cx.emit(AddItemModalEvent::Close)),
            )
            .child(
                crate::modal::frame(
                    "add-item-card",
                    if palette.instrument { 620. } else { 560. },
                    if palette.instrument { f32::from(window.viewport_size().height) } else { 640. },
                    header,
                    crate::modal::scroll_body("add-item-content", content),
                    footer,
                    &palette,
                )
                .map(|el| crate::keyboard::trap_tab(el, "add-item-card-trap", window, cx))
                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _, cx| {
                    if !this.saving && !(crate::instrument::is_instrument(cx) && this.choosing_kind) {
                        this.submit(cx);
                    }
                }))
                .on_key_down(cx.listener(
                    |_, event: &gpui::KeyDownEvent, _, cx| {
                        if event.keystroke.key == "escape" {
                            cx.stop_propagation();
                            cx.emit(AddItemModalEvent::Close);
                        }
                    },
                ))
                .map(|card| crate::modal::animate(card, palette.instrument, true)),
            );
        crate::modal::present(window, overlay)
    }
}

fn kind_tab(
    palette: &Palette,
    label: &'static str,
    active: bool,
    window: &mut Window,
    cx: &mut Context<AddItemModal>,
    on_click: impl Fn(&mut AddItemModal, &mut Context<AddItemModal>) + 'static,
) -> impl IntoElement {
    let id = SharedString::from(format!("tab-{label}"));
    let (base_bg, text) = if active {
        (palette.surface_container_high, palette.primary)
    } else {
        (palette.surface_container, palette.on_surface_variant)
    };
    let bg = if active {
        base_bg
    } else {
        let hover_t = animation::hover_transition(id.clone(), window, cx);
        let t = *hover_t.evaluate(window, cx);
        animation::lerp_hsla(base_bg, palette.surface_container_high, t)
    };
    let mut el = div()
        .id(id.clone())
        .flex_1()
        .py_2()
        .rounded_lg()
        .when(palette.instrument, |el| el.rounded_full().border_1().border_color(if active { palette.primary } else { palette.outline_variant }))
        .bg(bg)
        .text_color(text)
        .font_family(fonts::LABEL)
        .text_sm()
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .child(label);
    if !active {
        let hover_t = animation::hover_transition(id, window, cx);
        el = el.on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        });
    }
    el.on_mouse_down(
        MouseButton::Left,
        cx.listener(move |this, _, _, cx| on_click(this, cx)),
    )
}

#[cfg(test)]
mod modal_tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{point, size, Modifiers, ScrollDelta, ScrollWheelEvent, TestAppContext};
    use std::{cell::Cell, rc::Rc};

    struct Host {
        child: Entity<AddItemModal>,
        _subscription: gpui::Subscription,
    }
    impl Render for Host {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            div().relative().size_full().child(
                div()
                    .relative()
                    .ml(px(64.))
                    .mt(px(70.))
                    .w(px(160.))
                    .h(px(100.))
                    .overflow_hidden()
                    .child(self.child.clone()),
            )
        }
    }

    #[gpui::test]
    fn instrument_editor_is_a_drawer_with_fixed_actions(cx: &mut TestAppContext) {
        let directory = tempfile::tempdir().unwrap();
        let state = ui::state(&directory);
        let (_, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            cx.set_global(crate::instrument::ActiveInterface(crate::instrument::InterfaceMode::Instrument));
            let child = cx.new(|cx| { let mut editor = AddItemModal::new(state, cx); editor.choosing_kind = false; editor });
            ui::Host { child }
        });
        for (width, height) in [(1440., 900.), (945., 1025.), (390., 620.)] {
            cx.simulate_resize(size(px(width), px(height)));
            cx.run_until_parked();
            let card = ui::bounds(cx, "add-item-card");
            assert!((card.right() - px(width - 12.)).abs() < px(2.));
            assert!(card.size.width <= px(620.));
            let footer = ui::bounds(cx, "add-item-card-footer");
            assert!(footer.bottom() <= px(height));
            let content = ui::bounds(cx, "add-item-content");
            cx.simulate_event(ScrollWheelEvent {
                position: content.center(),
                delta: ScrollDelta::Pixels(point(px(0.), px(-2000.))),
                ..Default::default()
            });
            cx.run_until_parked();
            assert_eq!(ui::bounds(cx, "add-item-card-footer"), footer);
        }
    }

    #[gpui::test]
    fn rich_editor_actions_remain_readable_inside_scrolling_modal(cx: &mut TestAppContext) {
        let directory = tempfile::tempdir().unwrap();
        let state = ui::state(&directory);
        state.vault.write().schema_version = Some(2);
        let rich=serde_json::from_value(serde_json::json!({"customFields":[{"id":vela_desktop_core::Uuid::new_v4(),"label":"Recovery","type":"concealed","value":""}],"additionalUrls":[{"id":vela_desktop_core::Uuid::new_v4(),"url":"","match":"origin"}]})).unwrap();
        let (_, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            cx.set_global(crate::theme::ActiveTheme(crate::theme::ThemeId::Macchiato));
            let child = cx.new(|cx| AddItemModal::new_in_collection(state, rich, cx));
            ui::Host { child }
        });
        for (width, height) in [
            (1280., 820.),
            (945., 1025.),
            (640., 600.),
            (480., 480.),
            (360., 480.),
            (320., 480.),
        ] {
            cx.simulate_resize(size(px(width), px(height)));
            cx.run_until_parked();
            let body = ui::bounds(cx, "add-item-content");
            cx.simulate_event(ScrollWheelEvent {
                position: body.center(),
                delta: ScrollDelta::Pixels(point(px(0.), px(-4000.))),
                ..Default::default()
            });
            cx.run_until_parked();
            for (id, min_width) in [
                ("add-rich-field-label", 100.),
                ("url-mode-0-label", 80.),
                ("remove-url-0-label", 70.),
                ("add-url-label", 50.),
            ] {
                let bounds = crate::ui::action_label_bounds(cx, id);
                assert!(
                    bounds.size.width >= px(min_width),
                    "collapsed rich action at {width}×{height}: {id}: {bounds:?}"
                );
                assert!(
                    bounds.left() >= px(0.) && bounds.right() <= px(width),
                    "action overflow at {width}×{height}: {id}: {bounds:?}"
                );
            }
            assert!(ui::bounds(cx, "add-item-card-footer").bottom() <= px(height));
        }
    }

    #[gpui::test]
    fn editor_close_works_after_scrolling_real_fields(cx: &mut TestAppContext) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let directory = tempfile::tempdir().unwrap();
        let state = ui::state(&directory);
        let closes = Rc::new(Cell::new(0));
        let (host, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            let child = cx.new(|cx| AddItemModal::new(state, cx));
            let _subscription = cx.subscribe(&child, {
                let closes = closes.clone();
                move |_: &mut Host, _, event, _| {
                    if matches!(event, AddItemModalEvent::Close) {
                        closes.set(closes.get() + 1);
                    }
                }
            });
            Host {
                child,
                _subscription,
            }
        });
        for (width, height) in [(945., 382.), (360., 260.)] {
            cx.simulate_resize(size(px(width), px(height)));
            cx.run_until_parked();
            let close = ui::bounds(cx, "close-modal");
            let footer = ui::bounds(cx, "add-item-card-footer");
            let body = ui::bounds(cx, "add-item-content");
            assert!(close.top() >= px(0.) && footer.bottom() <= px(height));
            cx.simulate_event(ScrollWheelEvent {
                position: body.center(),
                delta: ScrollDelta::Pixels(point(px(0.), px(-3000.))),
                ..Default::default()
            });
            cx.run_until_parked();
            assert_eq!(ui::bounds(cx, "close-modal"), close);
            let before = closes.get();
            cx.simulate_mouse_move(close.center(), None, Modifiers::default());
            cx.simulate_click(close.center(), Modifiers::default());
            cx.run_until_parked();
            assert_eq!(
                closes.get(),
                before + 1,
                "close failed after scroll at {width}×{height}: {close:?}; body={body:?}"
            );
        }
        assert_eq!(closes.get(), 2);
        drop(host);
    }
}
