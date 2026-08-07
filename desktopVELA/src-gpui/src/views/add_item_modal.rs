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
use gpui_elements::editable_text::{text_area, text_input, EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::add_item;
use vela_desktop_core::vault::{VaultItem, VaultMeta};
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;
use crate::views::password_generator::{PasswordGenerator, PasswordGeneratorEvent};

#[derive(Clone, Copy, PartialEq)]
enum ItemKind {
    Login,
    CreditCard,
    SecureNote,
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
    kind: ItemKind,
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
    /// `Some(original_meta)` when editing an existing item — preserves its
    /// id/created_at/favorite/shared/share_recipient (none of which the form
    /// itself edits) and makes `submit` call `update_item` instead of
    /// `add_item`.
    editing: Option<VaultMeta>,
}

impl AddItemModal {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let field = |cx: &mut Context<Self>| cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));
        Self {
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
            editing: None,
        }
    }

    /// Pre-fills the form from an existing item and switches `submit` to
    /// call `update_item` instead of `add_item`.
    pub fn new_edit(app_state: Arc<AppState>, item: VaultItem, cx: &mut Context<Self>) -> Self {
        let mut this = Self::new(app_state, cx);
        this.editing = Some(item.meta().clone());
        this.name.update(cx, |s, cx| s.emplace(item.name(), cx));
        if let Some(notes) = item.notes() {
            this.notes.update(cx, |s, cx| s.emplace(notes, cx));
        }
        match &item {
            VaultItem::Login { url, username, pass, totp, .. } => {
                this.kind = ItemKind::Login;
                this.url.update(cx, |s, cx| s.emplace(url, cx));
                this.username.update(cx, |s, cx| s.emplace(username, cx));
                this.password.update(cx, |s, cx| s.emplace(pass, cx));
                if let Some(totp) = totp {
                    this.totp.update(cx, |s, cx| s.emplace(totp, cx));
                }
            }
            VaultItem::CreditCard { number, exp, cvv, pin, cardholder_name, .. } => {
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
                this.secure_note_content.update(cx, |s, cx| s.emplace(content, cx));
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
        let meta = match &self.editing {
            // Preserve everything the form doesn't itself edit.
            Some(original) => VaultMeta {
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
        let item = match self.kind {
            ItemKind::Login => VaultItem::Login {
                meta,
                url: self.url.read(cx).as_str().to_string(),
                username: self.username.read(cx).as_str().to_string(),
                pass: self.password.read(cx).as_str().to_string(),
                totp: {
                    let t = self.totp.read(cx).as_str().to_string();
                    (!t.trim().is_empty()).then_some(t)
                },
                app_ids: Vec::new(),
                credential_change_needs_reauth: false,
            },
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
            let result = cx
                .background_spawn_guarded("save item", async move {
                    if is_edit {
                        vela_desktop_core::commands::vault::update_item(&app_state, item).await.map(|_| ())
                    } else {
                        add_item(&app_state, item).await.map(|_| ())
                    }
                })
                .await
                .unwrap_or_else(|| Err("Saving the item failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                this.saving = false;
                match result {
                    Ok(()) => {
                        cx.emit(if is_edit { AddItemModalEvent::Updated } else { AddItemModalEvent::Created })
                    }
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
        let palette = crate::theme::current_palette(cx);

        let mut body = div().flex().flex_col().gap_4().child(labeled_field(
            &palette,
            "NAME *",
            text_input("field-name")
                .state(self.name.downgrade())
                .placeholder("Item name")
                .caret_blink_interval_500ms()
                .bg(palette.surface_container_highest)
                .text_color(palette.on_surface)
                .rounded_lg()
                .p_3()
                .w_full()
                .min_h_auto()
                .whitespace_nowrap()
                .overflow_x_scroll(),
        ));

        body = match self.kind {
            ItemKind::Login => body
                .child(labeled_field(
                    &palette,
                    "USERNAME",
                    text_input("field-username")
                        .state(self.username.downgrade())
                        .placeholder("username@email.com")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
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
                            text_input("field-password")
                                .state(self.password.downgrade())
                                .placeholder("Password")
                                .caret_blink_interval_500ms()
                                // Single-byte ASCII mask char — see
                                // biometric_gate.rs's `mask_char` comment for
                                // why '•' (multi-byte in UTF-8) misplaces the
                                // caret against ordinary ASCII passwords.
                                .mask_char(Some('*'))
                                .font_family(fonts::MONO)
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .caret_color(palette.on_surface)
                                .rounded_lg()
                                .p_3()
                                .w_full()
                                .min_h_auto()
                                .whitespace_nowrap()
                                .overflow_x_scroll(),
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
                    text_input("field-url")
                        .state(self.url.downgrade())
                        .placeholder("https://example.com")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                ))
                .child(labeled_field(
                    &palette,
                    "TOTP SECRET",
                    text_input("field-totp")
                        .state(self.totp.downgrade())
                        .placeholder("Base32 secret or OTPAUTH URL")
                        .caret_blink_interval_500ms()
                        .font_family(fonts::MONO)
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                ))
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
                    text_input("field-card-number")
                        .state(self.card_number.downgrade())
                        .placeholder("•••• •••• •••• ••••")
                        .caret_blink_interval_500ms()
                        .font_family(fonts::MONO)
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                ))
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(labeled_field(
                            &palette,
                            "EXPIRY",
                            text_input("field-card-exp")
                                .state(self.card_exp.downgrade())
                                .placeholder("MM/YY")
                                .caret_blink_interval_500ms()
                                .font_family(fonts::MONO)
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .rounded_lg()
                                .p_3()
                                .flex_1()
                                .min_h_auto()
                                .whitespace_nowrap()
                                .overflow_x_scroll(),
                        ))
                        .child(labeled_field(
                            &palette,
                            "CVV",
                            text_input("field-card-cvv")
                                .state(self.card_cvv.downgrade())
                                .placeholder("•••")
                                .caret_blink_interval_500ms()
                                .font_family(fonts::MONO)
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .rounded_lg()
                                .p_3()
                                .flex_1()
                                .min_h_auto()
                                .whitespace_nowrap()
                                .overflow_x_scroll(),
                        ))
                        .child(labeled_field(
                            &palette,
                            "PIN",
                            text_input("field-card-pin")
                                .state(self.card_pin.downgrade())
                                .placeholder("••••")
                                .caret_blink_interval_500ms()
                                .font_family(fonts::MONO)
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .rounded_lg()
                                .p_3()
                                .flex_1()
                                .min_h_auto()
                                .whitespace_nowrap()
                                .overflow_x_scroll(),
                        )),
                )
                .child(labeled_field(
                    &palette,
                    "CARDHOLDER NAME",
                    text_input("field-cardholder")
                        .state(self.cardholder_name.downgrade())
                        .placeholder("JOHN DOE")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                )),
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

        div()
            .id("add-item-backdrop")
            .absolute()
            .inset_0()
            .bg(gpui::black().opacity(0.6))
            .flex()
            .items_center()
            .justify_center()
            .font_family(fonts::LABEL)
            // Matches the original's backdrop `onClick={onClose}` — without
            // an explicit handler here, gpui doesn't insert a hitbox for a
            // plain styled div, so clicks silently fell through to whatever
            // vault content was underneath instead of being caught (let
            // alone closing the modal) — a real, confirmed bug, not just a
            // missing nicety.
            .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                cx.emit(AddItemModalEvent::Close);
            }))
            .child(
                div()
                    .id("add-item-card")
                    .map(|el| crate::keyboard::trap_tab(el, "add-item-card-trap", window, cx))
                    .w(px(560.))
                    .max_h(px(640.))
                    .rounded_2xl()
                    .bg(palette.surface_container)
                    .flex()
                    .flex_col()
                    // Stops the card's own clicks from bubbling to the
                    // backdrop above and closing the modal underneath them.
                    .on_mouse_down(MouseButton::Left, |_, _, cx| {
                        cx.stop_propagation();
                    })
                    // Enter saves from any single-line field. The Notes and
                    // Secure-note bodies are `text_area`s, where Enter inserts
                    // a newline and never reaches here.
                    .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                        if !this.saving {
                            this.submit(cx);
                        }
                    }))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .p_6()
                            .child(
                                div()
                                    .font_family(fonts::HEADLINE)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_2xl()
                                    .text_color(palette.on_surface)
                                    .child(if self.editing.is_some() { "Edit Item" } else { "Add New Item" }),
                            )
                            .child({
                                let hover_t = animation::hover_transition("close-modal", window, cx);
                                let t = *hover_t.evaluate(window, cx);
                                let bg = animation::lerp_hsla(gpui::transparent_black(), palette.surface_container_high, t);
                                div()
                                    .id("close-modal")
                                    .p_2()
                                    .rounded_lg()
                                    .bg(bg)
                                    .cursor_pointer()
                                    .child(icon("close", px(20.), palette.on_surface_variant))
                                    .on_hover(move |is_hovered, _, cx| {
                                        hover_t.update(cx, |v, cx| {
                                            *v = *is_hovered as u8 as f32;
                                            cx.notify();
                                        });
                                    })
                                    .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                                        cx.emit(AddItemModalEvent::Close);
                                    }))
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .px_6()
                            .pb_4()
                            .child(kind_tab(&palette, "Login", self.kind == ItemKind::Login, window, cx, |this, cx| {
                                this.kind = ItemKind::Login;
                                cx.notify();
                            }))
                            .child(kind_tab(&palette, "Card", self.kind == ItemKind::CreditCard, window, cx, |this, cx| {
                                this.kind = ItemKind::CreditCard;
                                cx.notify();
                            }))
                            .child(kind_tab(&palette, "Secure Note", self.kind == ItemKind::SecureNote, window, cx, |this, cx| {
                                this.kind = ItemKind::SecureNote;
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .id("modal-body-scroll")
                            .flex_1()
                            .overflow_y_scroll()
                            .px_6()
                            .child(body),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_4()
                            .p_6()
                            .child({
                                let hover_t = animation::hover_transition("cancel", window, cx);
                                let t = *hover_t.evaluate(window, cx);
                                let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);
                                div()
                                    .id("cancel")
                                    .flex_1()
                                    .py_3()
                                    .rounded_xl()
                                    .bg(bg)
                                    .text_color(palette.on_surface)
                                    .font_family(fonts::BODY)
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .child("Cancel")
                                    .on_hover(move |is_hovered, _, cx| {
                                        hover_t.update(cx, |v, cx| {
                                            *v = *is_hovered as u8 as f32;
                                            cx.notify();
                                        });
                                    })
                                    .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                                        cx.emit(AddItemModalEvent::Close);
                                    }))
                            })
                            .child({
                                let hover_t = animation::hover_transition("submit", window, cx);
                                let t = *hover_t.evaluate(window, cx);
                                let bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, t);
                                div()
                                    .id("submit")
                                    .flex_1()
                                    .py_3()
                                    .rounded_xl()
                                    .bg(bg)
                                    .text_color(palette.on_primary)
                                    .font_family(fonts::BODY)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .child(if self.saving {
                                        "Saving…"
                                    } else if self.editing.is_some() {
                                        "Save Changes"
                                    } else {
                                        "Create Item"
                                    })
                                    .on_hover(move |is_hovered, _, cx| {
                                        hover_t.update(cx, |v, cx| {
                                            *v = *is_hovered as u8 as f32;
                                            cx.notify();
                                        });
                                    })
                                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.submit(cx);
                                    }))
                            }),
                    )
                    .when_some(self.error.clone(), |el, error| {
                        el.child(div().text_sm().text_color(palette.error).child(error))
                    }),
            )
    }
}

fn labeled_field(palette: &Palette, label: &'static str, field: impl IntoElement) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            fonts::tracked_text(label, px(12.), 0.1)
                .font_family(fonts::LABEL)
                .text_xs()
                .text_color(palette.outline),
        )
        .child(field)
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
    el
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}
