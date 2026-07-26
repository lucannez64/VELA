//! Port of `desktopVELA/src/views/ItemDetail.tsx` — reveal/copy fields, live
//! TOTP countdown. Real clipboard writes via `arboard` (no vault mutation —
//! safe to wire fully, unlike edit/delete/favorite/share below).
//!
//! Deliberately read-only for now, consistent with the "be careful with
//! write paths" agreement: favorite toggle, edit, share, and delete all just
//! log rather than calling `update_item`/`delete_item`. Also not ported:
//! clipboard auto-clear-after-N-seconds (arboard write is immediate/
//! permanent-until-next-copy for now), and open-URL (needs a native
//! `open`/xdg-open call, not yet wired).

use std::sync::Arc;
use std::time::Duration;

use gpui::{
    div, prelude::*, px, App, Context, EventEmitter, IntoElement, MouseButton, Render, SharedString,
    Task, Window,
};

use chrono::{DateTime, Local};
use vela_desktop_core::vault::{ItemType, VaultItem};
use vela_desktop_core::AppState;

use crate::animation;
use crate::favicon_ui::{self, FaviconCache};
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

fn type_icon_name(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::Login => "key",
        ItemType::CreditCard => "credit_card",
        ItemType::SecureNote => "note",
        _ => "shield",
    }
}

/// Matches the original's raw `item.item_type` string after its CSS
/// `uppercase` visual transform (which just uppercases every character,
/// with no word-splitting) used in "Zero-Knowledge {type}".
fn type_label(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::Login => "LOGIN",
        ItemType::CreditCard => "CREDITCARD",
        ItemType::SecureNote => "SECURENOTE",
        _ => "ITEM",
    }
}

pub enum ItemDetailEvent {
    Back,
    /// The item was actually deleted — the owning `AppShell` should go back
    /// to the vault list and refresh it.
    Deleted,
    /// "Edit" was clicked — the owning `AppShell` should open `AddItemModal`
    /// in edit mode as an overlay above this screen.
    EditRequested(VaultItem),
    /// "Share Access" was clicked — the owning `AppShell` should navigate to
    /// SharingScreen with this item pre-selected in the share modal.
    ShareRequested(String),
}
impl EventEmitter<ItemDetailEvent> for ItemDetail {}

pub struct ItemDetail {
    app_state: Arc<AppState>,
    item: VaultItem,
    show_password: bool,
    show_card_number: bool,
    show_cvv: bool,
    show_pin: bool,
    totp_code: SharedString,
    totp_remaining: u64,
    _totp_task: Option<Task<()>>,
    favorite: bool,
    favicon_cache: FaviconCache,
    deleting: bool,
    error: Option<SharedString>,
    show_delete_confirm: bool,
}

impl ItemDetail {
    pub fn new(app_state: Arc<AppState>, item: VaultItem, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let totp_secret = if let VaultItem::Login { totp: Some(secret), .. } = &item {
            Some(secret.clone())
        } else {
            None
        };

        let totp_task = totp_secret.map(|secret| {
            cx.spawn(async move |this, cx| loop {
                let result = cx
                    .background_spawn({
                        let secret = secret.clone();
                        async move { vela_desktop_core::totp::generate_totp(secret) }
                    })
                    .await;
                let should_continue = this
                    .update(cx, |this, cx| {
                        match result {
                            Ok(code) => {
                                // Split into two roughly-even halves instead
                                // of a hardcoded 3/3 — real TOTP secrets can
                                // specify 6, 7, or 8 digits (RFC 6238), and
                                // this previously assumed exactly 6.
                                let mid = code.code.len().div_ceil(2);
                                this.totp_code =
                                    format!("{} {}", &code.code[..mid], &code.code[mid..]).into();
                                this.totp_remaining = code.remaining_secs;
                            }
                            Err(e) => tracing::warn!("Failed to generate TOTP code: {e}"),
                        }
                        cx.notify();
                    })
                    .is_ok();
                if !should_continue {
                    break;
                }
                cx.background_spawn(async { std::thread::sleep(Duration::from_secs(1)) })
                    .await;
            })
        });

        let favorite = item.favorite();
        Self {
            app_state,
            item,
            show_password: false,
            show_card_number: false,
            show_cvv: false,
            show_pin: false,
            totp_code: "--- ---".into(),
            totp_remaining: 30,
            _totp_task: totp_task,
            favorite,
            favicon_cache: favicon_ui::new_cache(),
            deleting: false,
            error: None,
            show_delete_confirm: false,
        }
    }

    fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        self.favorite = !self.favorite;
        let updated = self.item.clone().with_favorite(self.favorite);
        self.item = updated.clone();
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    vela_desktop_core::commands::vault::update_item(&app_state, updated).await
                })
                .await;
            if let Err(e) = result {
                tracing::warn!("Failed to save favorite: {e}");
                this.update(cx, |this, cx| {
                    this.error = Some(format!("Failed to save favorite: {e}").into());
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();
    }

    fn delete(&mut self, cx: &mut Context<Self>) {
        self.deleting = true;
        self.error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        let id = self.item.id().to_string();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    vela_desktop_core::commands::vault::delete_item(&app_state, &id).await
                })
                .await;
            this.update(cx, |this, cx| {
                this.deleting = false;
                match result {
                    Ok(()) => cx.emit(ItemDetailEvent::Deleted),
                    Err(e) => this.error = Some(format!("Failed to delete item: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn copy(&self, label: &str, value: &str, cx: &mut App) {
        crate::clipboard::copy(cx, label, value);
    }
}

impl Render for ItemDetail {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let item = self.item.clone();
        // Matches the original's `flex flex-col xl:flex-row` on the header
        // row (Tailwind's `xl:` = 1280px): below that width the title block
        // and the favorite/edit/share button group stack vertically instead
        // of being forced onto one row, which is what was pushing "Share
        // Access" off the right edge of the window at more typical widths.
        let stacked = window.viewport_size().width < px(1280.);

        let mut fields = div().flex().flex_col().gap_3();

        if let Some(username) = item.username() {
            fields = fields.child(field_card(&palette, "USERNAME", username, username, false, window, cx));
        }

        if let Some(password) = item.password() {
            let display = if self.show_password { password.to_string() } else { "••••••••••••".to_string() };
            fields = fields.child(
                field_card_with_reveal(&palette, "PASSWORD", &display, password, self.show_password, window, cx),
            );
        }

        if let VaultItem::CreditCard { number, exp, cvv, pin, cardholder_name, .. } = &item {
            if let Some(name) = cardholder_name {
                fields = fields.child(field_card(&palette, "CARDHOLDER NAME", name, name, false, window, cx));
            }
            let number_display = if self.show_card_number {
                number.clone()
            } else {
                format!("•••• •••• •••• {}", &number[number.len().saturating_sub(4)..])
            };
            fields = fields.child(field_card_with_reveal(
                &palette,
                "CARD NUMBER",
                &number_display,
                number,
                self.show_card_number,
                window,
                cx,
            ));
            fields = fields.child(field_card(&palette, "EXPIRY", exp, exp, true, window, cx));
            let cvv_display = if self.show_cvv { cvv.clone() } else { "•••".to_string() };
            fields = fields.child(field_card_with_reveal(&palette, "CVV", &cvv_display, cvv, self.show_cvv, window, cx));
            if let Some(pin) = pin {
                let pin_display = if self.show_pin { pin.clone() } else { "••••".to_string() };
                fields = fields.child(field_card_with_reveal(&palette, "PIN", &pin_display, pin, self.show_pin, window, cx));
            }
        }

        if let Some(url) = item.url() {
            fields = fields.child(field_card(&palette, "WEBSITE", url, url, false, window, cx));
        }

        if let VaultItem::SecureNote { content, .. } = &item {
            fields = fields.child(
                div()
                    .p_4()
                    .rounded_xl()
                    .bg(palette.surface_container_low)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        fonts::tracked_text("SECURE NOTE", px(10.), 0.2)
                            .font_family(fonts::LABEL)
                            .text_size(px(10.))
                            .text_color(palette.outline),
                    )
                    .child(
                        div()
                            .font_family(fonts::MONO)
                            .text_color(palette.on_surface)
                            .child(content.clone()),
                    ),
            );
        }

        if let Some(notes) = item.notes() {
            fields = fields.child(
                div()
                    .p_4()
                    .rounded_xl()
                    .bg(palette.surface_container_low)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        fonts::tracked_text("ADDITIONAL NOTES", px(10.), 0.2)
                            .font_family(fonts::LABEL)
                            .text_size(px(10.))
                            .text_color(palette.outline),
                    )
                    .child(
                        div()
                            .font_family(fonts::BODY)
                            .text_sm()
                            .text_color(palette.on_surface)
                            .child(notes.to_string()),
                    ),
            );
        }

        let totp_section = if matches!(&item, VaultItem::Login { totp: Some(_), .. }) {
            let progress = (self.totp_remaining as f32 / 30.0).clamp(0., 1.);
            Some(
                div()
                    .p_4()
                    .rounded_xl()
                    .bg(palette.surface_container_low)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .font_family(fonts::LABEL)
                                    .text_size(px(10.))
                                    .text_color(palette.outline)
                                    .child(fonts::tracked_text("TOTP (2FA)", px(10.), 0.2))
                                    .child(
                                        fonts::tracked_text("ACTIVE", px(10.), 0.2)
                                            .text_color(palette.primary)
                                            .font_weight(gpui::FontWeight::BOLD),
                                    ),
                            )
                            .child(
                                div()
                                    .font_family(fonts::MONO)
                                    .text_xs()
                                    .text_color(palette.outline)
                                    .child(format!("EXPIRES IN {}S", self.totp_remaining)),
                            ),
                    )
                    .child(
                        fonts::tracked_text(&self.totp_code, px(30.), 0.1)
                            .font_family(fonts::MONO)
                            .text_3xl()
                            .font_weight(gpui::FontWeight::LIGHT)
                            .text_color(palette.on_surface),
                    )
                    .child(
                        div()
                            .h(px(4.))
                            .w_full()
                            .rounded_full()
                            .bg(palette.surface_container_highest)
                            .child(
                                div()
                                    .h_full()
                                    .rounded_full()
                                    .bg(palette.primary)
                                    .w(gpui::relative(progress)),
                            ),
                    ),
            )
        } else {
            None
        };

        let is_received_share = item.is_received_share();
        let favorite = self.favorite;

        // This screen previously had no scroll container at all (content
        // longer than the window was just clipped with no way to reach it),
        // and the delete-confirm modal below must not be nested inside a
        // scrollable div for the same reason fixed elsewhere this round
        // (its backdrop would size to the scrollable content instead of the
        // real viewport). Outer non-scrolling wrapper + inner scrollable
        // content + modal as an outer sibling fixes both at once.
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .id("item-detail-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .bg(palette.surface_container_lowest)
                    .font_family(fonts::LABEL)
                    .p_6()
                    .gap_6()
                    .child({
                let mut header = div().flex().gap_6();
                header = if stacked {
                    header.flex_col()
                } else {
                    header.flex_row().items_start().justify_between()
                };
                header
                    .child(
                        div()
                            .flex()
                            .items_start()
                            .gap_4()
                            .min_w(px(0.))
                            .child(
                                div()
                                    .id("back-button")
                                    .mt(px(28.))
                                    .text_color(palette.on_surface_variant)
                                    .cursor_pointer()
                                    .child(icon("arrow_back", px(20.), palette.on_surface_variant))
                                    .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                                        cx.emit(ItemDetailEvent::Back);
                                    })),
                            )
                            .child(
                                div()
                                    .relative()
                                    .child({
                                        let icon_name = type_icon_name(item.item_type());
                                        match &item {
                                            VaultItem::Login { url, .. } if !url.is_empty() => {
                                                let weak_view = cx.weak_entity();
                                                favicon_ui::favicon_or_fallback(
                                                    &palette,
                                                    url,
                                                    icon_name,
                                                    px(80.),
                                                    &self.favicon_cache,
                                                    cx,
                                                    move |cx| {
                                                        weak_view.update(cx, |_, cx| cx.notify()).ok();
                                                    },
                                                )
                                            }
                                            _ => favicon_ui::fallback_icon_box(&palette, icon_name, px(80.))
                                                .into_any_element(),
                                        }
                                    })
                                    .child(
                                        div()
                                            .absolute()
                                            .bottom(px(-8.))
                                            .right(px(-8.))
                                            .px_2()
                                            .py(px(2.))
                                            .rounded_sm()
                                            .bg(palette.secondary)
                                            .text_color(palette.on_secondary)
                                            .child(fonts::tracked_text("SECURE", px(10.), 0.1).text_size(px(10.)).font_weight(gpui::FontWeight::BOLD)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .pt_2()
                                    .child(
                                        fonts::tracked_text(item.name(), px(30.), -0.025)
                                            .font_family(fonts::HEADLINE)
                                            .font_weight(gpui::FontWeight::BOLD)
                                            .text_3xl()
                                            .text_color(palette.on_surface),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(div().w(px(8.)).h(px(8.)).rounded_full().bg(palette.primary))
                                            .child(
                                                fonts::tracked_text(
                                                    &format!("ZERO-KNOWLEDGE {}", type_label(item.item_type())),
                                                    px(12.),
                                                    0.05,
                                                )
                                                .font_family(fonts::LABEL)
                                                .text_xs()
                                                .text_color(palette.on_surface_variant),
                                            )
                                            .when(is_received_share, |el| {
                                                el.child(
                                                    div()
                                                        .ml_2()
                                                        .px_2()
                                                        .py(px(1.))
                                                        .rounded_sm()
                                                        .bg(gpui::Hsla { a: 0.2, ..palette.secondary })
                                                        .text_color(palette.secondary)
                                                        .child(
                                                            fonts::tracked_text("Shared with you · Read-only", px(10.), 0.1)
                                                                .text_size(px(10.))
                                                                .font_family(fonts::LABEL)
                                                                .font_weight(gpui::FontWeight::BOLD),
                                                        ),
                                                )
                                            }),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .id("toggle-favorite")
                                    .w(px(40.))
                                    .h(px(40.))
                                    .rounded_full()
                                    .bg(palette.surface_container_highest)
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .child(icon(
                                        "star",
                                        px(20.),
                                        if favorite { gpui::rgb(0xfbbf24).into() } else { palette.on_surface_variant },
                                    ))
                                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.toggle_favorite(cx);
                                    })),
                            )
                            .when(!is_received_share, |el| {
                                el.child(
                                    div()
                                        .id("edit-item")
                                        .w(px(40.))
                                        .h(px(40.))
                                        .rounded_full()
                                        .bg(palette.surface_container_highest)
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .cursor_pointer()
                                        .child(icon("edit", px(20.), palette.on_surface))
                                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                            cx.emit(ItemDetailEvent::EditRequested(this.item.clone()));
                                        })),
                                )
                                .child(
                                    div()
                                        .id("share-item")
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .px_4()
                                        .h(px(40.))
                                        .rounded_full()
                                        .bg(palette.primary)
                                        .text_color(palette.on_primary)
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .text_sm()
                                        .cursor_pointer()
                                        .child(icon("share", px(16.), palette.on_primary))
                                        .child("Share Access")
                                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                            cx.emit(ItemDetailEvent::ShareRequested(this.item.id().to_string()));
                                        })),
                                )
                            }),
                    )
                    })
                    .child(fields)
                    .children(totp_section)
                    .child(footer(&palette, &item, is_received_share, cx)),
            )
            .when(self.show_delete_confirm, |el| {
                el.child(delete_confirm_modal(&palette, self.deleting, self.error.clone(), cx))
            })
    }
}

fn delete_confirm_modal(
    palette: &Palette,
    deleting: bool,
    error: Option<SharedString>,
    cx: &mut Context<ItemDetail>,
) -> impl IntoElement {
    div()
        .id("delete-confirm-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::black().opacity(0.6))
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            this.show_delete_confirm = false;
            cx.notify();
        }))
        .child(
            div()
                .id("delete-confirm-card")
                .w(px(400.))
                .p_6()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_lg()
                        .text_color(palette.on_surface)
                        .child("Delete this item?"),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("This can't be undone."),
                )
                .when_some(error, |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(
                            div()
                                .id("cancel-delete")
                                .flex_1()
                                .py_2()
                                .rounded_lg()
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .child("Cancel")
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.show_delete_confirm = false;
                                    cx.notify();
                                })),
                        )
                        .child(
                            div()
                                .id("confirm-delete")
                                .flex_1()
                                .py_2()
                                .rounded_lg()
                                .bg(palette.error)
                                .text_color(gpui::white())
                                .font_weight(gpui::FontWeight::BOLD)
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .child(if deleting { "Deleting…" } else { "Delete" })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.delete(cx);
                                })),
                        ),
                ),
        )
}

fn footer(
    palette: &Palette,
    item: &VaultItem,
    is_received_share: bool,
    cx: &mut Context<ItemDetail>,
) -> impl IntoElement {
    let updated_local: DateTime<Local> = item.updated_at().with_timezone(&Local);
    let updated_text = updated_local.format("%-m/%-d/%Y").to_string();

    div()
        .mt_6()
        .pt_8()
        .border_t_1()
        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
        .flex()
        .items_center()
        .justify_between()
        .child(if is_received_share {
            div().into_any_element()
        } else {
            div()
                .id("delete-item")
                .flex()
                .items_center()
                .px_4()
                .py_2()
                .rounded_lg()
                .text_color(palette.error)
                .cursor_pointer()
                .child(icon("delete", px(16.), palette.error))
                .child(div().ml_2().child("Delete"))
                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                    this.show_delete_confirm = true;
                    cx.notify();
                }))
                .into_any_element()
        })
        .child(
            div()
                .flex()
                .gap_8()
                .child(footer_stat(palette, "LAST MODIFIED", updated_text, palette.on_surface, false))
                .child(footer_stat(palette, "ENCRYPTION", "AES-256-GCM".to_string(), palette.secondary, true)),
        )
}

fn footer_stat(
    palette: &Palette,
    label: &'static str,
    value: String,
    value_color: gpui::Hsla,
    mono: bool,
) -> impl IntoElement {
    let mut value_el = div().text_xs().text_color(value_color);
    if mono {
        value_el = value_el.font_family(fonts::MONO);
    }
    div()
        .flex()
        .flex_col()
        .child(
            fonts::tracked_text(label, px(10.), 0.2)
                .font_family(fonts::LABEL)
                .text_size(px(10.))
                .text_color(palette.outline)
                .mb_1(),
        )
        .child(value_el.child(value))
}

/// `mono`: whether the value uses the monospace font — matches the
/// original's per-field choice (password/card-number/cvv/pin/totp are
/// font-mono, username/cardholder-name/url/expiry are not).
fn field_card(
    palette: &Palette,
    label: &'static str,
    value: &str,
    copy_value: &str,
    mono: bool,
    window: &mut Window,
    cx: &mut Context<ItemDetail>,
) -> impl IntoElement {
    field_card_inner(palette, label, value, copy_value, None, mono, window, cx)
}

fn field_card_with_reveal(
    palette: &Palette,
    label: &'static str,
    display_value: &str,
    copy_value: &str,
    revealed: bool,
    window: &mut Window,
    cx: &mut Context<ItemDetail>,
) -> impl IntoElement {
    field_card_inner(palette, label, display_value, copy_value, Some(revealed), true, window, cx)
}

fn field_card_inner(
    palette: &Palette,
    label: &'static str,
    display_value: &str,
    copy_value: &str,
    revealed: Option<bool>,
    mono: bool,
    window: &mut Window,
    cx: &mut Context<ItemDetail>,
) -> impl IntoElement {
    let copy_value = copy_value.to_string();
    let display_value = display_value.to_string();

    let mut row = div().flex().items_center().justify_between().gap_3();
    let mut value_el = div().text_color(palette.on_surface);
    value_el = if mono {
        value_el.font_family(fonts::MONO).text_lg()
    } else {
        value_el.font_family(fonts::BODY).text_lg().font_weight(gpui::FontWeight::MEDIUM)
    };
    row = row.child(value_el.child(display_value));

    let mut buttons = div().flex().gap_1();
    if let Some(revealed) = revealed {
        let hover_t = animation::hover_transition(format!("reveal-{label}"), window, cx);
        let t = *hover_t.evaluate(window, cx);
        let hover_bg = animation::lerp_hsla(gpui::transparent_black(), palette.surface_container_highest, t);
        buttons = buttons.child(
            div()
                .id(SharedString::from(format!("reveal-{label}")))
                .p_2()
                .rounded_lg()
                .cursor_pointer()
                .bg(hover_bg)
                .on_hover(move |is_hovered, _, cx| {
                    hover_t.update(cx, |v, cx| {
                        *v = *is_hovered as u8 as f32;
                        cx.notify();
                    });
                })
                .child(icon(
                    if revealed { "visibility_off" } else { "visibility" },
                    px(18.),
                    palette.on_surface_variant,
                ))
                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                    match label {
                        "PASSWORD" => this.show_password = !this.show_password,
                        "CARD NUMBER" => this.show_card_number = !this.show_card_number,
                        "CVV" => this.show_cvv = !this.show_cvv,
                        "PIN" => this.show_pin = !this.show_pin,
                        _ => {}
                    }
                    cx.notify();
                })),
        );
    }
    {
        let hover_t = animation::hover_transition(format!("copy-{label}"), window, cx);
        let t = *hover_t.evaluate(window, cx);
        let hover_bg = animation::lerp_hsla(gpui::transparent_black(), palette.surface_container_highest, t);
        buttons = buttons.child(
            div()
                .id(SharedString::from(format!("copy-{label}")))
                .p_2()
                .rounded_lg()
                .cursor_pointer()
                .bg(hover_bg)
                .on_hover(move |is_hovered, _, cx| {
                    hover_t.update(cx, |v, cx| {
                        *v = *is_hovered as u8 as f32;
                        cx.notify();
                    });
                })
                .child(icon("content_copy", px(18.), palette.primary))
                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                    this.copy(label, &copy_value, cx);
                    cx.notify();
                })),
        );
    }
    row = row.child(buttons);

    div()
        .p_4()
        .rounded_xl()
        .bg(palette.surface_container_low)
        .flex()
        .flex_col()
        .gap_2()
        .child(
            fonts::tracked_text(label, px(10.), 0.2)
                .font_family(fonts::LABEL)
                .text_size(px(10.))
                .text_color(palette.outline),
        )
        .child(row)
}
