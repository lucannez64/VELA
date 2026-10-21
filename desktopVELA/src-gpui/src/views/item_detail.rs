//! Port of `desktopVELA/src/views/ItemDetail.tsx` — reveal/copy fields, live
//! TOTP countdown, edit/delete, and opening the item's URL in the browser.
//!
//! Edit and delete call the real `update_item`/`delete_item`; clipboard
//! writes go through `crate::clipboard`, which marks them as secrets and
//! runs the auto-clear timer.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpui::{
    div, prelude::*, px, App, Context, EventEmitter, IntoElement, MouseButton, Render,
    SharedString, Task, Window,
};

use chrono::{DateTime, Local};
use vela_desktop_core::vault::{ItemType, VaultItem};
use vela_desktop_core::AppState;

use crate::animation;
use crate::background::GuardedSpawn;
use crate::favicon_ui::{self, FaviconCache};
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

fn type_icon_name(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::Login => "key",
        ItemType::CreditCard => "credit_card",
        ItemType::SecureNote => "note",
        ItemType::Passkey => "passkey",
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
        ItemType::Passkey => "PASSKEY",
        _ => "ITEM",
    }
}

/// Current unix time in milliseconds — the single source of truth the TOTP
/// countdown is derived from, so it cannot drift or stall with background
/// task scheduling.
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
    revealed_rich: std::collections::BTreeSet<String>,
    show_card_number: bool,
    show_cvv: bool,
    show_pin: bool,
    totp_code: SharedString,
    totp_remaining: u64,
    /// Seconds per code (from the item's own `otpauth` params, default 30).
    totp_period: u64,
    /// Unix milliseconds at which the currently shown code rolls over. The
    /// countdown is derived from this on the local clock rather than by
    /// asking the backend once a second.
    totp_expires_at: i64,
    /// When true the TOTP refresh is suspended (the edit modal is open over
    /// this screen) — the task does no work and emits no repaints.
    paused: bool,
    _totp_task: Option<Task<()>>,
    favorite: bool,
    favicon_cache: FaviconCache,
    deleting: bool,
    error: Option<SharedString>,
    show_delete_confirm: bool,
}

impl ItemDetail {
    pub fn new(app_state: Arc<AppState>, item: VaultItem, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify())
            .detach();
        let totp_secret = if let VaultItem::Login {
            totp: Some(secret), ..
        } = &item
        {
            Some(secret.clone())
        } else {
            None
        };

        let totp_task = totp_secret.map(|secret| {
            // What the loop should do on the next iteration.
            enum Tick {
                /// Nothing to do — the edit modal has us paused. Re-check soon.
                Idle,
                /// Fetch a fresh code (initial load, or the current one rolled
                /// over).
                Generate,
                /// Countdown updated; the current code expires in `ms`.
                Countdown(u64),
            }
            cx.spawn(async move |this, cx| loop {
                // Ask the entity what to do. A missing entity means the view
                // was dropped — stop the loop.
                let Ok(step) = this.update(cx, |this, cx| {
                    if this.paused {
                        return Tick::Idle;
                    }
                    let now = now_unix_ms();
                    if this.totp_expires_at == 0 || now >= this.totp_expires_at {
                        return Tick::Generate;
                    }
                    let remaining_ms = (this.totp_expires_at - now) as u64;
                    let remaining = remaining_ms.div_ceil(1000).max(1);
                    if remaining != this.totp_remaining {
                        this.totp_remaining = remaining;
                        cx.notify();
                    }
                    Tick::Countdown(remaining_ms)
                }) else {
                    break;
                };

                match step {
                    // Paused behind the edit modal: no generation, no repaints.
                    // Sleep briefly and re-check so unpausing resumes in time.
                    Tick::Idle => {
                        cx.background_spawn(async {
                            std::thread::sleep(Duration::from_millis(250))
                        })
                        .await;
                    }
                    Tick::Generate => {
                        let result = cx
                            .background_spawn_guarded("generate totp", {
                                let secret = secret.clone();
                                async move { vela_desktop_core::totp::generate_totp(secret) }
                            })
                            .await
                            .unwrap_or_else(|| {
                                Err("TOTP generation failed unexpectedly".to_string())
                            });
                        let alive = this
                            .update(cx, |this, cx| {
                                match result {
                                    Ok(code) => {
                                        let period = code.period.max(1);
                                        // Split into two roughly-even halves
                                        // instead of a hardcoded 3/3 — real
                                        // TOTP secrets can specify 6, 7, or 8
                                        // digits (RFC 6238).
                                        let mid = code.code.len().div_ceil(2);
                                        this.totp_period = period;
                                        this.totp_expires_at =
                                            now_unix_ms() + (code.remaining_secs as i64) * 1000;
                                        this.totp_code =
                                            format!("{} {}", &code.code[..mid], &code.code[mid..])
                                                .into();
                                        this.totp_remaining =
                                            code.remaining_secs.max(1).min(period);
                                    }
                                    Err(e) => {
                                        tracing::warn!("Failed to generate TOTP code: {e}")
                                    }
                                }
                                cx.notify();
                            })
                            .is_ok();
                        if !alive {
                            break;
                        }
                    }
                    Tick::Countdown(remaining_ms) => {
                        // Wake again when the displayed second changes (or
                        // earlier, at rollover).
                        let sleep_ms = remaining_ms.min(1000);
                        cx.background_spawn(async move {
                            std::thread::sleep(Duration::from_millis(sleep_ms))
                        })
                        .await;
                    }
                }
            })
        });

        let favorite = item.favorite();
        Self {
            app_state,
            item,
            show_password: false,
            revealed_rich: Default::default(),
            show_card_number: false,
            show_cvv: false,
            show_pin: false,
            totp_code: "--- ---".into(),
            totp_remaining: 30,
            totp_period: 30,
            totp_expires_at: 0,
            paused: false,
            _totp_task: totp_task,
            favorite,
            favicon_cache: favicon_ui::new_cache(),
            deleting: false,
            error: None,
            show_delete_confirm: false,
        }
    }

    /// Suspend/resume the live TOTP refresh. The shell pauses the detail view
    /// while the edit modal is open on top of it, so the loop stops driving
    /// per-second backend calls and repaints behind the modal (which, on the
    /// software-rendered gpui_wgpu path, is what made selecting a long TOTP
    /// URL in the modal stutter and freeze).
    pub fn set_paused(&mut self, paused: bool, cx: &mut Context<Self>) {
        self.paused = paused;
        cx.notify();
    }

    fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        self.favorite = !self.favorite;
        let updated = self.item.clone().with_favorite(self.favorite);
        self.item = updated.clone();
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("save favorite", async move {
                    vela_desktop_core::commands::vault::update_item(&app_state, updated).await
                })
                .await
                .unwrap_or_else(|| Err("Saving the item failed unexpectedly".to_string()));
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
                .background_spawn_guarded("delete item", async move {
                    vela_desktop_core::commands::vault::delete_item(&app_state, &id).await
                })
                .await
                .unwrap_or_else(|| Err("Deleting the item failed unexpectedly".to_string()));
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
        // Base the header layout on the space left beside navigation.
        let stacked = crate::layout::content_width(window.viewport_size().width.into()) < 1000.;

        let mut fields = div().flex().flex_col().flex_shrink_0().gap_3();

        if let Some(username) = item.username() {
            fields = fields.child(field_card(
                &palette, "USERNAME", username, username, false, window, cx,
            ));
        }

        if let Some(password) = item.password() {
            let display = if self.show_password {
                password.to_string()
            } else {
                "••••••••••••".to_string()
            };
            fields = fields.child(field_card_with_reveal(
                &palette,
                "PASSWORD",
                &display,
                password,
                self.show_password,
                window,
                cx,
            ));
        }

        if let VaultItem::CreditCard {
            number,
            exp,
            cvv,
            pin,
            cardholder_name,
            ..
        } = &item
        {
            if let Some(name) = cardholder_name {
                fields = fields.child(field_card(
                    &palette,
                    "CARDHOLDER NAME",
                    name,
                    name,
                    false,
                    window,
                    cx,
                ));
            }
            let number_display = if self.show_card_number {
                number.clone()
            } else {
                format!(
                    "•••• •••• •••• {}",
                    &number[number.len().saturating_sub(4)..]
                )
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
            let cvv_display = if self.show_cvv {
                cvv.clone()
            } else {
                "•••".to_string()
            };
            fields = fields.child(field_card_with_reveal(
                &palette,
                "CVV",
                &cvv_display,
                cvv,
                self.show_cvv,
                window,
                cx,
            ));
            if let Some(pin) = pin {
                let pin_display = if self.show_pin {
                    pin.clone()
                } else {
                    "••••".to_string()
                };
                fields = fields.child(field_card_with_reveal(
                    &palette,
                    "PIN",
                    &pin_display,
                    pin,
                    self.show_pin,
                    window,
                    cx,
                ));
            }
        }

        if let Some(url) = item.url() {
            let open_target = url.to_string();
            fields = fields.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .child(field_card(&palette, "WEBSITE", url, url, false, window, cx)),
                    )
                    .when(!open_target.is_empty(), |el| {
                        el.child(
                            div()
                                .id("open-item-url")
                                .p_2()
                                .rounded_lg()
                                .cursor_pointer()
                                .child(icon("open_in_new", px(18.), palette.on_surface_variant))
                                .on_mouse_down(MouseButton::Left, move |_, _, _cx| {
                                    // Hand off to the OS handler, same as the
                                    // vault list's row action.
                                    if let Err(e) = open::that(&open_target) {
                                        tracing::warn!("Failed to open {open_target}: {e}");
                                    }
                                }),
                        )
                    }),
            );
        }

        if let VaultItem::SecureNote { content, .. } = &item {
            fields = fields.child(note_card(
                &palette,
                "SECURE NOTE",
                content,
                (!content.is_empty()).then_some(content.as_str()),
                true,
                window,
                cx,
            ));
        }

        let rich = &item.meta().rich;
        let org = self.app_state.vault.read().organization.clone();
        if let Some(folder) = rich
            .folder_id
            .as_ref()
            .and_then(|id| vela_desktop_core::Uuid::parse_str(id).ok())
            .and_then(|id| org.folder(id))
        {
            let path = crate::views::rich_editor::folder_path(&org, folder.id);
            fields = fields.child(field_card(
                &palette, "FOLDER", &path, &path, false, window, cx,
            ));
        }
        let tag_names = rich
            .tag_ids
            .as_ref()
            .into_iter()
            .flatten()
            .filter_map(|id| org.tag(*id).map(|tag| tag.name.clone()))
            .collect::<Vec<_>>()
            .join(", ");
        if !tag_names.is_empty() {
            fields = fields.child(field_card(
                &palette, "TAGS", &tag_names, &tag_names, false, window, cx,
            ));
        }
        if let VaultItem::Identity {
            first_name,
            last_name,
            ssn,
            ..
        } = &item
        {
            fields = fields.child(rich_value(
                "identity-name".into(),
                "Name".into(),
                format!("{first_name} {last_name}"),
                false,
                false,
                &palette,
                window,
                cx,
            ));
            fields = fields.child(rich_value(
                "identity-number".into(),
                "Identity number / SSN".into(),
                ssn.clone(),
                true,
                self.revealed_rich.contains("identity-number"),
                &palette,
                window,
                cx,
            ));
        }
        if let Some(custom) = &rich.custom_fields {
            for field in custom {
                if matches!(
                    field.kind,
                    vela_desktop_core::rich_items::CustomFieldType::Unknown(_)
                ) {
                    fields = fields.child(
                        div().child(format!("{} — unsupported field preserved", field.label)),
                    );
                    continue;
                }
                let id = field.id.to_string();
                let value = field
                    .value
                    .0
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| field.value.0.to_string());
                fields = fields.child(rich_value(
                    id.clone(),
                    field.label.clone(),
                    value,
                    field.kind == vela_desktop_core::rich_items::CustomFieldType::Concealed,
                    self.revealed_rich.contains(&id),
                    &palette,
                    window,
                    cx,
                ));
            }
        }
        if let Some(urls) = &rich.additional_urls {
            for url in urls {
                fields = fields.child(rich_value(
                    url.id.to_string(),
                    format!("Additional site ({:?})", url.match_mode),
                    url.url.clone(),
                    false,
                    false,
                    &palette,
                    window,
                    cx,
                ));
            }
        }
        if let Some(details) = &rich.identity_details {
            for (label, value) in [
                ("Middle name", &details.middle_name),
                ("Preferred name", &details.preferred_name),
                ("Email", &details.email),
                ("Phone", &details.phone),
                ("Company", &details.company),
                ("Job title", &details.job_title),
            ] {
                if let Some(value) = value {
                    fields = fields.child(rich_value(
                        label.into(),
                        label.into(),
                        value.clone(),
                        false,
                        false,
                        &palette,
                        window,
                        cx,
                    ));
                }
            }
            for a in &details.addresses {
                let value = [
                    &a.line1,
                    &a.line2,
                    &a.city,
                    &a.region,
                    &a.postal_code,
                    &a.country_code,
                ]
                .into_iter()
                .filter_map(|v| v.as_deref())
                .collect::<Vec<_>>()
                .join("\n");
                fields = fields.child(rich_value(
                    a.id.to_string(),
                    a.label.clone().unwrap_or_else(|| "Address".into()),
                    value,
                    false,
                    false,
                    &palette,
                    window,
                    cx,
                ));
            }
        }
        if let Some(notes) = item.notes() {
            fields = fields.child(note_card(
                &palette,
                "ADDITIONAL NOTES",
                notes,
                None,
                false,
                window,
                cx,
            ));
        }

        let totp_section = if matches!(&item, VaultItem::Login { totp: Some(_), .. }) {
            let progress =
                (self.totp_remaining as f32 / self.totp_period.max(1) as f32).clamp(0., 1.);
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
                    .p_4()
                    .gap_6()
                    .child({
                let mut header = div().flex().flex_shrink_0().min_w_0().gap_6();
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
                            .gap_3()
                            .flex_1()
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
                                    .flex_shrink_0()
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
                                            // A passkey's RP ID is a bare
                                            // registrable domain; the
                                            // fetcher normalizes it to
                                            // https:// like a login URL.
                                            VaultItem::Passkey { rp_id, .. } if !rp_id.is_empty() => {
                                                let weak_view = cx.weak_entity();
                                                favicon_ui::favicon_or_fallback(
                                                    &palette,
                                                    rp_id,
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
                                    .flex_1()
                                    .min_w_0()
                                    .pt_2()
                                    .child(
                                        div().child(item.name().to_string()).whitespace_normal()
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
                            .flex_wrap()
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
                            // Passkeys are ceremony-created credentials whose
                            // private key never crosses IPC; the generic
                            // editor has nothing to edit and sharing one
                            // would need its own flow.
                            .when(!is_received_share && !matches!(item, VaultItem::Passkey { .. }), |el| {
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
        .p_4()
        .absolute()
        .inset_0()
        // Stop the hit-test at the backdrop, so the scroll container behind it
        // doesn't still handle `ScrollWheelEvent` (see add_item_modal's comment).
        .occlude()
        .bg(gpui::black().opacity(0.6))
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|this, _, _, cx| {
                this.show_delete_confirm = false;
                cx.notify();
            }),
        )
        .child(
            div()
                .id("delete-confirm-card")
                .w_full()
                .max_w(px(400.))
                .max_h_full()
                .overflow_y_scroll()
                .p_6()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla {
                    a: 0.2,
                    ..palette.outline_variant
                })
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
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        this.show_delete_confirm = false;
                                        cx.notify();
                                    }),
                                ),
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
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        this.delete(cx);
                                    }),
                                ),
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
        .border_color(gpui::Hsla {
            a: 0.1,
            ..palette.outline_variant
        })
        .flex()
        .items_center()
        .flex_wrap()
        .gap_4()
        .flex_shrink_0()
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
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        this.show_delete_confirm = true;
                        cx.notify();
                    }),
                )
                .into_any_element()
        })
        .child(
            div()
                .flex()
                .gap_8()
                .child(footer_stat(
                    palette,
                    "LAST MODIFIED",
                    updated_text,
                    palette.on_surface,
                    false,
                ))
                .child(footer_stat(
                    palette,
                    "ENCRYPTION",
                    "AES-256-GCM".to_string(),
                    palette.secondary,
                    true,
                )),
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

/// A full-width card for a multi-line note body.
///
/// `copy_value` is `Some` for the secure-note body — which previously had no
/// copy affordance at all, so a secure note could only be copied by the list
/// row's icon and that toasted "Nothing to copy" — and `None` for free-form
/// additional notes.
fn note_card(
    palette: &Palette,
    label: &'static str,
    content: &str,
    copy_value: Option<&str>,
    mono: bool,
    window: &mut Window,
    cx: &mut Context<ItemDetail>,
) -> impl IntoElement {
    let mut label_row = div().flex().items_center().justify_between().child(
        fonts::tracked_text(label, px(10.), 0.2)
            .font_family(fonts::LABEL)
            .text_size(px(10.))
            .text_color(palette.outline),
    );

    if let Some(value) = copy_value {
        let value = value.to_string();
        let hover_t = animation::hover_transition(format!("copy-{label}"), window, cx);
        let t = *hover_t.evaluate(window, cx);
        let hover_bg = animation::lerp_hsla(
            gpui::transparent_black(),
            palette.surface_container_highest,
            t,
        );
        label_row = label_row.child(
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
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        this.copy(label, &value, cx);
                        cx.notify();
                    }),
                ),
        );
    }

    let body = if mono {
        div()
            .font_family(fonts::MONO)
            .text_color(palette.on_surface)
    } else {
        div()
            .font_family(fonts::BODY)
            .text_sm()
            .text_color(palette.on_surface)
    };

    div()
        .p_4()
        .min_w_0()
        .flex_shrink_0()
        .rounded_xl()
        .bg(palette.surface_container_low)
        .flex()
        .flex_col()
        .gap_2()
        .child(label_row)
        .child(body.child(content.to_string()))
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
    field_card_inner(
        palette, label, label, value, copy_value, None, mono, window, cx,
    )
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
    field_card_inner(
        palette,
        label,
        label,
        display_value,
        copy_value,
        Some(revealed),
        true,
        window,
        cx,
    )
}

fn field_card_inner(
    palette: &Palette,
    key: &str,
    label: &str,
    display_value: &str,
    copy_value: &str,
    revealed: Option<bool>,
    mono: bool,
    window: &mut Window,
    cx: &mut Context<ItemDetail>,
) -> gpui::Div {
    let key = key.to_string();
    let label = label.to_uppercase();
    let copy_value = copy_value.to_string();
    let display_value = display_value.to_string();

    let mut row = div()
        .flex()
        .min_w_0()
        .items_center()
        .justify_between()
        .gap_3();
    let mut value_el = div()
        .id(SharedString::from(format!("value-{key}")))
        .flex_1()
        .min_w_0()
        .overflow_x_scroll()
        .whitespace_nowrap()
        .text_color(palette.on_surface);
    value_el = if mono {
        value_el.font_family(fonts::MONO).text_lg()
    } else {
        value_el
            .font_family(fonts::BODY)
            .text_lg()
            .font_weight(gpui::FontWeight::MEDIUM)
    };
    row = row.child(value_el.child(display_value));

    let mut buttons = div().flex().flex_shrink_0().gap_1();
    if let Some(revealed) = revealed {
        let reveal_key = key.clone();
        let hover_t = animation::hover_transition(format!("reveal-{key}"), window, cx);
        let t = *hover_t.evaluate(window, cx);
        let hover_bg = animation::lerp_hsla(
            gpui::transparent_black(),
            palette.surface_container_highest,
            t,
        );
        buttons = buttons.child(
            crate::ui::icon_button(
                format!("reveal-{key}"),
                if revealed {
                    "visibility_off"
                } else {
                    "visibility"
                },
                px(18.),
                palette.on_surface_variant,
            )
            .bg(hover_bg)
            .on_hover(move |is_hovered, _, cx| {
                hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    match reveal_key.as_str() {
                        "PASSWORD" => this.show_password = !this.show_password,
                        "CARD NUMBER" => this.show_card_number = !this.show_card_number,
                        "CVV" => this.show_cvv = !this.show_cvv,
                        "PIN" => this.show_pin = !this.show_pin,
                        other => {
                            if let Some(id) = other.strip_prefix("rich-") {
                                if !this.revealed_rich.remove(id) {
                                    this.revealed_rich.insert(id.to_string());
                                }
                            }
                        }
                    }
                    cx.notify();
                }),
            ),
        );
    }
    {
        let copy_label = label.clone();
        let hover_t = animation::hover_transition(format!("copy-{key}"), window, cx);
        let t = *hover_t.evaluate(window, cx);
        let hover_bg = animation::lerp_hsla(
            gpui::transparent_black(),
            palette.surface_container_highest,
            t,
        );
        buttons = buttons.child(
            crate::ui::icon_button(
                format!("copy-{key}"),
                "content_copy",
                px(18.),
                palette.primary,
            )
            .bg(hover_bg)
            .on_hover(move |is_hovered, _, cx| {
                hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    this.copy(&copy_label, &copy_value, cx);
                    cx.notify();
                }),
            ),
        );
    }
    row = row.child(buttons);

    crate::ui::field_card(palette)
        .debug_selector(move || format!("field-{key}"))
        .child(
            fonts::tracked_text(&label, px(10.), 0.2)
                .font_family(fonts::LABEL)
                .text_size(px(10.))
                .text_color(palette.outline),
        )
        .child(row)
}

fn rich_value(
    id: String,
    label: String,
    value: String,
    concealed: bool,
    revealed: bool,
    p: &Palette,
    window: &mut Window,
    cx: &mut Context<ItemDetail>,
) -> gpui::Div {
    let display = if concealed && !revealed {
        "••••••••".to_string()
    } else {
        value.clone()
    };
    field_card_inner(
        p,
        &format!("rich-{id}"),
        &label,
        &display,
        &value,
        concealed.then_some(revealed),
        concealed,
        window,
        cx,
    )
}

#[cfg(test)]
mod rich_field_tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{size, Modifiers, TestAppContext};

    #[gpui::test]
    fn shared_detail_cards_reveal_duplicate_labels_independently_in_every_theme(
        cx: &mut TestAppContext,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let state = ui::state(&directory);
        let first = vela_desktop_core::Uuid::new_v4();
        let second = vela_desktop_core::Uuid::new_v4();
        let item:VaultItem=serde_json::from_value(serde_json::json!({
            "item_type":"identity","id":"demo","name":"Demo identity","first_name":"Alex","last_name":"Demo","ssn":"synthetic-id",
            "customFields":[{"id":first,"label":"Recovery","type":"concealed","value":"first-demo-secret"},{"id":second,"label":"Recovery","type":"concealed","value":"second-demo-secret"}]
        })).unwrap();
        cx.update(|cx| cx.set_global(crate::demo::DemoMode));
        let (detail, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            ItemDetail::new(state, item, cx)
        });
        cx.simulate_resize(size(px(1280.), px(1200.)));
        for theme in crate::theme::ThemeId::ALL {
            cx.update(|_, cx| cx.set_global(crate::theme::ActiveTheme(theme)));
            cx.run_until_parked();
            detail.read_with(cx, |detail, _| assert!(detail.revealed_rich.is_empty()));
            let selector: &'static str = Box::leak(format!("reveal-rich-{first}").into_boxed_str());
            let reveal = ui::bounds(cx, selector);
            assert!(reveal.bottom() <= px(1200.));
            cx.simulate_mouse_move(reveal.center(), None, Modifiers::default());
            cx.simulate_click(reveal.center(), Modifiers::default());
            cx.run_until_parked();
            detail.read_with(cx, |detail, _| {
                assert!(detail.revealed_rich.contains(&first.to_string()));
                assert!(!detail.revealed_rich.contains(&second.to_string()));
            });
            let second_selector: &'static str =
                Box::leak(format!("reveal-rich-{second}").into_boxed_str());
            assert_eq!(ui::bounds(cx, second_selector).size, reveal.size);
            detail.update(cx, |detail, cx| {
                detail.revealed_rich.clear();
                cx.notify();
            });
        }
    }
}
