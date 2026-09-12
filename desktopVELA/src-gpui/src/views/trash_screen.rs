//! Trash (§1.2): deleted items restorable until purged. Native counterpart
//! of `desktopVELA/src/views/TrashView.tsx`, over the same core commands —
//! `get_deleted_items` / `restore_item` / `purge_deleted_item`.

use std::sync::Arc;

use chrono::Local;
use gpui::{div, prelude::*, px, App, Context, IntoElement, MouseButton, Render, SharedString, Window};

use vela_desktop_core::vault::DeletedItem;
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::fonts;
use crate::host;
use crate::icon::icon;
use crate::theme::Palette;
use crate::toast;

fn type_icon(item_type: &str) -> &'static str {
    match item_type {
        "login" => "key",
        "credit_card" => "credit_card",
        "secure_note" => "note",
        "passkey" => "passkey",
        _ => "shield",
    }
}

fn friendly_type(item_type: &str) -> &'static str {
    match item_type {
        "login" => "Login",
        "credit_card" => "Card",
        "secure_note" => "Secure Note",
        "passkey" => "Passkey",
        "file_blob" => "File",
        "breach_monitor" => "Breach Monitor",
        _ => "Item",
    }
}

pub struct TrashScreen {
    app_state: Arc<AppState>,
    entries: Option<Vec<DeletedItem>>,
    error: Option<SharedString>,
    /// Two-step confirm for "delete forever": the id armed for a second click.
    confirming_purge: Option<String>,
}

impl TrashScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let mut this = Self {
            app_state,
            entries: None,
            error: None,
            confirming_purge: None,
        };
        this.reload(cx);
        this
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let entries = cx
                .background_spawn_guarded("load trash", async move {
                    vela_desktop_core::commands::vault::get_deleted_items(&app_state)
                })
                .await
                .unwrap_or_else(|| Err("Loading the trash failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                match entries {
                    Ok(entries) => {
                        this.entries = Some(entries);
                        this.error = None;
                    }
                    Err(e) => this.error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn restore(&mut self, id: String, _name: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("restore item", {
                    let app_state = app_state.clone();
                    let id = id.clone();
                    async move {
                        vela_desktop_core::commands::vault::restore_item(&app_state, &id).await
                    }
                })
                .await
                .unwrap_or_else(|| Err("Restoring the item failed unexpectedly".to_string()));
            this.update(cx, |this, cx| match result {
                Ok(restored) => {
                    toast::show(
                        cx,
                        format!("Restored \"{}\"", restored.name()),
                        crate::toast::ToastKind::Success,
                    );
                    // The vault browser reloads on this global bump — the
                    // same mechanism an extension-side save uses.
                    host::notify_vault_items_changed(cx);
                    this.reload(cx);
                }
                Err(e) => {
                    toast::show(
                        cx,
                        format!("Failed to restore item: {e}"),
                        crate::toast::ToastKind::Error,
                    );
                }
            })
            .ok();
        })
        .detach();
    }

    fn purge(&mut self, id: String, cx: &mut Context<Self>) {
        // Two-step: the first click arms the confirm, the second erases.
        if self.confirming_purge.as_deref() != Some(id.as_str()) {
            self.confirming_purge = Some(id);
            cx.notify();
            return;
        }
        self.confirming_purge = None;
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("purge item", {
                    let app_state = app_state.clone();
                    let id = id.clone();
                    async move {
                        vela_desktop_core::commands::vault::purge_deleted_item(&app_state, &id)
                            .await
                    }
                })
                .await
                .unwrap_or_else(|| Err("Purging the item failed unexpectedly".to_string()));
            this.update(cx, |this, cx| match result {
                Ok(()) => {
                    toast::show(cx, "Deleted forever", crate::toast::ToastKind::Success);
                    host::notify_vault_items_changed(cx);
                    this.reload(cx);
                }
                Err(e) => {
                    toast::show(cx, format!("Failed to delete item: {e}"), crate::toast::ToastKind::Error);
                }
            })
            .ok();
        })
        .detach();
    }
}

impl Render for TrashScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);

        let mut body = div()
            .id("trash-scroll")
            .size_full()
            .flex()
            .flex_col()
            .overflow_y_scroll()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .p_6()
            .gap_6()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(icon("delete", px(22.), palette.on_surface_variant))
                            .child(
                                div()
                                    .font_family(fonts::HEADLINE)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_2xl()
                                    .text_color(palette.on_surface)
                                    .child("Trash"),
                            ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(palette.on_surface_variant)
                            .child("Deleted items stay here for 30 days. Restoring an item syncs it back to every device."),
                    ),
            );

        if let Some(error) = &self.error {
            body = body.child(div().text_sm().text_color(palette.error).child(error.clone()));
        } else if let Some(entries) = &self.entries {
            if entries.is_empty() {
                body = body.child(
                    div()
                        .flex()
                        .flex_col()
                        .items_center()
                        .gap_3()
                        .py_16()
                        .text_color(palette.on_surface_variant)
                        .child(icon("delete_sweep", px(48.), palette.outline_variant))
                        .child("The trash is empty"),
                );
            } else {
                let mut rows = div().flex().flex_col().gap_3();
                for entry in entries.iter() {
                    let id = entry.item.id().to_string();
                    let name: SharedString = entry.item.name().to_string().into();
                    let kind = friendly_type(&format!("{:?}", entry.item.item_type()).to_lowercase());
                    let deleted_at: SharedString = entry
                        .deleted_at
                        .with_timezone(&Local)
                        .format("%b %-d, %H:%M")
                        .to_string()
                        .into();
                    let armed = self.confirming_purge.as_deref() == Some(id.as_str());
                    let restore_id = id.clone();
                    let purge_id = id.clone();
                    let restore_chip = SharedString::from(format!("restore-{id}"));
                    let purge_chip = SharedString::from(format!("purge-{id}"));

                    rows = rows.child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_4()
                            .p_4()
                            .rounded_xl()
                            .bg(palette.surface_container_low)
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_4()
                                    .min_w_0()
                                    .child(icon(type_icon(&format!("{:?}", entry.item.item_type()).to_lowercase()), px(20.), palette.on_surface_variant))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .min_w_0()
                                            .child(
                                                div()
                                                    .font_family(fonts::BODY)
                                                    .font_weight(gpui::FontWeight::BOLD)
                                                    .text_color(palette.on_surface)
                                                    .text_ellipsis()
                                                    .child(name.clone()),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(palette.on_surface_variant)
                                                    .child(format!("{kind} · deleted {deleted_at}")),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(action_button(
                                        &palette,
                                        restore_chip,
                                        "restore",
                                        "Restore",
                                        false,
                                        cx.listener(move |this, _, _, cx| {
                                            this.restore(restore_id.clone(), name.to_string(), cx);
                                        }),
                                    ))
                                    .child(action_button(
                                        &palette,
                                        purge_chip,
                                        "delete_forever",
                                        if armed { "Confirm" } else { "Delete forever" },
                                        armed,
                                        cx.listener(move |this, _, _, cx| {
                                            this.purge(purge_id.clone(), cx);
                                        }),
                                    )),
                            ),
                    );
                }
                body = body.child(rows);
            }
        } else {
            body = body.child(div().text_sm().text_color(palette.on_surface_variant).child("Loading…"));
        }

        body
    }
}

fn action_button(
    palette: &Palette,
    id: SharedString,
    icon_name: &'static str,
    label: &'static str,
    danger: bool,
    handler: impl Fn(&gpui::MouseDownEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let icon_color = if danger { palette.error } else { palette.primary };
    div()
        .id(id)
        .flex()
        .items_center()
        .gap_2()
        .px_4()
        .py_2()
        .rounded_lg()
        .text_sm()
        .font_weight(gpui::FontWeight::MEDIUM)
        .cursor_pointer()
        .map(|el| if danger {
            el.bg(palette.error.opacity(0.15)).text_color(palette.error)
        } else {
            el.bg(palette.primary.opacity(0.1)).text_color(palette.primary)
        })
        .child(icon(icon_name, px(14.), icon_color))
        .child(label)
        .on_mouse_down(MouseButton::Left, handler)
}
