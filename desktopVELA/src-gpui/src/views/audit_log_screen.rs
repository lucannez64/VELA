//! Port of `desktopVELA/src/views/AuditLogScreen.tsx` — read-only activity
//! feed, grouped by day. Calls the real (read-only)
//! `vela_desktop_core::audit::load_audit_log`, the same encrypted local
//! audit log the shipped Tauri app reads — safe, no vault mutation.
//!
//! Not ported: nothing was actually skipped here — the original has no
//! actions besides reading/rendering the log.

use std::sync::Arc;

use chrono::{DateTime, Local};
use gpui::{div, prelude::*, px, Context, IntoElement, Render, SharedString, Task, Window};

use vela_desktop_core::audit::{AuditAction, AuditEntry};
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

pub struct AuditLogScreen {
    entries: Option<Vec<AuditEntry>>,
    error: Option<SharedString>,
    _pulse_task: Task<()>,
}

impl AuditLogScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.spawn(async move |this, cx| {
            let log = cx
                .background_spawn_guarded("load audit log", async move {
                    vela_desktop_core::audit::load_audit_log(&app_state)
                })
                .await
                // Both the guard's `None` and the loader's own `None` mean
                // the same thing to the screen below: no log to show.
                .flatten();
            this.update(cx, |this, cx| {
                match log {
                    Some(log) => {
                        let mut entries = log.entries;
                        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                        this.entries = Some(entries);
                    }
                    None => this.error = Some("Failed to load audit log".into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();

        Self {
            entries: None,
            error: None,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }
}

/// (label, icon name) per action, matching the original's `actionLabels`
/// table. Color is derived separately since it needs a live `&Palette`.
fn action_label_icon(action: &AuditAction) -> (&'static str, &'static str) {
    match action {
        AuditAction::VaultSync { .. } => ("Vault synced", "sync"),
        AuditAction::VaultCreated => ("Vault created", "add_circle"),
        AuditAction::VaultUnlocked => ("Vault unlocked", "lock_open"),
        AuditAction::VaultLocked => ("Vault locked", "lock"),
        AuditAction::DeviceEnrolled { .. } => ("Device enrolled", "devices"),
        AuditAction::DeviceRevoked { .. } => ("Device revoked", "device_unknown"),
        AuditAction::ShareSent { .. } => ("Share sent", "send"),
        AuditAction::ShareReceived { .. } => ("Share received", "inbox"),
        AuditAction::ItemAdded { .. } => ("Item added", "add"),
        AuditAction::ItemUpdated { .. } => ("Item updated", "edit"),
        AuditAction::ItemDeleted { .. } => ("Item deleted", "delete"),
        AuditAction::PasswordGenerated { .. } => ("Password generated", "password"),
        AuditAction::SettingsChanged => ("Settings changed", "settings"),
        AuditAction::WebSessionGranted { .. } => ("Web session granted", "devices"),
    }
}

fn action_color(action: &AuditAction, palette: &Palette) -> gpui::Hsla {
    match action {
        AuditAction::DeviceRevoked { .. } | AuditAction::ItemDeleted { .. } => palette.error,
        AuditAction::VaultCreated
        | AuditAction::DeviceEnrolled { .. }
        | AuditAction::ShareReceived { .. } => palette.secondary,
        AuditAction::VaultLocked | AuditAction::SettingsChanged => palette.on_surface_variant,
        _ => palette.primary,
    }
}

/// Port of the original's `getActionDetails`.
fn action_details(action: &AuditAction) -> Option<String> {
    match action {
        AuditAction::VaultSync { chunk_count } => Some(format!("{chunk_count} chunk(s)")),
        AuditAction::DeviceEnrolled { device_id, .. } => Some(format!("Device {}…", short_id(device_id))),
        AuditAction::DeviceRevoked { device_id, .. } => Some(format!("Device {}…", short_id(device_id))),
        AuditAction::ShareSent { recipient_user_id } => Some(format!("To {}…", short_id(recipient_user_id))),
        AuditAction::ShareReceived { sender_user_id } => Some(format!("From {}…", short_id(sender_user_id))),
        AuditAction::ItemAdded { item_type } | AuditAction::ItemUpdated { item_type } | AuditAction::ItemDeleted { item_type } => {
            Some(item_type.clone())
        }
        AuditAction::PasswordGenerated { length } => Some(format!("{length} characters")),
        _ => None,
    }
}

fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn device_name(entry: &AuditEntry) -> &str {
    match &entry.subject {
        vela_desktop_core::audit::AuditSubject::Device { device_name }
        | vela_desktop_core::audit::AuditSubject::Session { device_name } => device_name,
    }
}

impl Render for AuditLogScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);

        div()
            .id("audit-log-scroll")
            .size_full()
            .overflow_y_scroll()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .p_8()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .mb_8()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .font_family(fonts::HEADLINE)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_3xl()
                                    .text_color(palette.on_surface)
                                    .child("Activity Log"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(icon("lock", px(18.), palette.secondary))
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(palette.on_surface_variant)
                                            .child("Encrypted end-to-end. Only your enrolled devices can read this."),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_4()
                            .py_2()
                            .rounded_full()
                            .bg(gpui::Hsla { a: 0.1, ..palette.secondary })
                            .child(div().w(px(8.)).h(px(8.)).rounded_full().bg(palette.secondary))
                            .child(
                                fonts::tracked_text("ENCRYPTED", px(12.), 0.1)
                                    .font_family(fonts::LABEL)
                                    .text_xs()
                                    .text_color(palette.secondary),
                            ),
                    ),
            )
            .map(|el| match &self.entries {
                None => el.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .py_16()
                        .child(
                            icon("progress_activity", px(36.), palette.primary)
                                .opacity(animation::pulse_alpha(1.0)),
                        ),
                ),
                Some(entries) if entries.is_empty() => el.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .py_16()
                        .text_color(palette.on_surface_variant)
                        .child("No activity yet"),
                ),
                Some(entries) => el.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_8()
                        .children(date_groups(entries).into_iter().map(|(date, group)| {
                            date_group_section(&palette, &date, group, window, cx)
                        })),
                ),
            })
            .when_some(self.error.clone(), |el, error| {
                el.child(div().text_sm().text_color(palette.error).child(error))
            })
    }
}

/// Groups already-sorted (descending) entries into contiguous same-day runs
/// — cheaper than a hashmap since the input is pre-sorted by timestamp, and
/// preserves the original's "most recent day first" ordering for free.
fn date_groups(entries: &[AuditEntry]) -> Vec<(String, Vec<&AuditEntry>)> {
    let mut groups: Vec<(String, Vec<&AuditEntry>)> = Vec::new();
    for entry in entries {
        let local: DateTime<Local> = entry.timestamp.with_timezone(&Local);
        let date = local.format("%B %-d, %Y").to_string();
        match groups.last_mut() {
            Some((last_date, group)) if *last_date == date => group.push(entry),
            _ => groups.push((date, vec![entry])),
        }
    }
    groups
}

fn date_group_section(
    palette: &Palette,
    date: &str,
    entries: Vec<&AuditEntry>,
    window: &mut Window,
    cx: &mut Context<AuditLogScreen>,
) -> impl IntoElement {
    div()
        .child(
            fonts::tracked_text(date, px(12.), 0.1)
                .font_family(fonts::LABEL)
                .text_xs()
                .text_color(palette.outline)
                .mb_4(),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .children(entries.into_iter().map(|entry| audit_row(palette, entry, window, cx))),
        )
}

fn audit_row(
    palette: &Palette,
    entry: &AuditEntry,
    window: &mut Window,
    cx: &mut Context<AuditLogScreen>,
) -> impl IntoElement {
    let (label, icon_name) = action_label_icon(&entry.action);
    let color = action_color(&entry.action, palette);
    let details = action_details(&entry.action);
    let local_time: DateTime<Local> = entry.timestamp.with_timezone(&Local);
    let time = local_time.format("%I:%M %p").to_string();
    let device = device_name(entry).to_string();
    let row_id = SharedString::from(format!("audit-{}", entry.id));

    let hover_t = animation::hover_transition(row_id.clone(), window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = animation::lerp_hsla(palette.surface_container, palette.surface_container_high, t);

    div()
        .id(row_id)
        .flex()
        .items_center()
        .gap_4()
        .p_4()
        .rounded_xl()
        .bg(bg)
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .child(
            div()
                .w(px(40.))
                .h(px(40.))
                .flex_shrink_0()
                .rounded_full()
                .bg(palette.surface_container_highest)
                .flex()
                .items_center()
                .justify_center()
                .child(icon(icon_name, px(20.), color)),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.))
                .flex()
                .flex_col()
                .child(
                    div()
                        .font_family(fonts::BODY)
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_color(palette.on_surface)
                        .child(label),
                )
                .when_some(details, |el, details| {
                    el.child(div().text_sm().text_color(palette.on_surface_variant).child(details))
                }),
        )
        .child(
            div()
                .flex_shrink_0()
                .font_family(fonts::MONO)
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child(time),
        )
        .child(
            div()
                .flex_shrink_0()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .text_ellipsis()
                .overflow_hidden()
                .whitespace_nowrap()
                .max_w(px(140.))
                .child(device),
        )
}
