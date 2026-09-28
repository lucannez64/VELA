//! Port of `desktopVELA/src/views/AuditLogScreen.tsx` — read-only activity
//! feed, grouped by day. Calls the real (read-only)
//! `vela_desktop_core::audit::load_audit_log`, the same encrypted local
//! audit log the shipped Tauri app reads — safe, no vault mutation.
//!
//! The feed is virtualized with gpui's variable-height `list` (the same
//! element `VaultBrowser` uses). The original Tauri view rendered every entry
//! eagerly, which is survivable in React's reconciler but not here: gpui rebuilt
//! the whole tree — and a hover `Transition` per row — on every repaint, and the
//! loading spinner's 10fps ticker kept repainting forever, so a large log made
//! the app crawl. `list` renders only the visible window and the ticker is
//! dropped once the entries land.
//!
//! Not ported: nothing was actually skipped here — the original has no
//! actions besides reading/rendering the log.

use std::sync::Arc;

use chrono::{DateTime, Local};
use gpui::{
    div, list, prelude::*, px, App, Context, IntoElement, ListAlignment, ListState, Render,
    SharedString, Task, Window,
};

use vela_desktop_core::audit::{AuditAction, AuditEntry};
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

/// One virtualized row: a day header or an entry (index into `entries`).
enum AuditRow {
    Date(SharedString),
    Entry(usize),
}

pub struct AuditLogScreen {
    /// Shared with the `list` render closure, which only gets `&mut App` and so
    /// cannot read `self` — the same snapshot-by-`Arc` trick `VaultBrowser`
    /// uses for its items.
    entries: Option<Arc<Vec<AuditEntry>>>,
    /// Flattened day-header/entry rows, rebuilt once when the log loads rather
    /// than on every repaint (which is what made a large log expensive).
    rows: Arc<Vec<AuditRow>>,
    error: Option<SharedString>,
    list_state: ListState,
    /// Drives the loading spinner while the entries are in flight, then is
    /// dropped when they land — a large loaded log must not be repainted 10×/s
    /// for a spinner that is no longer on screen.
    _pulse_task: Option<Task<()>>,
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
                        let rows = build_rows(&entries);
                        this.list_state.reset(rows.len());
                        this.rows = Arc::new(rows);
                        this.entries = Some(Arc::new(entries));
                    }
                    None => this.error = Some("Failed to load audit log".into()),
                }
                // Loading is over either way; the spinner's repaint loop has
                // nothing left to animate.
                this._pulse_task = None;
                cx.notify();
            })
            .ok();
        })
        .detach();

        Self {
            entries: None,
            rows: Arc::new(Vec::new()),
            error: None,
            list_state: ListState::new(0, ListAlignment::Top, px(400.)),
            _pulse_task: Some(animation::spawn_pulse_ticker(cx)),
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
        AuditAction::VaultRekeyed { .. } => ("Vault keys rotated", "sync"),
        AuditAction::PlaintextIdentityKeysMigrated => {
            ("Device keys were stored unencrypted", "warning")
        }
        AuditAction::CredentialReleased { .. } => ("Credential filled", "key"),
    }
}

fn action_color(action: &AuditAction, palette: &Palette) -> gpui::Hsla {
    match action {
        // Red on purpose: this one is telling the user something already went
        // wrong, not reporting a routine action.
        AuditAction::DeviceRevoked { .. }
        | AuditAction::ItemDeleted { .. }
        | AuditAction::PlaintextIdentityKeysMigrated => palette.error,
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
        AuditAction::PlaintextIdentityKeysMigrated => Some(
            "This device's signing keys were found in cleartext and have been encrypted. Anything that could read the data directory before now had them — consider re-enrolling this device."
                .to_string(),
        ),
        AuditAction::VaultSync { chunk_count } => Some(format!("{chunk_count} chunk(s)")),
        AuditAction::DeviceEnrolled { device_id, .. } => Some(format!("Device {}…", short_id(device_id))),
        AuditAction::DeviceRevoked { device_id, .. } => Some(format!("Device {}…", short_id(device_id))),
        AuditAction::ShareSent { recipient_user_id } => Some(format!("To {}…", short_id(recipient_user_id))),
        AuditAction::ShareReceived { sender_user_id } => Some(format!("From {}…", short_id(sender_user_id))),
        AuditAction::ItemAdded { item_type } | AuditAction::ItemUpdated { item_type } | AuditAction::ItemDeleted { item_type } => {
            Some(item_type.clone())
        }
        AuditAction::PasswordGenerated { length } => Some(format!("{length} characters")),
        AuditAction::CredentialReleased { caller, domain } => {
            Some(format!("{domain} → {caller}"))
        }
        AuditAction::VaultRekeyed { from_epoch, to_epoch } => {
            Some(format!("Epoch {from_epoch} → {to_epoch}"))
        }
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

/// The entry's calendar-day label in the local timezone (the original's
/// `toLocaleDateString` with month/day/year).
fn local_date(entry: &AuditEntry) -> String {
    let local: DateTime<Local> = entry.timestamp.with_timezone(&Local);
    local.format("%B %-d, %Y").to_string()
}

/// Flattens already-sorted (descending) entries into day headers + entry rows.
///
/// A contiguous same-day run becomes one header, so the input is walked once —
/// cheaper than a map, and it preserves the original's "most recent day first"
/// ordering for free.
fn build_rows(entries: &[AuditEntry]) -> Vec<AuditRow> {
    let mut rows = Vec::with_capacity(entries.len() + 8);
    let mut last_date: Option<String> = None;
    for (index, entry) in entries.iter().enumerate() {
        let date = local_date(entry);
        if last_date.as_deref() != Some(date.as_str()) {
            rows.push(AuditRow::Date(date.clone().into()));
            last_date = Some(date);
        }
        rows.push(AuditRow::Entry(index));
    }
    rows
}

impl Render for AuditLogScreen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let rows = self.rows.clone();
        let entries = self.entries.clone();

        // The page header stays put; the virtualized `list` fills the rest of
        // the viewport and scrolls internally, so only visible rows are built.
        let body = match (&self.entries, &self.error) {
            (None, Some(error)) => div()
                .flex()
                .items_center()
                .justify_center()
                .py_16()
                .text_color(palette.error)
                .child(error.clone())
                .into_any_element(),
            (None, None) => div()
                .flex()
                .items_center()
                .justify_center()
                .py_16()
                .child(
                    icon("progress_activity", px(36.), palette.primary)
                        .opacity(animation::pulse_alpha(1.0)),
                )
                .into_any_element(),
            (Some(entries), _) if entries.is_empty() => div()
                .flex()
                .items_center()
                .justify_center()
                .py_16()
                .text_color(palette.on_surface_variant)
                .child("No activity yet")
                .into_any_element(),
            (Some(_), _) => list(self.list_state.clone(), move |ix, window, app| match &rows[ix] {
                AuditRow::Date(date) => date_header(&palette, date).into_any_element(),
                AuditRow::Entry(entry_ix) => {
                    // `rows` and `entries` are snapshots from the same load
                    // (rebuilt together, above), so the index is always valid.
                    let entries = entries.as_ref().expect("rows imply loaded entries");
                    div()
                        .pb_2()
                        .child(audit_row(&palette, &entries[*entry_ix], window, app))
                        .into_any_element()
                }
            })
            .flex_1()
            .min_h(px(0.))
            .w_full()
            .into_any_element(),
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .p_8()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .mb_6()
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
            // The error state is rendered by `body` above (there is no log to
            // show), so it isn't appended a second time here.
            .child(body)
    }
}

/// A day separator inside the virtualized list. Padding rather than margin so
/// the `list` measurement stays a simple box height.
fn date_header(palette: &Palette, date: &str) -> impl IntoElement {
    div()
        .pt_4()
        .pb_2()
        .child(
            fonts::tracked_text(date, px(12.), 0.1)
                .font_family(fonts::LABEL)
                .text_xs()
                .text_color(palette.outline),
        )
}

fn audit_row(
    palette: &Palette,
    entry: &AuditEntry,
    window: &mut Window,
    app: &mut App,
) -> impl IntoElement {
    let (label, icon_name) = action_label_icon(&entry.action);
    let color = action_color(&entry.action, palette);
    let details = action_details(&entry.action);
    let local_time: DateTime<Local> = entry.timestamp.with_timezone(&Local);
    let time = local_time.format("%I:%M %p").to_string();
    let device = device_name(entry).to_string();
    let row_id = SharedString::from(format!("audit-{}", entry.id));

    let hover_t = animation::hover_transition(row_id.clone(), window, app);
    let t = *hover_t.evaluate(window, app);
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use vela_desktop_core::audit::AuditSubject;

    fn entry(id: &str, ts: DateTime<Utc>, action: AuditAction) -> AuditEntry {
        AuditEntry {
            id: id.into(),
            timestamp: ts,
            action,
            subject: AuditSubject::Device { device_name: "test-box".into() },
        }
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn every_action_has_a_label_and_icon() {
        let actions = [
            AuditAction::VaultSync { chunk_count: 1 },
            AuditAction::VaultCreated,
            AuditAction::VaultUnlocked,
            AuditAction::VaultLocked,
            AuditAction::DeviceEnrolled { device_id: "d".into(), enrolling_device_id: None },
            AuditAction::DeviceRevoked { device_id: "d".into(), revoking_device_id: "r".into() },
            AuditAction::ShareSent { recipient_user_id: "u".into() },
            AuditAction::ShareReceived { sender_user_id: "u".into() },
            AuditAction::ItemAdded { item_type: "login".into() },
            AuditAction::ItemUpdated { item_type: "login".into() },
            AuditAction::ItemDeleted { item_type: "login".into() },
            AuditAction::PasswordGenerated { length: 20 },
            AuditAction::SettingsChanged,
            AuditAction::WebSessionGranted { mode: "ro".into(), ttl_secs: 60 },
            AuditAction::CredentialReleased {
                caller: "firefox (pid 4321)".into(),
                domain: "github.com".into(),
            },
        ];
        for action in &actions {
            let (label, icon) = action_label_icon(action);
            assert!(!label.is_empty(), "label missing for {action:?}");
            assert!(!icon.is_empty(), "icon missing for {action:?}");
        }
        assert_eq!(action_label_icon(&AuditAction::VaultLocked), ("Vault locked", "lock"));
    }

    #[test]
    fn action_details_render_payload_fields() {
        assert_eq!(
            action_details(&AuditAction::VaultSync { chunk_count: 5 }),
            Some("5 chunk(s)".into())
        );
        assert_eq!(
            action_details(&AuditAction::ItemAdded { item_type: "login".into() }),
            Some("login".into())
        );
        assert_eq!(
            action_details(&AuditAction::PasswordGenerated { length: 20 }),
            Some("20 characters".into())
        );
        assert_eq!(
            action_details(&AuditAction::CredentialReleased {
                caller: "firefox (pid 4321)".into(),
                domain: "github.com".into(),
            }),
            Some("github.com → firefox (pid 4321)".into())
        );
        assert_eq!(
            action_details(&AuditAction::DeviceEnrolled {
                device_id: "abcdefgh1234".into(),
                enrolling_device_id: None,
            }),
            Some("Device abcdefgh…".into())
        );
        assert_eq!(action_details(&AuditAction::VaultLocked), None);
        assert_eq!(action_details(&AuditAction::SettingsChanged), None);
    }

    #[test]
    fn short_id_truncates_to_eight_chars() {
        assert_eq!(short_id("abcdefgh1234"), "abcdefgh");
        assert_eq!(short_id("abcdefgh"), "abcdefgh");
        assert_eq!(short_id("abc"), "abc");
    }

    #[test]
    fn device_name_reads_both_subject_variants() {
        let device = entry("a", ts("2025-03-01T12:00:00Z"), AuditAction::VaultLocked);
        assert_eq!(device_name(&device), "test-box");

        let session = AuditEntry {
            subject: AuditSubject::Session { device_name: "web".into() },
            ..entry("b", ts("2025-03-01T12:00:00Z"), AuditAction::VaultLocked)
        };
        assert_eq!(device_name(&session), "web");
    }

    #[test]
    fn build_rows_contiguous_days_preserving_order() {
        // Noon UTC keeps the local calendar day stable in every timezone
        // (±12h never crosses midnight; even ±14h keeps the two days apart).
        let day2_late = entry("c", ts("2025-03-02T11:00:00Z"), AuditAction::VaultUnlocked);
        let day2_early = entry("b", ts("2025-03-02T09:00:00Z"), AuditAction::VaultLocked);
        let day1 = entry("a", ts("2025-03-01T12:00:00Z"), AuditAction::VaultCreated);
        let entries = vec![day2_late, day2_early, day1];

        let rows = build_rows(&entries);
        // header, c, b, header, a — two calendar days, entries in the
        // original (descending) order.
        assert_eq!(rows.len(), 5, "two day headers plus three entries");
        let (AuditRow::Date(first_day), AuditRow::Date(second_day)) = (&rows[0], &rows[3]) else {
            panic!("expected day headers at rows 0 and 3");
        };
        assert_ne!(first_day, second_day, "group headers are the day labels");
        let AuditRow::Entry(c) = &rows[1] else { panic!("row 1 is an entry") };
        let AuditRow::Entry(b) = &rows[2] else { panic!("row 2 is an entry") };
        let AuditRow::Entry(a) = &rows[4] else { panic!("row 4 is an entry") };
        assert_eq!(entries[*c].id, "c");
        assert_eq!(entries[*b].id, "b");
        assert_eq!(entries[*a].id, "a");
    }

    #[test]
    fn build_rows_empty_input() {
        assert!(build_rows(&[]).is_empty());
    }

    #[test]
    fn build_rows_reindexes_across_day_boundaries() {
        // The entry indices must point into the *original* slice — the second
        // day's first entry is index 2, not 0.
        let entries = vec![
            entry("a", ts("2025-03-02T11:00:00Z"), AuditAction::VaultUnlocked),
            entry("b", ts("2025-03-02T09:00:00Z"), AuditAction::VaultLocked),
            entry("c", ts("2025-03-01T12:00:00Z"), AuditAction::VaultCreated),
        ];
        let rows = build_rows(&entries);
        // header, a, b, header, c
        assert!(matches!(rows[3], AuditRow::Date(_)));
        let AuditRow::Entry(third) = &rows[4] else { panic!("row 4 is the day-2 entry") };
        assert_eq!(*third, 2);
        assert_eq!(entries[*third].id, "c");
    }

    #[test]
    fn action_color_semantics() {
        let palette = Palette::vela();
        let eq = |a: gpui::Hsla, b: gpui::Hsla| a.h == b.h && a.s == b.s && a.l == b.l && a.a == b.a;

        assert!(eq(action_color(&AuditAction::ItemDeleted { item_type: "login".into() }, &palette), palette.error));
        assert!(eq(action_color(&AuditAction::DeviceRevoked { device_id: "d".into(), revoking_device_id: "r".into() }, &palette), palette.error));
        assert!(eq(action_color(&AuditAction::VaultCreated, &palette), palette.secondary));
        assert!(eq(action_color(&AuditAction::VaultLocked, &palette), palette.on_surface_variant));
        assert!(eq(action_color(&AuditAction::ItemAdded { item_type: "login".into() }, &palette), palette.primary));
    }

    #[test]
    fn local_timezone_conversion_is_stable() {
        // The grouping math must hold for any reference timestamp.
        let t = Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap();
        let entries = [entry("x", t, AuditAction::VaultLocked)];
        let rows = build_rows(&entries);
        assert_eq!(rows.len(), 2);
        let AuditRow::Date(date) = &rows[0] else { panic!("first row is the day header") };
        assert!(date.contains("2025"));
    }
}
