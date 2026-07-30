//! Port of `desktopVELA/src/views/SettingsScreen.tsx`.
//!
//! Write-path safety: `theme`/`auto_lock_minutes`/`clipboard_clear_seconds`/
//! `require_biometric_on_reveal`/`quick_search_shortcut`/`server_url`/
//! `sync_on_startup`/`background_sync_minutes` are all real settings-file
//! writes via `vela_desktop_core::commands::settings::update_settings` (not
//! vault data — same trust level as any other real settings change made
//! through the shipped Tauri app). "Sign out" is a real `lock_session` call
//! (clears in-memory crypto/vault, no disk mutation beyond the existing
//! audit log). **Delete vault now calls the real `reset_vault`** — typing
//! "DELETE" to confirm really, permanently deletes the vault; on success the
//! app routes back to the Welcome (first-launch) screen.
//!
//! "Sync now" now calls the real `vela_desktop_core::sync::trigger_sync` —
//! the full chunked, encrypted, lamport-clocked sync protocol with
//! tombstone-aware conflict detection (extracted verbatim from
//! `src-tauri/src/commands/sync.rs`). "Last synced" reflects a real
//! `get_sync_status` read on mount, refreshed after every sync attempt.
//!
//! Not ported: RecoverySettings' cloud-backup/security-key/trusted-contact
//! flows (WebAuthn-dependent, deliberately deferred — see the plan's
//! "WebAuthn/FIDO2 last" scope cut), native Export/Import file dialogs. The
//! quick-search-shortcut edit and the global shortcut re-registration side
//! effect are not live in the gpui build yet (see `vela_desktop_core::
//! commands::settings::update_settings`'s doc comment) — a changed
//! shortcut is only persisted, applying after a restart.

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, Context, EventEmitter, IntoElement, MouseButton, Render, SharedString,
    Task, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::commands::settings::{get_settings, update_settings};
use vela_desktop_core::settings::Settings;
use vela_desktop_core::vault::VaultItem;
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::{Palette, ThemeId};

pub enum SettingsScreenEvent {
    ThemeChanged(ThemeId),
    SignedOut,
    /// The vault was actually, permanently deleted — the app should go back
    /// to the first-launch Welcome screen, not BiometricGate (there's no
    /// vault left to unlock).
    VaultDeleted,
}
impl EventEmitter<SettingsScreenEvent> for SettingsScreen {}

pub struct SettingsScreen {
    app_state: Arc<AppState>,
    settings: Option<Settings>,
    error: Option<SharedString>,
    editing_server_url: bool,
    server_url_state: gpui::Entity<EditableTextState>,
    editing_shortcut: bool,
    shortcut_state: gpui::Entity<EditableTextState>,
    show_delete_modal: bool,
    delete_confirm_state: gpui::Entity<EditableTextState>,
    deleting: bool,
    delete_error: Option<SharedString>,
    syncing: bool,
    sync_status: Option<vela_desktop_core::sync::SyncStatus>,
    sync_error: Option<SharedString>,
    conflict_modal: Option<ConflictResolutionState>,
    resolving: bool,
    resolve_error: Option<SharedString>,
    exporting: bool,
    importing: bool,
    export_import_status: Option<SharedString>,
    recovery_status: Option<vela_desktop_core::recovery::RecoveryStatus>,
    show_security_key_modal: bool,
    security_key_pin_state: gpui::Entity<EditableTextState>,
    registering_security_key: bool,
    security_key_error: Option<SharedString>,
    _pulse_task: Task<()>,
}

/// Port of `ConflictResolution.tsx`'s local carousel-index state.
struct ConflictResolutionState {
    conflicts: Vec<vela_desktop_core::sync::ConflictItem>,
    index: usize,
}

#[derive(Clone, Copy)]
enum ConflictAction {
    KeepLocal,
    KeepServer,
    KeepBoth,
}

impl SettingsScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.spawn({
            let app_state = app_state.clone();
            async move |this, cx| {
                let result = cx
                    .background_spawn_guarded("load settings", {
                        let app_state = app_state.clone();
                        async move { get_settings(&app_state) }
                    })
                    .await
                    .unwrap_or_else(|| Err("Loading settings failed unexpectedly".to_string()));
                this.update(cx, |this, cx| {
                    match result {
                        Ok(settings) => this.settings = Some(settings),
                        Err(e) => this.error = Some(e.into()),
                    }
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();

        Self::load_sync_status(&app_state, cx);
        Self::load_recovery_status(&app_state, cx);

        Self {
            app_state,
            settings: None,
            error: None,
            editing_server_url: false,
            server_url_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            editing_shortcut: false,
            shortcut_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            show_delete_modal: false,
            delete_confirm_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            deleting: false,
            delete_error: None,
            syncing: false,
            sync_status: None,
            sync_error: None,
            conflict_modal: None,
            resolving: false,
            resolve_error: None,
            exporting: false,
            importing: false,
            export_import_status: None,
            recovery_status: None,
            show_security_key_modal: false,
            security_key_pin_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            registering_security_key: false,
            security_key_error: None,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }

    fn load_recovery_status(app_state: &Arc<AppState>, cx: &mut Context<Self>) {
        let app_state = app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("load recovery status", async move {
                    vela_desktop_core::recovery::get_recovery_setup_status(&app_state)
                })
                .await
                .unwrap_or_else(|| Err("Loading recovery status failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                if let Ok(status) = result {
                    this.recovery_status = Some(status);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_security_key_modal(&mut self, cx: &mut Context<Self>) {
        self.security_key_pin_state.update(cx, |s, cx| s.emplace("", cx));
        self.security_key_error = None;
        self.show_security_key_modal = true;
        cx.notify();
    }

    fn close_security_key_modal(&mut self, cx: &mut Context<Self>) {
        self.show_security_key_modal = false;
        cx.notify();
    }

    fn register_security_key(&mut self, cx: &mut Context<Self>) {
        let pin = self.security_key_pin_state.read(cx).as_str().to_string();
        if pin.is_empty() {
            self.security_key_error = Some("Enter your security key's PIN".into());
            cx.notify();
            return;
        }

        self.registering_security_key = true;
        self.security_key_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network calls (registration challenge/finish, recovery
            // share upload) plus a blocking hardware ceremony inside — must
            // run via gpui_tokio's bridge onto the actual tokio runtime, not
            // `cx.background_spawn` (a separate thread pool that never
            // entered that runtime and panics on real reactor I/O).
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::webauthn::register_security_key(&app_state, pin).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.registering_security_key = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_security_key_modal = false;
                        let app_state = this.app_state.clone();
                        Self::load_recovery_status(&app_state, cx);
                    }
                    Ok(Err(e)) => this.security_key_error = Some(e.into()),
                    Err(e) => this.security_key_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Real, but purely local — reads `sync_meta.json`'s mtime and decrypts
    /// the local conflicts store. No network I/O, so plain `background_spawn`
    /// is fine here (unlike `sync_now`, which must go through
    /// `gpui_tokio::Tokio::spawn`).
    fn load_sync_status(app_state: &Arc<AppState>, cx: &mut Context<Self>) {
        let app_state = app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("load sync status", async move {
                    vela_desktop_core::sync::get_sync_status(&app_state).await
                })
                .await
                .unwrap_or_else(|| Err("Loading sync status failed unexpectedly".to_string()));
            this.update(cx, |this, cx| {
                if let Ok(status) = result {
                    this.sync_status = Some(status);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn sync_now(&mut self, cx: &mut Context<Self>) {
        self.syncing = true;
        self.sync_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network I/O (chunk upload/download, server auth) — must
            // run via gpui_tokio's bridge onto the actual tokio runtime, not
            // `cx.background_spawn` (a separate thread pool that never
            // entered that runtime and panics on real reactor I/O).
            let result =
                gpui_tokio::Tokio::spawn(cx, async move { vela_desktop_core::sync::trigger_sync(&app_state).await })
                    .await;
            this.update(cx, |this, cx| {
                this.syncing = false;
                // Same toast text/type mapping as the original's `doSync`
                // (`App.tsx`): a reported `status.error` is an "info" toast
                // (not fatal, e.g. "server unreachable, will retry"),
                // conflicts are "error", a clean sync is "success".
                use crate::toast::{show, ToastKind};
                match result {
                    Ok(Ok(status)) => {
                        if let Some(err) = &status.error {
                            show(cx, err.clone(), ToastKind::Info);
                        } else if !status.conflicts.is_empty() {
                            show(cx, format!("{} conflict(s) detected", status.conflicts.len()), ToastKind::Error);
                        } else {
                            show(cx, "Vault synced", ToastKind::Success);
                        }
                        this.sync_error = status.error.clone().map(Into::into);
                        this.sync_status = Some(status);
                    }
                    Ok(Err(e)) => {
                        show(cx, format!("Sync failed: {e}"), ToastKind::Error);
                        this.sync_error = Some(e.into());
                    }
                    Err(e) => {
                        show(cx, format!("Sync failed: Task failed: {e}"), ToastKind::Error);
                        this.sync_error = Some(format!("Task failed: {e}").into());
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_conflict_modal(&mut self, cx: &mut Context<Self>) {
        if let Some(status) = &self.sync_status {
            if !status.conflicts.is_empty() {
                self.conflict_modal =
                    Some(ConflictResolutionState { conflicts: status.conflicts.clone(), index: 0 });
                self.resolve_error = None;
                cx.notify();
            }
        }
    }

    fn close_conflict_modal(&mut self, cx: &mut Context<Self>) {
        self.conflict_modal = None;
        self.resolve_error = None;
        cx.notify();
    }

    /// Ports `ConflictResolution.tsx`'s three handlers. Each first writes the
    /// chosen `VaultItem` for real (`update_item`/`add_item`), then marks the
    /// conflict resolved server-side via `resolve_conflict` — same two-step
    /// sequence as the original, same order (write wins even if the second
    /// call fails; a stale "unresolved" marker is recoverable, a lost edit
    /// isn't).
    fn resolve_conflict_action(&mut self, action: ConflictAction, cx: &mut Context<Self>) {
        let Some(modal) = &self.conflict_modal else { return };
        let Some(conflict) = modal.conflicts.get(modal.index).cloned() else { return };

        self.resolving = true;
        self.resolve_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let item_id = conflict.item_id.clone();
            let result: Result<(), String> = gpui_tokio::Tokio::spawn(cx, async move {
                match action {
                    ConflictAction::KeepLocal => {
                        vela_desktop_core::commands::vault::update_item(&app_state, conflict.local_version.clone())
                            .await?;
                        vela_desktop_core::sync::resolve_conflict(&app_state, conflict.item_id.clone(), true).await
                    }
                    ConflictAction::KeepServer => {
                        vela_desktop_core::commands::vault::update_item(&app_state, conflict.server_version.clone())
                            .await?;
                        vela_desktop_core::sync::resolve_conflict(&app_state, conflict.item_id.clone(), false).await
                    }
                    ConflictAction::KeepBoth => {
                        let duplicated = conflict
                            .local_version
                            .with_id(String::new())
                            .with_name(format!("{} (conflict copy)", conflict.local_version.name()));
                        vela_desktop_core::commands::vault::add_item(&app_state, duplicated).await?;
                        vela_desktop_core::sync::resolve_conflict(&app_state, conflict.item_id.clone(), true).await
                    }
                }
            })
            .await
            .map_err(|e| format!("Task failed: {e}"))
            .and_then(|r| r);

            this.update(cx, |this, cx| {
                this.resolving = false;
                match result {
                    Ok(()) => {
                        if let Some(modal) = &mut this.conflict_modal {
                            modal.conflicts.retain(|c| c.item_id != item_id);
                            if modal.conflicts.is_empty() {
                                this.conflict_modal = None;
                            } else if modal.index >= modal.conflicts.len() {
                                modal.index = modal.conflicts.len() - 1;
                            }
                        }
                        // Reflect the resolution in the "N unresolved
                        // conflicts" summary immediately, without waiting
                        // for the next sync.
                        if let Some(status) = &mut this.sync_status {
                            status.conflicts.retain(|c| c.item_id != item_id);
                        }
                    }
                    Err(e) => this.resolve_error = Some(format!("Failed to resolve conflict: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Port of `SettingsScreen.tsx`'s export handler: `@tauri-apps/plugin-
    /// dialog`'s native save picker + `save_vault_export_file` become one
    /// native `rfd` save dialog (no separate renderer process, so no IPC
    /// round-trip needed to hand the path back).
    fn export_vault(&mut self, cx: &mut Context<Self>) {
        self.exporting = true;
        self.export_import_status = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result: Result<Option<()>, String> = async {
                let json = cx
                    .background_spawn_guarded("export vault", {
                        let app_state = app_state.clone();
                        async move { vela_desktop_core::commands::vault::export_vault_bitwarden_json(&app_state) }
                    })
                    .await
                    .unwrap_or_else(|| Err("Export failed unexpectedly".to_string()))?;

                let default_name = format!("vela-export-{}.json", chrono::Local::now().format("%Y-%m-%d"));
                let file = rfd::AsyncFileDialog::new()
                    .set_file_name(&default_name)
                    .add_filter("JSON", &["json"])
                    .save_file()
                    .await;
                let Some(file) = file else { return Ok(None) };
                file.write(json.as_bytes()).await.map_err(|e| format!("Failed to write export file: {e}"))?;
                Ok(Some(()))
            }
            .await;

            this.update(cx, |this, cx| {
                this.exporting = false;
                this.export_import_status = match result {
                    Ok(Some(())) => Some("Vault exported".into()),
                    Ok(None) => None, // user cancelled the save dialog
                    Err(e) => Some(format!("Export failed: {e}").into()),
                };
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Port of `SettingsScreen.tsx`'s import handler: the browser `<input
    /// type="file">` + `FileReader` dance becomes one native `rfd` open
    /// dialog + a direct `std::fs::read`.
    fn import_vault(&mut self, cx: &mut Context<Self>) {
        self.importing = true;
        self.export_import_status = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result: Result<Option<vela_desktop_core::commands::vault::ImportResult>, String> = async {
                let file = rfd::AsyncFileDialog::new().add_filter("JSON", &["json"]).pick_file().await;
                let Some(file) = file else { return Ok(None) };
                let data = file.read().await;
                let text = String::from_utf8(data).map_err(|e| format!("Import file is not valid UTF-8: {e}"))?;

                let imported = cx
                    .background_spawn_guarded("import vault", {
                        let app_state = app_state.clone();
                        async move { vela_desktop_core::commands::vault::import_vault_bitwarden_json(&app_state, &text) }
                    })
                    .await
                    .unwrap_or_else(|| Err("Import failed unexpectedly".to_string()))?;
                Ok(Some(imported))
            }
            .await;

            this.update(cx, |this, cx| {
                this.importing = false;
                this.export_import_status = match result {
                    Ok(Some(r)) => Some(format!("Imported {} of {} items", r.added, r.total).into()),
                    Ok(None) => None, // user cancelled the open dialog
                    Err(e) => Some(format!("Import failed: {e}").into()),
                };
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn save(&mut self, new_settings: Settings, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("save settings", {
                    let app_state = app_state.clone();
                    let settings = new_settings.clone();
                    async move { update_settings(&app_state, settings) }
                })
                .await
                .unwrap_or_else(|| Err("Saving settings failed unexpectedly".to_string()));
            this.update(cx, |this, cx| match result {
                Ok(()) => {
                    let theme_changed = this
                        .settings
                        .as_ref()
                        .map(|s| s.theme != new_settings.theme)
                        .unwrap_or(true);
                    this.settings = Some(new_settings.clone());
                    this.error = None;
                    // Keep the clipboard helper's cached delay in step with
                    // what was just persisted, so a changed
                    // "clear clipboard after" takes effect on the very next
                    // copy instead of only after a restart.
                    crate::clipboard::set_clear_seconds(cx, new_settings.clipboard_clear_seconds);
                    if theme_changed {
                        cx.emit(SettingsScreenEvent::ThemeChanged(ThemeId::from_setting(&new_settings.theme)));
                    }
                    // Every settings change goes through this one function
                    // in the original too (`handleUpdateSettings`), which
                    // toasts "Settings saved" on every single successful
                    // save, not just from one dedicated Save button.
                    crate::toast::show(cx, "Settings saved", crate::toast::ToastKind::Success);
                    cx.notify();
                }
                Err(e) => {
                    crate::toast::show(cx, format!("Failed to save settings: {e}"), crate::toast::ToastKind::Error);
                    this.error = Some(e.into());
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    fn sign_out(&mut self, cx: &mut Context<Self>) {
        vela_desktop_core::commands::session::lock_session(&self.app_state);
        crate::toast::show(cx, "Signed out", crate::toast::ToastKind::Info);
        cx.emit(SettingsScreenEvent::SignedOut);
    }

    fn copy_user_id(&self, cx: &mut Context<Self>) {
        if let Some(settings) = &self.settings {
            crate::clipboard::copy(cx, "user ID", &settings.user_id);
        }
    }

    fn delete_vault(&mut self, cx: &mut Context<Self>) {
        self.deleting = true;
        self.delete_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // `reset_vault` may perform a real server auth challenge (when
            // unlocked with a server configured, which is always true here
            // since Settings is only reachable post-unlock) — must run via
            // gpui_tokio's bridge onto the actual tokio runtime, not
            // `cx.background_spawn` (a separate thread pool that never
            // entered that runtime and panics on real reactor I/O).
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::session::reset_vault(
                    &app_state,
                    Some("DELETE".to_string()),
                    None,
                )
                .await
            })
            .await;
            this.update(cx, |this, cx| {
                this.deleting = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_delete_modal = false;
                        cx.emit(SettingsScreenEvent::VaultDeleted);
                    }
                    Ok(Err(e)) => this.delete_error = Some(format!("Failed to delete vault: {e}").into()),
                    Err(e) => this.delete_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

impl Render for SettingsScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);

        let Some(settings) = self.settings.clone() else {
            return div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .bg(palette.surface)
                .child(icon("progress_activity", px(36.), palette.primary).opacity(animation::pulse_alpha(1.0)))
                .into_any_element();
        };

        // The delete-vault modal must NOT be a child of the scrollable div
        // below — its `.absolute().inset_0()` backdrop would otherwise
        // resolve against the SCROLLABLE CONTENT's bounds (taller than the
        // real viewport with all sections expanded) instead of the true
        // window, letting clicks/scroll-wheel input reach the settings list
        // right through the "backdrop". Keeping the modal as a sibling of
        // this OUTER (non-scrolling) container fixes that.
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .id("settings-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .bg(palette.surface)
                    .font_family(fonts::LABEL)
                    .p_8()
                    .child(
                        div()
                            .font_family(fonts::HEADLINE)
                            .font_weight(gpui::FontWeight::BOLD)
                    .text_3xl()
                    .text_color(palette.on_surface)
                    .mb_8()
                    .child("Settings"),
            )
            .child(
                div()
                    .max_w(px(720.))
                    .flex()
                    .flex_col()
                    .gap_8()
                    .child(appearance_section(&palette, &settings, cx))
                    .child(security_section(&palette, &settings, self, window, cx))
                    .child(recovery_section(&palette, self, window, cx))
                    .child(sync_section(&palette, &settings, self, window, cx))
                    .child(import_export_section(&palette, self, window, cx))
                    .child(extension_section(&palette, &settings, window, cx))
                    .child(account_section(&palette, &settings, window, cx)),
            )
                    .when_some(self.error.clone(), |el, error| {
                        el.child(div().text_sm().text_color(palette.error).child(error))
                    }),
            )
            .when(self.show_delete_modal, |el| el.child(delete_modal(&palette, self, window, cx)))
            .when(self.conflict_modal.is_some(), |el| el.child(conflict_resolution_modal(&palette, self, window, cx)))
            .when(self.show_security_key_modal, |el| el.child(security_key_modal(&palette, self, window, cx)))
            .into_any_element()
    }
}

fn section_label(palette: &Palette, label: &'static str) -> impl IntoElement {
    fonts::tracked_text(label, px(12.), 0.1)
        .font_family(fonts::LABEL)
        .text_xs()
        .text_color(palette.outline)
        .mb_4()
}

fn card(palette: &Palette) -> gpui::Div {
    div().bg(palette.surface_container).rounded_xl().p_6().flex().flex_col().gap_6()
}

fn field_label(palette: &Palette, title: &'static str, subtitle: &'static str) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .child(
            div()
                .font_family(fonts::BODY)
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(palette.on_surface)
                .child(title),
        )
        // An empty subtitle still rendered a blank (but height-occupying)
        // second line, making the whole label taller than just the title —
        // which threw off vertical centering for anything placed next to it
        // (e.g. the Browser Extension status dot). Skip the row entirely
        // when there's no subtitle instead of rendering it blank.
        .when(!subtitle.is_empty(), |el| {
            el.child(
                div()
                    .text_sm()
                    .text_color(palette.on_surface_variant)
                    .child(subtitle),
            )
        })
}

fn switch(palette: &Palette, checked: bool) -> impl IntoElement {
    div()
        .w(px(48.))
        .h(px(28.))
        .rounded_full()
        .bg(if checked { palette.primary } else { palette.surface_container_highest })
        .flex()
        .items_center()
        .px(px(2.))
        .when(checked, |el| el.justify_end())
        .when(!checked, |el| el.justify_start())
        .child(div().w(px(20.)).h(px(20.)).rounded_full().bg(gpui::rgb(0xffffff)))
}

fn action_button(
    palette: &Palette,
    id: &'static str,
    label: &'static str,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> gpui::Stateful<gpui::Div> {
    let hover_t = crate::animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = crate::animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);
    div()
        .id(id)
        .px_4()
        .py_2()
        .rounded_lg()
        .bg(bg)
        .text_color(palette.on_surface)
        .cursor_pointer()
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .child(label)
}

fn appearance_section(
    palette: &Palette,
    settings: &Settings,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let current = ThemeId::from_setting(&settings.theme);
    // A manual 2-column grid (two explicit rows) rather than `flex_wrap` —
    // gpui's flex-wrap container didn't reserve height for the wrapped
    // second row, so it overlapped the section below it. Fixed row-based
    // layout sidesteps that entirely.
    div()
        .child(section_label(palette, "Appearance"))
        .child(
            card(palette)
                .child(field_label(palette, "Theme", "Choose how VELA looks on this device"))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .children(ThemeId::ALL.chunks(2).map(|row| {
                            div()
                                .flex()
                                .gap_3()
                                .children(row.iter().map(|&theme_id| {
                                    theme_card(palette, settings, theme_id, current, cx)
                                }))
                        })),
                ),
        )
}

fn theme_card(
    palette: &Palette,
    settings: &Settings,
    theme_id: ThemeId,
    current: ThemeId,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let selected = theme_id == current;
    let swatch_palette = theme_id.palette();
    let mut new_settings = settings.clone();
    new_settings.theme = theme_id.to_setting();
    div()
        .id(theme_id.label())
        .flex_1()
        .p_3()
        .rounded_xl()
        .cursor_pointer()
        .bg(if selected {
            gpui::Hsla { a: 0.05, ..palette.primary }
        } else {
            palette.surface_container_low
        })
        .border_1()
        .border_color(if selected {
            palette.primary
        } else {
            gpui::Hsla { a: 0.2, ..palette.outline_variant }
        })
        .flex()
        .flex_col()
        .gap_3()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .gap(px(6.))
                        .child(swatch(swatch_palette.surface))
                        .child(swatch(swatch_palette.surface_container))
                        .child(swatch(swatch_palette.primary))
                        .child(swatch(swatch_palette.accent_violet)),
                )
                .when(selected, |el| el.child(icon("check_circle", px(18.), palette.primary))),
        )
        .child(
            div()
                .font_family(fonts::BODY)
                .text_sm()
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(palette.on_surface)
                .child(theme_id.label()),
        )
        .child(
            div()
                .text_xs()
                .text_color(palette.on_surface_variant)
                .child(theme_id.description()),
        )
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
            this.save(new_settings.clone(), cx);
        }))
}

fn swatch(color: gpui::Hsla) -> impl IntoElement {
    div().w(px(18.)).h(px(18.)).rounded_md().bg(color)
}

const AUTO_LOCK_OPTIONS: &[(u32, &str)] = &[(1, "1 min"), (5, "5 min"), (15, "15 min"), (30, "30 min"), (60, "1 hr")];
const CLIPBOARD_OPTIONS: &[(u32, &str)] = &[(15, "15 sec"), (30, "30 sec"), (60, "1 min"), (120, "2 min")];
const SYNC_INTERVAL_OPTIONS: &[(u32, &str)] = &[(1, "1 min"), (5, "5 min"), (15, "15 min"), (30, "30 min")];

fn pill_options(
    palette: &Palette,
    options: &'static [(u32, &'static str)],
    current: u32,
    on_pick: impl Fn(&mut SettingsScreen, u32, &mut Context<SettingsScreen>) + Copy + 'static,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    div()
        .flex()
        .flex_wrap()
        .gap_2()
        .children(options.iter().map(|&(value, label)| {
            let selected = value == current;
            div()
                .id(SharedString::from(format!("pill-{label}-{value}")))
                .px_3()
                .py_2()
                .rounded_lg()
                .text_sm()
                .cursor_pointer()
                .bg(if selected { palette.primary } else { palette.surface_container_highest })
                .text_color(if selected { palette.on_primary } else { palette.on_surface })
                .child(label)
                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                    on_pick(this, value, cx);
                }))
        }))
}

fn security_section(
    palette: &Palette,
    settings: &Settings,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let auto_lock = settings.auto_lock_minutes;
    let clipboard = settings.clipboard_clear_seconds;
    let require_biometric = settings.require_biometric_on_reveal;
    let editing_shortcut = screen.editing_shortcut;
    let shortcut = settings.quick_search_shortcut.clone();

    div()
        .child(section_label(palette, "Security"))
        .child(
            card(palette)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(field_label(palette, "Auto-lock after idle", "Automatically lock when inactive"))
                        .child(pill_options(palette, AUTO_LOCK_OPTIONS, auto_lock, |this, value, cx| {
                            if let Some(settings) = this.settings.clone() {
                                let mut updated = settings;
                                updated.auto_lock_minutes = value;
                                this.save(updated, cx);
                            }
                        }, cx)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(field_label(palette, "Clipboard clear delay", "Time before copied data is cleared"))
                        .child(pill_options(palette, CLIPBOARD_OPTIONS, clipboard, |this, value, cx| {
                            if let Some(settings) = this.settings.clone() {
                                let mut updated = settings;
                                updated.clipboard_clear_seconds = value;
                                this.save(updated, cx);
                            }
                        }, cx)),
                )
                .child(
                    div()
                        .id("toggle-require-biometric")
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .cursor_pointer()
                        .child(field_label(palette, "Require biometrics on reveal", "Authenticate before showing passwords"))
                        .child(switch(palette, require_biometric))
                        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                            if let Some(settings) = this.settings.clone() {
                                let mut updated = settings;
                                updated.require_biometric_on_reveal = !updated.require_biometric_on_reveal;
                                this.save(updated, cx);
                            }
                        })),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(field_label(palette, "Quick search shortcut", "Global shortcut for opening quick search"))
                                .when(!editing_shortcut, |el| {
                                    el.child(action_button(palette, "edit-shortcut", "Change", window, cx).on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(move |this, _, _, cx| {
                                            this.shortcut_state.update(cx, |state, cx| state.emplace(&shortcut, cx));
                                            this.editing_shortcut = true;
                                            cx.notify();
                                        }),
                                    ))
                                }),
                        )
                        .child(if editing_shortcut {
                            div()
                                .flex()
                                .gap_2()
                                // Enter saves the edited shortcut, same as the
                                // Save button beside it.
                                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                                    let draft = this.shortcut_state.read(cx).as_str().trim().to_string();
                                    if let Some(settings) = this.settings.clone() {
                                        let mut updated = settings;
                                        updated.quick_search_shortcut = draft;
                                        this.save(updated, cx);
                                    }
                                    this.editing_shortcut = false;
                                    cx.notify();
                                }))
                                .child(
                                    text_input("shortcut-input")
                                        .state(screen.shortcut_state.downgrade())
                                        .placeholder("Ctrl+Alt+V")
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
                                )
                                .child(action_button(palette, "save-shortcut", "Save", window, cx).on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        let draft = this.shortcut_state.read(cx).as_str().trim().to_string();
                                        if let Some(settings) = this.settings.clone() {
                                            let mut updated = settings;
                                            updated.quick_search_shortcut = draft;
                                            this.save(updated, cx);
                                        }
                                        this.editing_shortcut = false;
                                        cx.notify();
                                    }),
                                ))
                                .child(action_button(palette, "cancel-shortcut", "Cancel", window, cx).on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        this.editing_shortcut = false;
                                        cx.notify();
                                    }),
                                ))
                                .into_any_element()
                        } else {
                            div()
                                .font_family(fonts::MONO)
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(settings.quick_search_shortcut.clone())
                                .into_any_element()
                        }),
                ),
        )
}

/// Port of `RecoverySettings.tsx`'s method list. Security key is real
/// (native CTAP2 ceremony, see `vela_desktop_core::webauthn`); cloud backup
/// (needs rclone remote-picker wiring) and trusted contact (needs the
/// `TrustedContactRecovery` flow) stay honest read-only status rows for
/// now — deliberately out of scope for this pass, matching this codebase's
/// per-feature (not per-screen) stubbing convention.
fn recovery_section(
    palette: &Palette,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let status = screen.recovery_status.clone();
    let cloud_backup_done = status.as_ref().map(|s| s.cloud_backup_delivered).unwrap_or(false);
    let security_key_done = status.as_ref().map(|s| s.security_key_delivered).unwrap_or(false);
    let trusted_contact_done = status.as_ref().map(|s| s.trusted_contact_acknowledged).unwrap_or(false);
    let completed_count =
        [cloud_backup_done, security_key_done, trusted_contact_done].iter().filter(|d| **d).count();

    div()
        .child(section_label(palette, "Recovery"))
        .child(
            card(palette)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(icon(
                            if completed_count >= 2 { "verified_user" } else { "gpp_maybe" },
                            px(22.),
                            if completed_count >= 2 { palette.primary } else { gpui::rgb(0xf59e0b).into() },
                        ))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    div()
                                        .font_family(fonts::BODY)
                                        .font_weight(gpui::FontWeight::MEDIUM)
                                        .text_color(palette.on_surface)
                                        .child(if completed_count >= 2 {
                                            "Recovery is configured"
                                        } else {
                                            "Recovery not configured"
                                        }),
                                )
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(palette.on_surface_variant)
                                        .child(if completed_count >= 2 {
                                            format!("{completed_count} of 3 methods active — any 2 can restore your vault")
                                        } else {
                                            "Set up at least 2 methods to restore your vault if all devices are lost".to_string()
                                        }),
                                ),
                        ),
                )
                .child(recovery_method_row(
                    palette,
                    "cloud_upload",
                    "Cloud backup",
                    cloud_backup_done,
                    "Upload a recovery share via rclone",
                    "Not ported yet — manage from the web or mobile app for now.",
                ))
                .child({
                    let mut row = recovery_method_row(
                        palette,
                        "key",
                        "Security key",
                        security_key_done,
                        "Register a passkey to gate the server share",
                        "",
                    )
                    .into_any_element();
                    if !security_key_done {
                        row = div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(row)
                            .child(
                                div().flex().justify_end().child(
                                    action_button(palette, "enable-security-key", "Enable", window, cx).on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(|this, _, _, cx| this.open_security_key_modal(cx)),
                                    ),
                                ),
                            )
                            .into_any_element();
                    }
                    row
                })
                .child(recovery_method_row(
                    palette,
                    "person_add",
                    "Trusted contact",
                    trusted_contact_done,
                    "Give a share to someone you trust",
                    "Not ported yet — manage from the web or mobile app for now.",
                )),
        )
}

fn recovery_method_row(
    palette: &Palette,
    icon_name: &'static str,
    title: &'static str,
    done: bool,
    todo_label: &'static str,
    not_ported_note: &'static str,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(icon(
                    if done { "check_circle" } else { icon_name },
                    px(18.),
                    if done { palette.primary } else { palette.on_surface_variant },
                ))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .child(
                            div()
                                .font_family(fonts::BODY)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(palette.on_surface)
                                .child(title),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(if done { "Delivered".to_string() } else { todo_label.to_string() }),
                        ),
                ),
        )
        .when(!done && !not_ported_note.is_empty(), |el| {
            el.child(div().pl(px(30.)).text_xs().text_color(palette.outline).child(not_ported_note))
        })
}

fn security_key_modal(
    palette: &Palette,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let registering = screen.registering_security_key;

    let cancel_hover = animation::hover_transition("security-key-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    let confirm_hover = animation::hover_transition("security-key-confirm", window, cx);
    let confirm_t = *confirm_hover.evaluate(window, cx);
    let confirm_bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, confirm_t);

    div()
        .id("security-key-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_security_key_modal(cx)))
        .child(
            div()
                .id("security-key-modal-body")
                .map(|el| crate::keyboard::trap_tab(el, "security-key-modal-trap", window, cx))
                .w(px(420.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                    if !this.registering_security_key {
                        this.register_security_key(cx);
                    }
                }))
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_xl()
                        .text_color(palette.on_surface)
                        .child("Enable security key"),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(
                            "Insert your FIDO2 security key, enter its PIN, then continue. You'll be \
                             prompted to touch the key to complete registration.",
                        ),
                )
                .child(fonts::tracked_text("SECURITY KEY PIN", px(10.), 0.15).text_xs().text_color(palette.outline))
                .child(
                    text_input("security-key-pin-input")
                        .state(screen.security_key_pin_state.downgrade())
                        .placeholder("PIN")
                        .caret_blink_interval_500ms()
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
                )
                .when(registering, |el| {
                    el.child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_sm()
                            .text_color(palette.primary)
                            .child(icon("progress_activity", px(14.), palette.primary).opacity(animation::pulse_alpha(1.0)))
                            .child("Waiting for the key to be touched…"),
                    )
                })
                .when_some(screen.security_key_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .id("security-key-cancel")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(cancel_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_hover(move |is_hovered, _, cx| {
                                    cancel_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.close_security_key_modal(cx);
                                })),
                        )
                        .child(
                            div()
                                .id("security-key-confirm")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(confirm_bg)
                                .text_color(palette.on_primary)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(!registering, |el| el.cursor_pointer())
                                .opacity(if registering { 0.6 } else { 1.0 })
                                .child(if registering { "Registering…" } else { "Continue" })
                                .on_hover(move |is_hovered, _, cx| {
                                    confirm_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .when(!registering, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.register_security_key(cx);
                                    }))
                                }),
                        ),
                ),
        )
}

fn sync_section(
    palette: &Palette,
    settings: &Settings,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let editing_server_url = screen.editing_server_url;
    let server_url = settings.server_url.clone();
    let sync_on_startup = settings.sync_on_startup;
    let background_sync = settings.background_sync_minutes;
    let syncing = screen.syncing;
    let last_synced = screen
        .sync_status
        .as_ref()
        .and_then(|s| s.last_synced)
        .map(|dt| dt.with_timezone(&chrono::Local).format("%b %-d, %Y %-I:%M %p").to_string())
        .unwrap_or_else(|| "Never".to_string());
    let conflict_count = screen.sync_status.as_ref().map(|s| s.conflicts.len()).unwrap_or(0);
    let sync_error = screen.sync_error.clone();

    div()
        .child(section_label(palette, "Sync"))
        .child(
            card(palette)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(field_label(palette, "Server URL", "VELA server address for sync and auth"))
                                .when(!editing_server_url, |el| {
                                    el.child(action_button(palette, "edit-server-url", "Edit", window, cx).on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(move |this, _, _, cx| {
                                            this.server_url_state.update(cx, |state, cx| state.emplace(&server_url, cx));
                                            this.editing_server_url = true;
                                            cx.notify();
                                        }),
                                    ))
                                }),
                        )
                        .child(if editing_server_url {
                            div()
                                .flex()
                                .gap_2()
                                // Enter saves the edited URL, same as the Save
                                // button beside it.
                                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                                    let draft = this.server_url_state.read(cx).as_str().trim().to_string();
                                    if let Some(settings) = this.settings.clone() {
                                        let mut updated = settings;
                                        updated.server_url = draft;
                                        this.save(updated, cx);
                                    }
                                    this.editing_server_url = false;
                                    cx.notify();
                                }))
                                .child(
                                    text_input("server-url-input")
                                        .state(screen.server_url_state.downgrade())
                                        .placeholder("http://192.168.1.34:8443")
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
                                )
                                .child(action_button(palette, "save-server-url", "Save", window, cx).on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        let draft = this.server_url_state.read(cx).as_str().trim().to_string();
                                        if let Some(settings) = this.settings.clone() {
                                            let mut updated = settings;
                                            updated.server_url = draft;
                                            this.save(updated, cx);
                                        }
                                        this.editing_server_url = false;
                                        cx.notify();
                                    }),
                                ))
                                .child(action_button(palette, "cancel-server-url", "Cancel", window, cx).on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, _, cx| {
                                        this.editing_server_url = false;
                                        cx.notify();
                                    }),
                                ))
                                .into_any_element()
                        } else {
                            let display = if settings.server_url.is_empty() {
                                "Not configured".to_string()
                            } else {
                                settings.server_url.clone()
                            };
                            div()
                                .font_family(fonts::MONO)
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(display)
                                .into_any_element()
                        }),
                )
                .child(
                    div()
                        .id("toggle-sync-startup")
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .cursor_pointer()
                        .child(field_label(palette, "Sync on startup", "Automatically sync when app opens"))
                        .child(switch(palette, sync_on_startup))
                        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                            if let Some(settings) = this.settings.clone() {
                                let mut updated = settings;
                                updated.sync_on_startup = !updated.sync_on_startup;
                                this.save(updated, cx);
                            }
                        })),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(field_label(palette, "Background sync interval", "How often to sync in the background"))
                        .child(pill_options(palette, SYNC_INTERVAL_OPTIONS, background_sync, |this, value, cx| {
                            if let Some(settings) = this.settings.clone() {
                                let mut updated = settings;
                                updated.background_sync_minutes = value;
                                this.save(updated, cx);
                            }
                        }, cx)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    div()
                                        .font_family(fonts::BODY)
                                        .font_weight(gpui::FontWeight::MEDIUM)
                                        .text_color(palette.on_surface)
                                        .child("Last synced"),
                                )
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(palette.on_surface_variant)
                                        .child(last_synced),
                                ),
                        )
                        .child(
                            action_button(
                                palette,
                                "sync-now",
                                if syncing { "Syncing…" } else { "Sync now" },
                                window,
                                cx,
                            )
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _, _, cx| this.sync_now(cx)),
                            ),
                        ),
                )
                .when_some(sync_error, |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .when(conflict_count > 0, |el| {
                    el.child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_4()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(palette.error)
                                    .child(format!(
                                        "{conflict_count} unresolved conflict{}",
                                        if conflict_count != 1 { "s" } else { "" }
                                    )),
                            )
                            .child(action_button(palette, "resolve-conflicts", "Resolve conflicts", window, cx).on_mouse_down(
                                MouseButton::Left,
                                cx.listener(|this, _, _, cx| this.open_conflict_modal(cx)),
                            )),
                    )
                }),
        )
}

fn import_export_section(
    palette: &Palette,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let exporting = screen.exporting;
    let importing = screen.importing;
    let status = screen.export_import_status.clone();

    div()
        .child(section_label(palette, "Import / Export"))
        .child(
            card(palette)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(field_label(palette, "Export vault", "Download as Bitwarden-compatible JSON"))
                        .child(
                            action_button(palette, "export-vault", if exporting { "Exporting…" } else { "Export" }, window, cx)
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.export_vault(cx))),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(field_label(palette, "Import vault", "Import from Bitwarden-compatible JSON"))
                        .child(
                            action_button(palette, "import-vault", if importing { "Importing…" } else { "Import" }, window, cx)
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.import_vault(cx))),
                        ),
                )
                .when_some(status, |el, status| {
                    el.child(div().text_sm().text_color(palette.on_surface_variant).child(status))
                }),
        )
}

fn extension_section(palette: &Palette, settings: &Settings, window: &mut Window, cx: &mut Context<SettingsScreen>) -> impl IntoElement {
    let connected = settings.extension_connected;
    div()
        .child(section_label(palette, "Browser Extension"))
        .child(
            card(palette)
                .flex_row()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .w(px(10.))
                                .h(px(10.))
                                .rounded_full()
                                .bg(if connected { palette.primary } else { gpui::rgb(0xf59e0b).into() }),
                        )
                        .child(field_label(
                            palette,
                            if connected { "Extension connected" } else { "Extension not found" },
                            "",
                        )),
                )
                .child(action_button(palette, "manage-extension", "Manage extension", window, cx)),
        )
}

fn account_section(
    palette: &Palette,
    settings: &Settings,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let user_id = settings.user_id.clone();
    div()
        .child(section_label(palette, "Account"))
        .child(
            card(palette)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    div()
                                        .font_family(fonts::BODY)
                                        .font_weight(gpui::FontWeight::MEDIUM)
                                        .text_color(palette.on_surface)
                                        .child("User ID"),
                                )
                                .child(
                                    div()
                                        .font_family(fonts::MONO)
                                        .text_xs()
                                        .text_color(palette.on_surface_variant)
                                        .child(user_id),
                                ),
                        )
                        .child(action_button(palette, "copy-user-id", "Copy", window, cx).on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|this, _, _, cx| this.copy_user_id(cx)),
                        )),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .id("sign-out")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Sign out and lock")
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.sign_out(cx);
                                })),
                        )
                        .child(
                            div()
                                .id("delete-vault")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(gpui::Hsla { a: 0.1, ..palette.error })
                                .text_color(palette.error)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Delete vault")
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.show_delete_modal = true;
                                    cx.notify();
                                })),
                        ),
                ),
        )
}

fn delete_modal(
    palette: &Palette,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let confirm_text = screen.delete_confirm_state.read(cx).as_str().to_string();
    let can_delete = confirm_text == "DELETE";

    div()
        .id("delete-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            this.show_delete_modal = false;
            cx.notify();
        }))
        .child(
            div()
                .id("delete-modal-body")
                .map(|el| crate::keyboard::trap_tab(el, "delete-modal-trap", window, cx))
                .w(px(420.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.3, ..palette.error })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                // Enter confirms, but only once DELETE has actually been
                // typed — the same guard the button carries.
                .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _window, cx| {
                    if !this.deleting && this.delete_confirm_state.read(cx).as_str() == "DELETE" {
                        this.delete_vault(cx);
                    }
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(icon("warning", px(24.), palette.error))
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Delete vault?"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("This action is irreversible. All your data will be permanently deleted. Type DELETE to confirm."),
                )
                .when_some(screen.delete_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    text_input("delete-confirm-input")
                        .state(screen.delete_confirm_state.downgrade())
                        .placeholder("Type DELETE")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_xl()
                        .p_3()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .id("cancel-delete")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(palette.surface_container_highest)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.show_delete_modal = false;
                                    cx.notify();
                                })),
                        )
                        .child(
                            div()
                                .id("confirm-delete")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(if can_delete { palette.error } else { gpui::Hsla { a: 0.4, ..palette.error } })
                                .text_color(gpui::white())
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(can_delete, |el| el.cursor_pointer())
                                .child(if screen.deleting { "Deleting…" } else { "Delete forever" })
                                .when(can_delete, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.delete_vault(cx);
                                    }))
                                }),
                        ),
                ),
        )
}

/// Matches `ConflictResolution.tsx`'s `getChangedFields` — a coarse,
/// type-aware diff naming which fields differ between the local and server
/// versions of a conflicted item. Sensitive values (password/CVV/PIN/SSN/
/// note content) are masked as "[changed]" rather than displayed, same as
/// the original; non-sensitive identifying fields (username/URL/title/
/// cardholder name/email) are shown plainly.
fn conflict_changed_fields(local: &VaultItem, server: &VaultItem) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    match (local, server) {
        (
            VaultItem::Login { url: lu, username: luser, pass: lp, totp: ltotp, .. },
            VaultItem::Login { url: su, username: suser, pass: sp, totp: stotp, .. },
        ) => {
            if luser != suser {
                out.push(("Username", luser.clone(), suser.clone()));
            }
            if lu != su {
                out.push(("URL", lu.clone(), su.clone()));
            }
            if lp != sp {
                out.push(("Password", "[changed]".to_string(), "[changed]".to_string()));
            }
            if ltotp != stotp {
                out.push(("TOTP", "[changed]".to_string(), "[changed]".to_string()));
            }
        }
        (
            VaultItem::CreditCard { number: ln, exp: le, cvv: lc, pin: lp, cardholder_name: lcn, .. },
            VaultItem::CreditCard { number: sn, exp: se, cvv: sc, pin: sp, cardholder_name: scn, .. },
        ) => {
            if lcn != scn {
                out.push((
                    "Cardholder name",
                    lcn.clone().unwrap_or_default(),
                    scn.clone().unwrap_or_default(),
                ));
            }
            if ln != sn {
                out.push(("Card number", "[changed]".to_string(), "[changed]".to_string()));
            }
            if le != se {
                out.push(("Expiration", le.clone(), se.clone()));
            }
            if lc != sc {
                out.push(("CVV", "[changed]".to_string(), "[changed]".to_string()));
            }
            if lp != sp {
                out.push(("PIN", "[changed]".to_string(), "[changed]".to_string()));
            }
        }
        (VaultItem::SecureNote { title: lt, content: lc, .. }, VaultItem::SecureNote { title: st, content: sc, .. }) => {
            if lt != st {
                out.push(("Title", lt.clone(), st.clone()));
            }
            if lc != sc {
                out.push(("Note content", "[changed]".to_string(), "[changed]".to_string()));
            }
        }
        (
            VaultItem::Identity { first_name: lf, last_name: ll, ssn: ls, .. },
            VaultItem::Identity { first_name: sf, last_name: sl, ssn: ss, .. },
        ) => {
            if lf != sf || ll != sl {
                out.push(("Name", format!("{lf} {ll}"), format!("{sf} {sl}")));
            }
            if ls != ss {
                out.push(("SSN", "[changed]".to_string(), "[changed]".to_string()));
            }
        }
        (VaultItem::BreachMonitor { email: le, .. }, VaultItem::BreachMonitor { email: se, .. }) => {
            if le != se {
                out.push(("Email", le.clone(), se.clone()));
            }
        }
        _ => {
            out.push(("Item type", format!("{:?}", local.item_type()), format!("{:?}", server.item_type())));
        }
    }
    out
}

/// The real conflict-resolution carousel — port of `ConflictResolution.tsx`.
/// Shown after `sync_now` (or the initial `get_sync_status` load) reports
/// unresolved conflicts; each conflict is resolved one at a time via the
/// three real actions (`resolve_conflict_action`), advancing to the next
/// automatically until none remain.
fn conflict_resolution_modal(
    palette: &Palette,
    screen: &SettingsScreen,
    window: &mut Window,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    let Some(modal) = &screen.conflict_modal else {
        return div().into_any_element();
    };
    let total = modal.conflicts.len();
    let index = modal.index.min(total.saturating_sub(1));
    let Some(conflict) = modal.conflicts.get(index).cloned() else {
        return div().into_any_element();
    };
    let changed = conflict_changed_fields(&conflict.local_version, &conflict.server_version);
    let resolving = screen.resolving;

    let local_updated = conflict.local_version.updated_at().with_timezone(&chrono::Local).format("%b %-d, %-I:%M %p").to_string();
    let server_updated = conflict.server_version.updated_at().with_timezone(&chrono::Local).format("%b %-d, %-I:%M %p").to_string();

    let side_card = |label: &'static str, updated: String, values: Box<dyn Fn(&(&'static str, String, String)) -> String>| {
        div()
            .flex_1()
            .p_6()
            .rounded_xl()
            .bg(palette.surface_container_high)
            .border_1()
            .border_color(gpui::Hsla { a: 0.05, ..palette.outline_variant })
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .font_family(fonts::HEADLINE)
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(palette.on_surface)
                            .child(label),
                    )
                    .child(div().text_xs().font_family(fonts::MONO).text_color(palette.on_surface_variant).child(updated)),
            )
            .children(changed.iter().map(move |field| {
                div()
                    .flex()
                    .flex_col()
                    .child(fonts::tracked_text(field.0, px(10.), 0.15).text_xs().text_color(gpui::rgb(0xf59e0b)))
                    .child(div().text_sm().text_color(palette.on_surface).child(values(field)))
            }))
    };

    div()
        .id("conflict-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_conflict_modal(cx)))
        .child(
            div()
                .id("conflict-modal-body")
                .max_w(px(760.))
                .max_h(px(640.))
                .id("conflict-modal-scroll")
                .overflow_y_scroll()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.3, h: 0.11, s: 0.9, l: 0.5 })
                .flex()
                .flex_col()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    div()
                        .p_6()
                        .border_b_1()
                        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .child(icon("warning", px(20.), gpui::rgb(0xf59e0b).into()))
                                .child(
                                    div()
                                        .font_family(fonts::HEADLINE)
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .text_2xl()
                                        .text_color(palette.on_surface)
                                        .child(format!("Sync Conflict — {}", conflict.local_version.name())),
                                ),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child("Choose which version to keep, or keep both."),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_family(fonts::LABEL)
                                .text_color(gpui::rgb(0xf59e0b))
                                .child(format!("{} of {total} conflict{}", index + 1, if total != 1 { "s" } else { "" })),
                        ),
                )
                .when_some(screen.resolve_error.clone(), |el, error| {
                    el.child(div().px_6().pt_4().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .p_6()
                        .flex()
                        .gap_6()
                        .child(side_card("This device", local_updated, Box::new(|f: &(&'static str, String, String)| f.1.clone())))
                        .child(side_card("Server version", server_updated, Box::new(|f: &(&'static str, String, String)| f.2.clone()))),
                )
                .child({
                    let keep_local_hover = animation::hover_transition("conflict-keep-local", window, cx);
                    let keep_local_t = *keep_local_hover.evaluate(window, cx);
                    let keep_local_bg =
                        animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, keep_local_t);

                    let keep_server_hover = animation::hover_transition("conflict-keep-server", window, cx);
                    let keep_server_t = *keep_server_hover.evaluate(window, cx);
                    let keep_server_bg =
                        animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, keep_server_t);

                    let keep_both_hover = animation::hover_transition("conflict-keep-both", window, cx);
                    let keep_both_t = *keep_both_hover.evaluate(window, cx);
                    let keep_both_bg =
                        animation::lerp_hsla(gpui::Hsla { a: 0.2, ..palette.primary }, gpui::Hsla { a: 0.3, ..palette.primary }, keep_both_t);

                    div()
                        .p_6()
                        .border_t_1()
                        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .id("conflict-keep-local")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(keep_local_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(!resolving, |el| el.cursor_pointer())
                                .opacity(if resolving { 0.6 } else { 1.0 })
                                .child("Keep this device")
                                .on_hover(move |is_hovered, _, cx| {
                                    keep_local_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .when(!resolving, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.resolve_conflict_action(ConflictAction::KeepLocal, cx);
                                    }))
                                }),
                        )
                        .child(
                            div()
                                .id("conflict-keep-server")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(keep_server_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(!resolving, |el| el.cursor_pointer())
                                .opacity(if resolving { 0.6 } else { 1.0 })
                                .child("Keep server")
                                .on_hover(move |is_hovered, _, cx| {
                                    keep_server_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .when(!resolving, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.resolve_conflict_action(ConflictAction::KeepServer, cx);
                                    }))
                                }),
                        )
                        .child(
                            div()
                                .id("conflict-keep-both")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(keep_both_bg)
                                .text_color(palette.primary)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(!resolving, |el| el.cursor_pointer())
                                .opacity(if resolving { 0.6 } else { 1.0 })
                                .child(if resolving { "Resolving…" } else { "Keep both" })
                                .on_hover(move |is_hovered, _, cx| {
                                    keep_both_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .when(!resolving, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.resolve_conflict_action(ConflictAction::KeepBoth, cx);
                                    }))
                                }),
                        )
                })
        )
        .into_any_element()
}
