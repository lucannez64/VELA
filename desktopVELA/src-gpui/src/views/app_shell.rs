//! Persistent post-unlock shell — port of `App.tsx`'s `<Sidebar/>` +
//! `<main>` layout. Owns navigation between Vault/ItemDetail/Settings and
//! (placeholders for) Devices/Sharing/Audit Log/Breach Monitor, which
//! haven't been ported yet. Replaces `RootView`'s previous direct
//! `VaultBrowser`/`ItemDetail` screen variants.

use std::sync::Arc;

use gpui::{div, prelude::*, px, Context, Entity, EventEmitter, IntoElement, MouseButton, Render, Subscription, Window};

use vela_desktop_core::recovery::RecoveryStatus;
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::fonts;
use crate::icon::icon;
use crate::sidebar::{NavView, Sidebar, SidebarEvent};
use crate::theme::{Palette, ThemeId};
use crate::views::audit_log_screen::AuditLogScreen;
use crate::views::breach_monitor_screen::BreachMonitorScreen;
use crate::views::devices_screen::DevicesScreen;
use crate::views::add_item_modal::{AddItemModal, AddItemModalEvent};
use crate::views::item_detail::{ItemDetail, ItemDetailEvent};
use crate::views::settings_screen::{SettingsScreen, SettingsScreenEvent};
use crate::views::sharing_screen::SharingScreen;
use crate::views::vault_browser::{VaultBrowser, VaultBrowserEvent};

pub enum AppShellEvent {
    ThemeChanged(ThemeId),
    Locked,
    /// The vault was actually, permanently deleted — go back to Welcome
    /// (first-launch), not BiometricGate.
    VaultDeleted,
}
impl EventEmitter<AppShellEvent> for AppShell {}

enum Content {
    Vault(Entity<VaultBrowser>),
    ItemDetail(Entity<ItemDetail>),
    Settings(Entity<SettingsScreen>),
    AuditLog(Entity<AuditLogScreen>),
    Sharing(Entity<SharingScreen>),
    Devices(Entity<DevicesScreen>),
    BreachMonitor(Entity<BreachMonitorScreen>),
    /// No remaining screens use this — kept for future nav entries.
    #[allow(dead_code)]
    Placeholder(&'static str),
}

pub struct AppShell {
    app_state: Arc<AppState>,
    sidebar: Entity<Sidebar>,
    nav: NavView,
    content: Content,
    /// A separate overlay from `VaultBrowser`'s own "Add Item" modal — this
    /// one hosts `AddItemModal` in *edit* mode, opened from `ItemDetail`'s
    /// Edit button regardless of which `Content` is currently showing, and
    /// renders on top of it.
    edit_modal: Option<Entity<AddItemModal>>,
    _edit_subscription: Option<Subscription>,
    _subscriptions: Vec<Subscription>,
    /// Auto-sync (startup + periodic) — cancelled when this shell is dropped
    /// on lock, so syncing stops exactly when the session does.
    _sync_scheduler: gpui::Task<()>,
    /// How many recovery methods are set up, polled periodically — the
    /// "keep asking" half of the recovery-deferral bargain. `None` while the
    /// vault is locked (the shell only exists unlocked anyway) or unknown.
    recovery_status: Option<RecoveryStatus>,
    /// The periodic recovery-reminder poll — cancelled on drop like the sync
    /// scheduler.
    _recovery_reminder: gpui::Task<()>,
}

impl AppShell {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let sidebar = cx.new(Sidebar::new);
        let sync_scheduler = crate::sync_scheduler::start(app_state.clone(), cx);
        let recovery_reminder = Self::start_recovery_reminder(app_state.clone(), cx);
        let mut this = Self {
            app_state,
            sidebar,
            nav: NavView::Vault,
            content: Content::Placeholder(""),
            edit_modal: None,
            _edit_subscription: None,
            _subscriptions: Vec::new(),
            _sync_scheduler: sync_scheduler,
            recovery_status: None,
            _recovery_reminder: recovery_reminder,
        };
        this.subscribe_sidebar(cx);
        this.show_vault(cx);
        this
    }

    fn show_edit_modal(&mut self, item: vela_desktop_core::vault::VaultItem, cx: &mut Context<Self>) {
        // The edit modal renders on top of ItemDetail; stop its TOTP loop so
        // it isn't re-rendering every second behind the form (the source of
        // the selection freeze/lag while editing a TOTP URL).
        self.set_detail_paused(true, cx);
        let modal = cx.new({
            let app_state = self.app_state.clone();
            move |cx| AddItemModal::new_edit(app_state, item, cx)
        });
        let subscription = cx.subscribe(&modal, |this, _modal, event, cx| match event {
            AddItemModalEvent::Close => {
                this.edit_modal = None;
                this._edit_subscription = None;
                // The item detail is still showing underneath — resume its
                // countdown (it re-derives from the clock, so any time spent
                // paused is caught up immediately).
                this.set_detail_paused(false, cx);
                cx.notify();
            }
            AddItemModalEvent::Created | AddItemModalEvent::Updated => {
                this.edit_modal = None;
                this._edit_subscription = None;
                // Go back to the vault list — matches the simpler of the
                // two reasonable choices (re-fetching ItemDetail in place
                // being the other), and guarantees the list reflects the
                // edit immediately. The old detail view (and its TOTP task)
                // is dropped with it.
                this.show_vault(cx);
                cx.notify();
            }
        });
        self.edit_modal = Some(modal);
        self._edit_subscription = Some(subscription);
        cx.notify();
    }

    /// Poll recovery setup status every few seconds, so the standing banner
    /// appears once recovery is due and disappears as soon as it is set up —
    /// no restart, no settings-change subscription.
    ///
    /// The "keep asking" half of the deferral: skipping is allowed, forgetting
    /// is not. See `desktopVELA/src/components/RecoveryReminder.tsx`.
    fn start_recovery_reminder(
        app_state: Arc<AppState>,
        cx: &mut Context<Self>,
    ) -> gpui::Task<()> {
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(15))
                    .await;
                let result = cx
                    .background_spawn_guarded("recovery reminder", {
                        let app_state = app_state.clone();
                        async move {
                            vela_desktop_core::recovery::get_recovery_setup_status(&app_state)
                        }
                    })
                    .await
                    .unwrap_or_else(|| Err("Recovery reminder check failed".to_string()));
                this.update(cx, |this, cx| {
                    this.recovery_status = result.ok();
                    cx.notify();
                })
                .ok();
            }
        })
    }

    /// Pause or resume the live TOTP refresh on the currently showing item
    /// detail view, if there is one.
    fn set_detail_paused(&self, paused: bool, cx: &mut Context<Self>) {
        if let Content::ItemDetail(detail) = &self.content {
            detail.update(cx, |detail, cx| detail.set_paused(paused, cx));
        }
    }

    fn subscribe_sidebar(&mut self, cx: &mut Context<Self>) {
        let sidebar = self.sidebar.clone();
        let subscription = cx.subscribe(&sidebar, |this, _sidebar, event, cx| match event {
            SidebarEvent::Navigate(view) => this.navigate(*view, cx),
            SidebarEvent::AddItem => this.add_item(cx),
            SidebarEvent::Lock => {
                vela_desktop_core::commands::session::lock_session(&this.app_state);
                // A copied secret must not outlive the unlocked session —
                // same reason the original calls `clearClipboard()` here.
                crate::clipboard::clear(cx);
                crate::toast::show(cx, "Session locked", crate::toast::ToastKind::Info);
                cx.emit(AppShellEvent::Locked);
            }
        });
        self._subscriptions.push(subscription);
    }

    fn navigate(&mut self, view: NavView, cx: &mut Context<Self>) {
        self.nav = view;
        match view {
            NavView::Vault => self.show_vault(cx),
            NavView::Settings => self.show_settings(cx),
            NavView::Devices => self.show_devices(cx),
            NavView::Sharing => self.show_sharing(cx),
            NavView::Audit => self.show_audit_log(cx),
            NavView::BreachMonitor => self.show_breach_monitor(cx),
        }
        cx.notify();
    }

    fn show_vault(&mut self, cx: &mut Context<Self>) {
        let browser = cx.new({
            let app_state = self.app_state.clone();
            move |cx| VaultBrowser::new(app_state, cx)
        });
        let subscription = cx.subscribe(&browser, |this, _browser, event, cx| match event {
            VaultBrowserEvent::ItemSelected(id) => this.show_item_detail(id.clone(), cx),
            VaultBrowserEvent::NavigateToBreachMonitor => {
                this.sidebar.update(cx, |sidebar, cx| sidebar.set_active(NavView::BreachMonitor, cx));
                this.show_breach_monitor(cx);
            }
        });
        self.content = Content::Vault(browser);
        self._subscriptions.push(subscription);
        cx.notify();
    }

    /// Jump straight to an item's detail view, used by the quick-search popup
    /// (`quick_search.rs`) — the equivalent of the Tauri build's `open-item`
    /// event, which `App.tsx` listens for and turns into `setSelectedItem`.
    pub fn open_item(&mut self, id: String, cx: &mut Context<Self>) {
        if self.nav != NavView::Vault {
            self.sidebar.update(cx, |sidebar, cx| sidebar.set_active(NavView::Vault, cx));
            self.nav = NavView::Vault;
        }
        self.show_item_detail(id, cx);
    }

    fn show_item_detail(&mut self, id: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let item = cx
                .background_spawn_guarded("open item", {
                    let app_state = app_state.clone();
                    async move { vela_desktop_core::commands::vault::get_item(&app_state, &id) }
                })
                .await
                .unwrap_or_else(|| Err("Opening the item failed unexpectedly".to_string()));
            match item {
                Ok(Some(item)) => {
                    this.update(cx, |this, cx| {
                        let detail = cx.new({
                            let app_state = app_state.clone();
                            move |cx| ItemDetail::new(app_state, item, cx)
                        });
                        let subscription =
                            cx.subscribe(&detail, |this, _detail, event, cx| match event {
                                ItemDetailEvent::Back => this.show_vault(cx),
                                ItemDetailEvent::Deleted => this.show_vault(cx),
                                ItemDetailEvent::EditRequested(item) => {
                                    this.show_edit_modal(item.clone(), cx);
                                }
                                ItemDetailEvent::ShareRequested(item_id) => {
                                    this.sidebar.update(cx, |sidebar, cx| {
                                        sidebar.set_active(NavView::Sharing, cx)
                                    });
                                    this.show_sharing_with_item(item_id.clone(), cx);
                                }
                            });
                        this.content = Content::ItemDetail(detail);
                        this._subscriptions.push(subscription);
                        cx.notify();
                    })
                    .ok();
                }
                Ok(None) => tracing::warn!("Selected item vanished before ItemDetail could load it"),
                Err(e) => tracing::warn!("Failed to load item: {e}"),
            }
        })
        .detach();
    }

    fn show_settings(&mut self, cx: &mut Context<Self>) {
        let settings = cx.new({
            let app_state = self.app_state.clone();
            move |cx| SettingsScreen::new(app_state, cx)
        });
        let subscription = cx.subscribe(&settings, |_this, _settings, event, cx| match event {
            SettingsScreenEvent::ThemeChanged(theme_id) => {
                cx.emit(AppShellEvent::ThemeChanged(*theme_id));
            }
            SettingsScreenEvent::SignedOut => cx.emit(AppShellEvent::Locked),
            SettingsScreenEvent::VaultDeleted => cx.emit(AppShellEvent::VaultDeleted),
        });
        self.content = Content::Settings(settings);
        self._subscriptions.push(subscription);
        cx.notify();
    }

    fn show_audit_log(&mut self, cx: &mut Context<Self>) {
        let audit = cx.new({
            let app_state = self.app_state.clone();
            move |cx| AuditLogScreen::new(app_state, cx)
        });
        self.content = Content::AuditLog(audit);
        cx.notify();
    }

    fn show_breach_monitor(&mut self, cx: &mut Context<Self>) {
        let breach = cx.new({
            let app_state = self.app_state.clone();
            move |cx| BreachMonitorScreen::new(app_state, cx)
        });
        self.content = Content::BreachMonitor(breach);
        cx.notify();
    }

    fn show_devices(&mut self, cx: &mut Context<Self>) {
        let devices = cx.new({
            let app_state = self.app_state.clone();
            move |cx| DevicesScreen::new(app_state, cx)
        });
        self.content = Content::Devices(devices);
        cx.notify();
    }

    fn show_sharing(&mut self, cx: &mut Context<Self>) {
        let sharing = cx.new({
            let app_state = self.app_state.clone();
            move |cx| SharingScreen::new(app_state, cx)
        });
        self.content = Content::Sharing(sharing);
        cx.notify();
    }

    /// Navigates to Sharing and immediately opens the share modal with
    /// `item_id` pre-selected — used from `ItemDetail`'s "Share Access".
    fn show_sharing_with_item(&mut self, item_id: String, cx: &mut Context<Self>) {
        let sharing = cx.new({
            let app_state = self.app_state.clone();
            move |cx| SharingScreen::new(app_state, cx)
        });
        sharing.update(cx, |sharing, cx| sharing.open_share_modal_for_item(item_id, cx));
        self.content = Content::Sharing(sharing);
        cx.notify();
    }

    fn add_item(&mut self, cx: &mut Context<Self>) {
        if self.nav != NavView::Vault {
            self.sidebar.update(cx, |sidebar, cx| sidebar.set_active(NavView::Vault, cx));
            self.navigate(NavView::Vault, cx);
        }
        if let Content::Vault(browser) = &self.content {
            browser.clone().update(cx, |vb, cx| vb.open_add_item_modal(cx));
        }
    }
}

impl Render for AppShell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);

        let content: gpui::AnyElement = match &self.content {
            Content::Vault(v) => v.clone().into_any_element(),
            Content::ItemDetail(v) => v.clone().into_any_element(),
            Content::Settings(v) => v.clone().into_any_element(),
            Content::AuditLog(v) => v.clone().into_any_element(),
            Content::Sharing(v) => v.clone().into_any_element(),
            Content::Devices(v) => v.clone().into_any_element(),
            Content::BreachMonitor(v) => v.clone().into_any_element(),
            Content::Placeholder(name) => placeholder(&palette, name).into_any_element(),
        };

        div()
            .relative()
            .size_full()
            .flex()
            .bg(palette.surface)
            .child(self.sidebar.clone())
            .child(
                div()
                    .flex_1()
                    .h_full()
                    .flex()
                    .flex_col()
                    .child(self.recovery_reminder_banner(&palette, cx))
                    .child(div().flex_1().overflow_hidden().child(content)),
            )
            .when_some(self.edit_modal.clone(), |el, modal| el.child(modal))
    }
}

impl AppShell {
    /// The standing "no way back" banner, port of
    /// `RecoveryReminder.tsx`. Deliberately not dismissable: a banner you can
    /// close is one you close, and the failure it warns about is
    /// unrecoverable. It goes away by being fixed.
    fn recovery_reminder_banner(&self, palette: &Palette, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(status) = &self.recovery_status else {
            return div().into_any_element();
        };
        let methods = [
            status.cloud_backup_delivered,
            status.security_key_delivered,
            status.trusted_contact_acknowledged,
        ]
        .into_iter()
        .filter(|done| *done)
        .count();
        if methods >= 2 {
            return div().into_any_element();
        }

        let subtitle = if methods == 0 {
            "No recovery methods are set up. Nobody can restore it for you — not support, not us."
        } else {
            "1 of the 2 recovery methods is set up. Nobody can restore it for you — not support, not us."
        };

        div()
            .w_full()
            .px_4()
            .py_3()
            .bg(palette.surface_container)
            .border_b_1()
            .border_color(palette.outline_variant)
            .flex()
            .items_center()
            .gap_3()
            .child(icon("shield_question", px(20.), palette.error))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .text_color(palette.on_surface)
                            .child("This vault has no way back if you forget your master password"),
                    )
                    .child(
                        div()
                            .text_color(palette.on_surface_variant)
                            .text_size(px(12.))
                            .child(subtitle),
                    ),
            )
            .child(
                div()
                    .px_4()
                    .py_2()
                    .rounded_lg()
                    .bg(palette.error)
                    .text_color(palette.surface)
                    .cursor_pointer()
                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                        this.navigate(NavView::Settings, cx);
                        cx.notify();
                    }))
                    .child("Set up recovery"),
            )
            .into_any_element()
    }
}

fn placeholder(palette: &Palette, name: &'static str) -> impl IntoElement {
    div()
        .size_full()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_3()
        .bg(palette.surface)
        .child(icon("construction", px(40.), palette.on_surface_variant))
        .child(
            div()
                .font_family(fonts::BODY)
                .text_color(palette.on_surface_variant)
                .child(format!("{name} isn't ported yet")),
        )
}
