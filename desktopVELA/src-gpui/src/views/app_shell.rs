//! Persistent post-unlock shell — port of `App.tsx`'s `<Sidebar/>` +
//! `<main>` layout. Owns navigation between Vault/ItemDetail/Settings and
//! (placeholders for) Devices/Sharing/Audit Log/Breach Monitor, which
//! haven't been ported yet. Replaces `RootView`'s previous direct
//! `VaultBrowser`/`ItemDetail` screen variants.

use std::sync::Arc;

use gpui::{div, prelude::*, px, Context, Entity, EventEmitter, IntoElement, Render, Subscription, Window};

use vela_desktop_core::AppState;

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
}

impl AppShell {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let sidebar = cx.new(Sidebar::new);
        let mut this = Self {
            app_state,
            sidebar,
            nav: NavView::Vault,
            content: Content::Placeholder(""),
            edit_modal: None,
            _edit_subscription: None,
            _subscriptions: Vec::new(),
        };
        this.subscribe_sidebar(cx);
        this.show_vault(cx);
        this
    }

    fn show_edit_modal(&mut self, item: vela_desktop_core::vault::VaultItem, cx: &mut Context<Self>) {
        let modal = cx.new({
            let app_state = self.app_state.clone();
            move |cx| AddItemModal::new_edit(app_state, item, cx)
        });
        let subscription = cx.subscribe(&modal, |this, _modal, event, cx| match event {
            AddItemModalEvent::Close => {
                this.edit_modal = None;
                this._edit_subscription = None;
                cx.notify();
            }
            AddItemModalEvent::Created | AddItemModalEvent::Updated => {
                this.edit_modal = None;
                this._edit_subscription = None;
                // Go back to the vault list — matches the simpler of the
                // two reasonable choices (re-fetching ItemDetail in place
                // being the other), and guarantees the list reflects the
                // edit immediately.
                this.show_vault(cx);
                cx.notify();
            }
        });
        self.edit_modal = Some(modal);
        self._edit_subscription = Some(subscription);
        cx.notify();
    }

    fn subscribe_sidebar(&mut self, cx: &mut Context<Self>) {
        let sidebar = self.sidebar.clone();
        let subscription = cx.subscribe(&sidebar, |this, _sidebar, event, cx| match event {
            SidebarEvent::Navigate(view) => this.navigate(*view, cx),
            SidebarEvent::AddItem => this.add_item(cx),
            SidebarEvent::Lock => {
                vela_desktop_core::commands::session::lock_session(&this.app_state);
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

    fn show_item_detail(&mut self, id: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let item = cx
                .background_spawn({
                    let app_state = app_state.clone();
                    async move { vela_desktop_core::commands::vault::get_item(&app_state, &id) }
                })
                .await;
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
            .child(div().flex_1().h_full().overflow_hidden().child(content))
            .when_some(self.edit_modal.clone(), |el, modal| el.child(modal))
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
