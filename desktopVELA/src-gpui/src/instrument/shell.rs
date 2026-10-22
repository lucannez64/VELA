//! The instrument shell: rail, top bar and content area. It owns the same
//! responsibilities as the classic `AppShell` (auto-lock activity, sync
//! scheduler, recovery reminder, lock, theme changes) and emits the same
//! `AppShellEvent`s, so `RootView` treats both shells identically.

use std::sync::Arc;

use chrono::Utc;
use gpui::{
    div, prelude::*, px, relative, AnimationExt, App, Context, Entity, EventEmitter, FontWeight,
    Hsla, IntoElement, MouseButton, Render, SharedString, Subscription, Task,
    UniformListScrollHandle, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage, TextChanged};
use vela_desktop_core::audit::AuditEntry;
use vela_desktop_core::recovery::RecoveryStatus;
use vela_desktop_core::vault::VaultItem;
use vela_desktop_core::AppState;

use super::analysis::{analyze, Analysis, Kind};
use super::generator::GenState;
use super::{alpha, anim_id, mono, ms, stagger, tokens, Tok};
use crate::background::GuardedSpawn;
use crate::fonts;
use super::icons::icon;
use crate::theme::{ActiveTheme, ThemeId};
use crate::views::add_item_modal::{AddItemModal, AddItemModalEvent};
use crate::views::app_shell::AppShellEvent;
use crate::views::audit_log_screen::AuditLogScreen;
use crate::views::breach_monitor_screen::BreachMonitorScreen;
use crate::views::devices_screen::DevicesScreen;
use crate::views::settings_screen::{SettingsScreen, SettingsScreenEvent};
use crate::views::sharing_screen::SharingScreen;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Overview,
    Vault,
    Sharing,
    Devices,
    Activity,
    Breach,
    Settings,
    Profile,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListKind {
    All,
    Favorites,
    Of(Kind),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Recent,
    Name,
    Weakest,
}

impl Sort {
    pub fn label(self) -> &'static str {
        match self {
            Sort::Recent => "Recently changed",
            Sort::Name => "Name",
            Sort::Weakest => "Weakest first",
        }
    }
    pub(super) fn next(self) -> Self {
        match self {
            Sort::Recent => Sort::Name,
            Sort::Name => Sort::Weakest,
            Sort::Weakest => Sort::Recent,
        }
    }
}

enum Embedded {
    Sharing(Entity<SharingScreen>),
    Devices(Entity<DevicesScreen>),
    Activity(Entity<AuditLogScreen>),
    Breach(Entity<BreachMonitorScreen>),
    Settings(Entity<SettingsScreen>),
}

pub(super) struct Totp {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
    expires_at_ms: i64,
}

pub struct InstrumentShell {
    pub(super) app_state: Arc<AppState>,
    pub(super) view: View,
    pub(super) items: Arc<Vec<VaultItem>>,
    pub(super) analysis: Analysis,
    pub(super) loaded: bool,
    pub(super) audit: Vec<AuditEntry>,
    pub(super) search: Entity<EditableTextState>,
    pub(super) last_query: String,
    pub(super) list_kind: ListKind,
    pub(super) risk_only: bool,
    pub(super) sort: Sort,
    /// Indexes into `analysis.facts`, filtered and sorted.
    pub(super) rows: Arc<Vec<usize>>,
    pub(super) selected: Option<String>,
    pub(super) reveal: bool,
    pub(super) confirm_delete: bool,
    pub(super) totp: Option<Totp>,
    _totp_task: Option<Task<()>>,
    embedded: Option<Embedded>,
    modal: Option<Entity<AddItemModal>>,
    _modal_subscription: Option<Subscription>,
    pub(super) generator: Option<GenState>,
    pub(super) theme_menu: bool,
    pub(super) more_menu: bool,
    pub(super) profile_name: String,
    pub(super) profile_id: String,
    /// Bumped on every view change so entrance animations replay.
    pub(super) anim_gen: u64,
    /// Bumped on every selection change so the detail panel slides in.
    pub(super) detail_gen: u64,
    pub(super) list_scroll: UniformListScrollHandle,
    recovery_status: Option<RecoveryStatus>,
    _recovery_reminder: Task<()>,
    _sync_scheduler: Task<()>,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<AppShellEvent> for InstrumentShell {}

impl InstrumentShell {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<ActiveTheme>(|_, cx| cx.notify()).detach();
        cx.observe_global::<crate::host::VaultItemsVersion>(|this: &mut Self, cx| this.reload(cx))
            .detach();
        let search = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));
        let search_sub = cx.subscribe(&search, |this: &mut Self, _, _: &TextChanged, cx| {
            if this.view != View::Vault {
                this.set_view(View::Vault, cx);
            }
            this.refresh_rows();
            cx.notify();
        });
        let demo = cx.has_global::<crate::demo::DemoMode>();
        let sync_scheduler = if demo {
            cx.spawn(async |_, _| {})
        } else {
            crate::sync_scheduler::start(app_state.clone(), cx)
        };
        let recovery_reminder = if demo {
            cx.spawn(async |_, _| {})
        } else {
            Self::start_recovery_reminder(app_state.clone(), cx)
        };
        let profile_name = if demo { "Alex Demo" } else { "VELA account" }.to_string();
        let profile_id = if demo { "alex@example.test".to_string() } else { app_state.store.load_user_id().unwrap_or_default() };
        let mut this = Self {
            app_state,
            view: View::Overview,
            items: Arc::new(Vec::new()),
            analysis: Analysis::default(),
            loaded: false,
            audit: Vec::new(),
            search,
            last_query: String::new(),
            list_kind: ListKind::All,
            risk_only: false,
            sort: Sort::Recent,
            rows: Arc::new(Vec::new()),
            selected: None,
            reveal: false,
            confirm_delete: false,
            totp: None,
            _totp_task: None,
            embedded: None,
            modal: None,
            _modal_subscription: None,
            generator: None,
            theme_menu: false,
            more_menu: false,
            profile_name,
            profile_id,
            anim_gen: 1,
            detail_gen: 1,
            list_scroll: UniformListScrollHandle::new(),
            recovery_status: None,
            _recovery_reminder: recovery_reminder,
            _sync_scheduler: sync_scheduler,
            _subscriptions: vec![search_sub],
        };
        this.reload(cx);
        this
    }

    // ── data ────────────────────────────────────────────────────────────

    pub(super) fn reload(&mut self, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let loaded = cx
                .background_spawn_guarded("instrument load", async move {
                    let items = vela_desktop_core::commands::vault::get_items_arc(&app_state);
                    let mut audit = vela_desktop_core::audit::load_audit_log(&app_state)
                        .map(|log| log.entries)
                        .unwrap_or_default();
                    audit.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                    audit.truncate(600);
                    items.map(|items| {
                        let analysis = analyze(&items, Utc::now());
                        (items, analysis, audit)
                    })
                })
                .await;
            this.update(cx, |this, cx| {
                match loaded {
                    Some(Ok((items, analysis, audit))) => {
                        this.items = items;
                        this.analysis = analysis;
                        this.audit = audit;
                        this.loaded = true;
                        // Re-read the selected item's secret after edits, and
                        // conceal any value that was previously revealed.
                        let selected = this.selected.clone().filter(|id| {
                            this.items.iter().any(|item| item.id() == id)
                        });
                        this.select(None, cx);
                        if selected.is_some() {
                            this.select(selected, cx);
                        }
                        this.refresh_rows();
                    }
                    Some(Err(e)) => tracing::warn!("Instrument shell could not load items: {e}"),
                    None => tracing::warn!("Instrument shell load panicked"),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub(super) fn query(&self, cx: &App) -> String {
        self.search.read(cx).as_str().trim().to_lowercase()
    }

    pub(super) fn refresh_rows(&mut self) {
        // The search text lives in an entity; callers that have `cx` pass the
        // query through `refresh_rows_with`. This variant keeps the last one.
        let q = self.last_query.clone();
        self.refresh_rows_with(&q);
    }

    pub(super) fn item_at(&self, fact: usize) -> &VaultItem {
        &self.items[self.analysis.facts[fact].index]
    }

    pub(super) fn selected_item(&self) -> Option<(usize, &VaultItem)> {
        let id = self.selected.as_ref()?;
        self.analysis
            .facts
            .iter()
            .enumerate()
            .find(|(_, f)| self.items[f.index].id() == id)
            .map(|(slot, f)| (slot, &self.items[f.index]))
    }

    // ── navigation ──────────────────────────────────────────────────────

    pub(super) fn set_view(&mut self, view: View, cx: &mut Context<Self>) {
        self.theme_menu = false;
        self.more_menu = false;
        self.anim_gen += 1;
        self.view = view;
        if view != View::Vault {
            // Stop the code timer and conceal secrets when leaving details.
            self.select(None, cx);
        }
        self.embedded = match view {
            View::Overview | View::Vault | View::Profile => None,
            View::Sharing => Some(Embedded::Sharing(cx.new({
                let s = self.app_state.clone();
                move |cx| SharingScreen::new(s, cx)
            }))),
            View::Devices => Some(Embedded::Devices(cx.new({
                let s = self.app_state.clone();
                move |cx| DevicesScreen::new(s, cx)
            }))),
            View::Activity => Some(Embedded::Activity(cx.new({
                let s = self.app_state.clone();
                move |cx| AuditLogScreen::new(s, cx)
            }))),
            View::Breach => Some(Embedded::Breach(cx.new({
                let s = self.app_state.clone();
                move |cx| BreachMonitorScreen::new(s, cx)
            }))),
            View::Settings => {
                let settings = cx.new({
                    let s = self.app_state.clone();
                    move |cx| SettingsScreen::new(s, cx)
                });
                let sub = cx.subscribe(&settings, |_, _, event, cx| match event {
                    SettingsScreenEvent::ThemeChanged(id) => {
                        cx.emit(AppShellEvent::ThemeChanged(*id))
                    }
                    SettingsScreenEvent::SignedOut => cx.emit(AppShellEvent::Locked),
                    SettingsScreenEvent::VaultDeleted => cx.emit(AppShellEvent::VaultDeleted),
                });
                self._subscriptions.push(sub);
                Some(Embedded::Settings(settings))
            }
        };
        if matches!(view, View::Overview) {
            // The overview reads the audit log; keep it current.
            self.reload(cx);
        }
        cx.notify();
    }

    pub(super) fn open_list(&mut self, kind: ListKind, risk: bool, cx: &mut Context<Self>) {
        self.list_kind = kind;
        self.risk_only = risk;
        self.refresh_rows();
        self.set_view(View::Vault, cx);
    }

    /// Quick-search hand-off, same contract as `AppShell::open_item`.
    pub fn open_item(&mut self, id: String, cx: &mut Context<Self>) {
        self.list_kind = ListKind::All;
        self.risk_only = false;
        self.search.update(cx, |s, cx| s.emplace("", cx));
        self.last_query.clear();
        self.refresh_rows();
        if self.view != View::Vault {
            self.set_view(View::Vault, cx);
        }
        self.select(Some(id), cx);
    }

    pub(super) fn select(&mut self, id: Option<String>, cx: &mut Context<Self>) {
        if self.selected == id {
            return;
        }
        self.selected = id;
        self.reveal = false;
        self.confirm_delete = false;
        self.detail_gen += 1;
        self.totp = None;
        self._totp_task = None;
        let secret = self.selected_item().and_then(|(_, item)| match item {
            VaultItem::Login { totp: Some(s), .. } if !s.trim().is_empty() => Some(s.clone()),
            _ => None,
        });
        if let Some(secret) = secret {
            self._totp_task = Some(self.spawn_totp(secret, cx));
        }
        cx.notify();
    }

    /// One repaint per second while a code is on screen — the same cadence
    /// as the classic `ItemDetail`, and nothing at all otherwise.
    fn spawn_totp(&self, secret: String, cx: &mut Context<Self>) -> Task<()> {
        cx.spawn(async move |this, cx| loop {
            let now = Utc::now().timestamp_millis();
            let needs_code = this
                .update(cx, |this, cx| {
                    let stale = this.totp.as_ref().is_none_or(|t| now >= t.expires_at_ms);
                    if !stale {
                        if let Some(t) = &mut this.totp {
                            let left = ((t.expires_at_ms - now) as u64).div_ceil(1000).max(1);
                            if left != t.remaining {
                                t.remaining = left;
                                cx.notify();
                            }
                        }
                    }
                    stale
                })
                .unwrap_or(false);
            if this.upgrade().is_none() {
                break;
            }
            if needs_code {
                let result = cx
                    .background_spawn_guarded("instrument totp", {
                        let secret = secret.clone();
                        async move { vela_desktop_core::totp::generate_totp(secret) }
                    })
                    .await;
                let alive = this
                    .update(cx, |this, cx| {
                        if let Some(Ok(code)) = result {
                            this.totp = Some(Totp {
                                code: code.code,
                                remaining: code.remaining_secs.max(1),
                                period: code.period.max(1),
                                expires_at_ms: Utc::now().timestamp_millis()
                                    + code.remaining_secs as i64 * 1000,
                            });
                        }
                        cx.notify();
                    })
                    .is_ok();
                if !alive {
                    break;
                }
            }
            cx.background_executor()
                .timer(std::time::Duration::from_millis(250))
                .await;
        })
    }

    // ── actions ─────────────────────────────────────────────────────────

    pub(super) fn copy(&self, label: &str, value: &str, cx: &mut App) {
        crate::clipboard::copy(cx, label, value);
    }

    pub(super) fn new_item(&mut self, cx: &mut Context<Self>) {
        let modal = cx.new({
            let s = self.app_state.clone();
            move |cx| AddItemModal::new(s, cx)
        });
        self.host_modal(modal, cx);
    }

    pub(super) fn edit_selected(&mut self, cx: &mut Context<Self>) {
        let Some((_, item)) = self.selected_item() else { return };
        // The generic editor cannot represent a passkey (saving would replace
        // it with a login) and received shares are read-only.
        if matches!(item, VaultItem::Passkey { .. }) || item.is_received_share() { return; }
        let item = item.clone();
        let modal = cx.new({
            let s = self.app_state.clone();
            move |cx| AddItemModal::new_edit(s, item, cx)
        });
        self.host_modal(modal, cx);
    }

    fn host_modal(&mut self, modal: Entity<AddItemModal>, cx: &mut Context<Self>) {
        let sub = cx.subscribe(&modal, |this, _, event, cx| {
            this.modal = None;
            this._modal_subscription = None;
            if matches!(event, AddItemModalEvent::Created | AddItemModalEvent::Updated) {
                this.reload(cx);
            }
            cx.notify();
        });
        self.generator = None;
        self.theme_menu = false;
        self.modal = Some(modal);
        self._modal_subscription = Some(sub);
        cx.notify();
    }

    pub(super) fn toggle_favorite(&mut self, cx: &mut Context<Self>) {
        let Some((_, item)) = self.selected_item() else { return };
        let updated = item.clone().with_favorite(!item.favorite());
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("save favorite", async move {
                    vela_desktop_core::commands::vault::update_item(&app_state, updated).await
                })
                .await
                .unwrap_or_else(|| Err("Saving the item failed unexpectedly".into()));
            this.update(cx, |this, cx| match result {
                Ok(_) => this.reload(cx),
                Err(e) => crate::toast::show(cx, e, crate::toast::ToastKind::Error),
            })
            .ok();
        })
        .detach();
    }

    pub(super) fn delete_selected(&mut self, cx: &mut Context<Self>) {
        if !self.confirm_delete {
            self.confirm_delete = true;
            cx.notify();
            return;
        }
        let Some((_, item)) = self.selected_item() else { return };
        let (id, name) = (item.id().to_string(), item.name().to_string());
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn_guarded("delete item", async move {
                    vela_desktop_core::commands::vault::delete_item(&app_state, &id).await
                })
                .await
                .unwrap_or_else(|| Err("Deleting the item failed unexpectedly".into()));
            this.update(cx, |this, cx| match result {
                Ok(()) => {
                    this.select(None, cx);
                    this.reload(cx);
                    crate::toast::show(cx, format!("{name} deleted"), crate::toast::ToastKind::Info);
                }
                Err(e) => crate::toast::show(cx, e, crate::toast::ToastKind::Error),
            })
            .ok();
        })
        .detach();
    }

    pub(super) fn share_selected(&mut self, cx: &mut Context<Self>) {
        let Some((_, item)) = self.selected_item() else { return };
        if matches!(item, VaultItem::Passkey { .. }) || item.is_received_share() { return; }
        let id = item.id().to_string();
        self.set_view(View::Sharing, cx);
        if let Some(Embedded::Sharing(sharing)) = &self.embedded {
            sharing.update(cx, |s, cx| s.open_share_modal_for_item(id, cx));
        }
    }

    pub(super) fn lock(&mut self, cx: &mut Context<Self>) {
        vela_desktop_core::commands::session::lock_session(&self.app_state);
        crate::clipboard::clear(cx);
        crate::toast::show(cx, "Session locked", crate::toast::ToastKind::Info);
        cx.emit(AppShellEvent::Locked);
    }

    fn set_theme(&mut self, id: ThemeId, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        if let Ok(mut settings) = vela_desktop_core::commands::settings::get_settings(&app_state) {
            settings.theme = id.to_setting();
            if let Err(e) = vela_desktop_core::commands::settings::update_settings(&app_state, settings) {
                tracing::warn!("Could not save theme: {e}");
            }
        }
        cx.emit(AppShellEvent::ThemeChanged(id));
    }

    fn start_recovery_reminder(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Task<()> {
        cx.spawn(async move |this, cx| loop {
            cx.background_executor()
                .timer(std::time::Duration::from_secs(15))
                .await;
            let result = cx
                .background_spawn_guarded("recovery reminder", {
                    let app_state = app_state.clone();
                    async move { vela_desktop_core::recovery::get_recovery_setup_status(&app_state) }
                })
                .await;
            let alive = this
                .update(cx, |this, cx| {
                    let next = result.and_then(Result::ok);
                    let changed = format!("{:?}", next) != format!("{:?}", this.recovery_status);
                    this.recovery_status = next;
                    if changed {
                        cx.notify();
                    }
                })
                .is_ok();
            if !alive {
                break;
            }
        })
    }
}

// The search query is cached so row filtering can run without `cx`.
impl InstrumentShell {
    pub(super) fn sync_query(&mut self, cx: &App) {
        let q = self.query(cx);
        if q != self.last_query {
            self.last_query = q.clone();
            self.refresh_rows_with(&q);
        }
    }
}

// ── rendering ───────────────────────────────────────────────────────────

const RAIL_WIDE: f32 = 224.;
const RAIL_NARROW: f32 = 72.;

pub(super) fn wide_rail(window: &Window) -> bool {
    f32::from(window.viewport_size().width) >= 1240.
}

pub(crate) fn pill(id: impl Into<SharedString>, label: impl Into<SharedString>, primary: bool, t: &Tok) -> gpui::Stateful<gpui::Div> {
    let id: SharedString = id.into();
    let base = div()
        .id(gpui::ElementId::Name(id.clone()))
        .debug_selector(move || id.to_string())
        .h(px(40.))
        .px(px(16.))
        .rounded_full()
        .flex()
        .items_center()
        .gap(px(8.))
        .cursor_pointer()
        .flex_shrink_0()
        .text_size(px(13.))
        .font_weight(FontWeight::MEDIUM)
        .child(label.into());
    if primary {
        base.bg(t.primary_bg).text_color(t.primary_fg).hover(|s| s.opacity(0.9))
    } else {
        let hover = t.panel2;
        base.bg(t.panel)
            .border_1()
            .border_color(t.line)
            .text_color(t.text)
            .hover(move |s| s.bg(hover))
    }
}

pub(crate) fn icon_btn(id: impl Into<SharedString>, name: &'static str, t: &Tok) -> gpui::Stateful<gpui::Div> {
    let id: SharedString = id.into();
    let hover = t.panel2;
    div()
        .id(gpui::ElementId::Name(id.clone()))
        .debug_selector(move || id.to_string())
        .size(px(34.))
        .flex_shrink_0()
        .rounded(px(11.))
        .bg(t.panel)
        .border_1()
        .border_color(t.line)
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(icon(name, px(17.), t.text))
}

impl InstrumentShell {
    fn nav_row(
        &self,
        id: &'static str,
        icon_name: &'static str,
        label: &'static str,
        count: Option<(usize, bool)>,
        active: bool,
        wide: bool,
        t: &Tok,
        on_click: impl Fn(&mut Self, &mut Context<Self>) + 'static,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let hover = t.panel2;
        let fg = if active { t.text } else { t.muted };
        let row = div()
            .id(id)
            .debug_selector(move || id.to_string())
            .relative()
            .h(px(36.))
            .px(px(10.))
            .rounded(px(12.))
            .flex()
            .items_center()
            .gap(px(11.))
            .when(!wide, |d| d.w(px(44.)).justify_center().px_0())
            .cursor_pointer()
            .text_color(fg)
            .text_size(px(13.5))
            .font_weight(FontWeight::MEDIUM)
            .when(active, |d| d.bg(t.panel3).border_1().border_color(t.line))
            .when(!active, |d| d.hover(move |s| s.bg(hover)))
            .child(icon(icon_name, px(18.), fg))
            .when(wide, |d| d.child(div().flex_1().child(label)))
            .when_some(count.filter(|_| wide), |d, (n, risk)| {
                d.child(
                    div()
                        .font_family(fonts::MONO)
                        .text_size(px(10.5))
                        .text_color(if risk { t.risk } else { t.faint })
                        .child(n.to_string()),
                )
            })
            .on_click(cx.listener(move |this, _, _, cx| on_click(this, cx)));
        row
    }

    fn render_rail(&mut self, wide: bool, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let a = &self.analysis;
        let total = a.facts.len();
        let favs = a.favorites.len();
        let risk = a.at_risk;
        let v = self.view;
        let lk = self.list_kind;
        let ro = self.risk_only;
        let group = |label: &'static str, t: &Tok| {
            div()
                .when(wide, |d| d.px(px(10.)).pt(px(14.)).pb(px(8.)).child(mono(label, t.faint)))
                .when(!wide, |d| d.h(px(14.)))
        };
        let brand_style = super::dot_matrix::DotStyle::new(4.2, t.text).gradient(t.grad);
        div()
            .id("instrument-rail")
            .flex_shrink_0()
            .w(px(if wide { RAIL_WIDE } else { RAIL_NARROW }))
            .h_full()
            .flex()
            .flex_col()
            .bg(t.panel)
            .border_1()
            .border_color(t.line)
            .rounded(px(22.))
            .px(px(12.))
            .pt(px(if wide {18.} else {4.}))
            .pb(px(12.))
            .when(!wide, |d| d.items_center())
            .when(wide, |el|el.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .px(px(8.))
                    .pb(px(10.))
                    .child(super::dot_matrix::dot_text("V", brand_style))
                    .when(wide, |d| {
                        d.child(super::dot_matrix::dot_text(
                            "VELA",
                            super::dot_matrix::DotStyle::new(3.2, t.text),
                        ))
                        .child(div().flex_1())
                    }),
            ))
            .when(wide, |el|el.child(group("01 / Vault", t)))
            .child(self.nav_row("nav-overview", "grid_view", "Overview", None, v == View::Overview, wide, t, |s, cx| s.set_view(View::Overview, cx), cx))
            .child(self.nav_row("nav-all", "vault", "All items", Some((total, false)), v == View::Vault && lk == ListKind::All && !ro, wide, t, |s, cx| s.open_list(ListKind::All, false, cx), cx))
            .child(self.nav_row("nav-favs", "star", "Favourites", Some((favs, false)), v == View::Vault && lk == ListKind::Favorites, wide, t, |s, cx| s.open_list(ListKind::Favorites, false, cx), cx))
            .child(group("02 / Security", t))
            .child(self.nav_row("nav-risk", "shield", "Needs attention", (risk > 0).then_some((risk, true)), v == View::Vault && ro, wide, t, |s, cx| s.open_list(ListKind::All, true, cx), cx))
            .child(self.nav_row("nav-gen", "casino", "Generator", None, false, wide, t, |s, cx| s.open_generator(cx), cx))
            .child(self.nav_row("nav-sharing", "share", "Sharing", None, v == View::Sharing, wide, t, |s, cx| s.set_view(View::Sharing, cx), cx))
            .child(group("03 / This device", t))
            .child(self.nav_row("nav-devices", "devices", "Devices", None, v == View::Devices, wide, t, |s, cx| s.set_view(View::Devices, cx), cx))
            .child(self.nav_row("nav-activity", "history", "Activity", None, v == View::Activity, wide, t, |s, cx| s.set_view(View::Activity, cx), cx))
            .child(self.nav_row("nav-settings", "settings", "Settings", None, v == View::Settings, wide, t, |s, cx| s.set_view(View::Settings, cx), cx))
            .child(div().flex_1())
            .child(div().id("rail-profile").debug_selector(||"rail-profile".into())
                .flex().items_center().gap(px(10.)).py(px(10.)).cursor_pointer()
                .child(super::avatar(&self.profile_name,32.,t))
                .when(wide, |el|el.child(div().min_w_0().child(div().text_size(px(12.)).child(self.profile_name.clone())).child(mono("This device",t.faint))))
                .on_click(cx.listener(|this,_,_,cx|this.set_view(View::Profile,cx))))
            .child(
                div()
                    .id("instrument-lock")
                    .debug_selector(|| "instrument-lock".into())
                    .h(px(42.))
                    .when(!wide, |d| d.w(px(44.)))
                    .rounded_full()
                    .border_1()
                    .border_color(t.line2)
                    .flex()
                    .items_center()
                    .justify_center()
                    .gap(px(8.))
                    .cursor_pointer()
                    .text_color(t.text)
                    .text_size(px(13.))
                    .font_weight(FontWeight::MEDIUM)
                    .hover({
                        let c = t.panel2;
                        move |s| s.bg(c)
                    })
                    .child(icon("lock", px(17.), t.text))
                    .when(wide, |d| d.child("Lock vault"))
                    .on_click(cx.listener(|this, _, _, cx| this.lock(cx))),
            )
    }

    fn render_top(&mut self, wide: bool, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let narrow = !wide;
        let pulse_color = t.signal;
        div()
            .flex()
            .items_center()
            .gap(px(10.))
            .h(px(52.))
            .flex_shrink_0()
            .child(
                div()
                    .flex_1()
                    .max_w(px(560.))
                    .min_w(px(160.))
                    .h(px(44.))
                    .rounded_full()
                    .bg(t.panel)
                    .border_1()
                    .border_color(t.line)
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .pl(px(16.))
                    .pr(px(8.))
                    .child(icon("search", px(17.), t.muted))
                    .child(
                        text_input("instrument-search")
                            .state(self.search.downgrade())
                            .placeholder("Search logins, cards, notes…")
                            .placeholder_color(t.muted)
                            .caret_blink_interval_500ms()
                            .text_color(t.text)
                            .caret_color(t.text)
                            .text_size(px(13.5))
                            .flex_1()
                            .min_w_0()
                            .whitespace_nowrap()
                            .overflow_x_scroll(),
                    )
                    .child(
                        div()
                            .px(px(7.))
                            .py(px(3.))
                            .rounded(px(7.))
                            .border_1()
                            .border_color(t.line2)
                            .child(mono("Ctrl K", t.muted)),
                    ),
            )
            .when(!narrow, |d| {
                d.child(
                    div()
                        .h(px(44.))
                        .px(px(16.))
                        .rounded_full()
                        .bg(t.panel)
                        .border_1()
                        .border_color(t.line)
                        .flex()
                        .items_center()
                        .gap(px(9.))
                        .text_size(px(13.))
                        .text_color(t.text)
                        .child(
                            // A few pulses on arrival, then still: no idle repaint loop.
                            div()
                                .size(px(7.))
                                .rounded_full()
                                .bg(pulse_color)
                                .with_animation(
                                    anim_id("status-pulse", 1),
                                    gpui::Animation::new(ms(3600)),
                                    move |el, d| {
                                        let phase = (d * 3.).fract();
                                        let a = if d >= 1. { 1. } else { 0.45 + 0.55 * (phase * std::f32::consts::PI).sin().abs() };
                                        el.bg(alpha(pulse_color, a))
                                    },
                                ),
                        )
                        .child(if cx.has_global::<crate::demo::DemoMode>() {
                            "Demo vault · local only"
                        } else {
                            "Unlocked · encrypted at rest"
                        }),
                )
            })
            .child(div().flex_1())
            .child(
                pill("top-generate", "Generate", false, t)
                    .child(icon("casino", px(16.), t.text))
                    .on_click(cx.listener(|this, _, _, cx| this.open_generator(cx))),
            )
            .child(
                pill("top-new", "New item", true, t)
                    .on_click(cx.listener(|this, _, _, cx| this.new_item(cx))),
            )
            .child(
                icon_btn("top-theme", "palette", t)
                    .size(px(44.))
                    .rounded_full()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.theme_menu = !this.theme_menu;
                        cx.notify();
                    })),
            )
    }

    fn render_theme_menu(&mut self, t: &Tok, cx: &mut Context<Self>) -> impl IntoElement {
        let current = cx.try_global::<ActiveTheme>().map(|a| a.0).unwrap_or(ThemeId::Vela);
        let gen = self.anim_gen;
        div()
            .id("theme-menu")
            .debug_selector(|| "theme-menu".into())
            .absolute()
            .top(px(66.))
            .right(px(12.))
            .w(px(300.))
            .p(px(12.))
            .rounded(px(20.))
            .bg(t.panel)
            .border_1()
            .border_color(t.line2)
            .occlude()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(div().px(px(6.)).pb(px(4.)).child(mono("Theme", t.muted)))
            .children(super::THEMES.into_iter().map(|id| {
                let tk = super::tokens_for(id);
                let name = if id == ThemeId::Vela { "Night (VELA Dark)" } else { id.label() };
                let selected = id == current;
                let hover = t.panel2;
                div()
                    .id(gpui::ElementId::Name(format!("theme-{}", id.label()).into()))
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .p(px(8.))
                    .rounded(px(14.))
                    .cursor_pointer()
                    .border_1()
                    .border_color(if selected { t.violet } else { alpha(t.line, 0.) })
                    .hover(move |s| s.bg(hover))
                    .child(
                        div()
                            .w(px(56.))
                            .h(px(38.))
                            .rounded(px(9.))
                            .bg(tk.bg)
                            .p(px(6.))
                            .flex()
                            .flex_col()
                            .justify_between()
                            .child(div().w(px(26.)).h(px(4.)).rounded_full().bg(tk.text))
                            .child(
                                div()
                                    .flex()
                                    .gap(px(3.))
                                    .child(div().size(px(7.)).rounded_full().bg(tk.violet))
                                    .child(div().size(px(7.)).rounded_full().bg(tk.signal))
                                    .child(div().size(px(7.)).rounded_full().bg(tk.risk)),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .child(div().text_size(px(13.)).text_color(t.text).child(name))
                            .child(mono(if tk.dark { "Dark" } else { "Light" }, t.faint)),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| this.set_theme(id, cx)))
            }))
            .with_animation(
                anim_id("theme-menu", gen),
                gpui::Animation::new(ms(180)).with_easing(super::ease_out),
                |el, d| el.opacity(d).top(px(58. + 8. * d)),
            )
    }

    fn render_recovery_banner(&self, t: &Tok, cx: &mut Context<Self>) -> Option<impl IntoElement> {
        let status = self.recovery_status.as_ref()?;
        let methods = [
            status.cloud_backup_delivered,
            status.security_key_delivered,
            status.trusted_contact_acknowledged,
        ]
        .into_iter()
        .filter(|d| *d)
        .count();
        if methods >= 2 {
            return None;
        }
        let subtitle = if methods == 0 {
            "No recovery methods are set up. Nobody can restore it for you — not support, not us."
        } else {
            "1 of the 2 recovery methods is set up. Nobody can restore it for you — not support, not us."
        };
        Some(
            div()
                .flex_shrink_0()
                .flex()
                .items_center()
                .gap(px(12.))
                .p(px(14.))
                .rounded(px(18.))
                .bg(alpha(t.risk, 0.08))
                .border_1()
                .border_color(alpha(t.risk, 0.35))
                .child(icon("shield_question", px(20.), t.risk))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .child(div().text_color(t.text).font_weight(FontWeight::MEDIUM).child("This vault has no way back if you forget your master password"))
                        .child(div().text_size(px(12.5)).text_color(t.muted).child(subtitle)),
                )
                .child(pill("recovery-setup", "Set up recovery", true, t).on_click(cx.listener(|this, _, _, cx| {
                    this.set_view(View::Settings, cx);
                    if let Some(Embedded::Settings(s)) = &this.embedded {
                        s.update(cx, |s, cx| s.show_recovery(cx));
                    }
                }))),
        )
    }

    fn render_embedded(&self, _t: &Tok) -> gpui::AnyElement {
        let view: gpui::AnyElement = match &self.embedded {
            Some(Embedded::Sharing(v)) => v.clone().into_any_element(),
            Some(Embedded::Devices(v)) => v.clone().into_any_element(),
            Some(Embedded::Activity(v)) => v.clone().into_any_element(),
            Some(Embedded::Breach(v)) => v.clone().into_any_element(),
            Some(Embedded::Settings(v)) => v.clone().into_any_element(),
            None => div().into_any_element(),
        };
        div()
            .size_full()
            .overflow_hidden()
            .child(view)
            .with_animation(
                anim_id("embedded", self.anim_gen),
                stagger(0, 0, 260),
                |el, d| el.opacity(d).top(px(10. * (1. - d))),
            )
            .into_any_element()
    }
}

impl Render for InstrumentShell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync_query(cx);
        let t = tokens(cx);
        let wide = wide_rail(window);
        let mobile = f32::from(window.viewport_size().width) < 760.;
        let content: gpui::AnyElement = match self.view {
            View::Overview => self.render_overview(window, &t, cx),
            View::Vault => self.render_vault(window, &t, cx),
            View::Profile => self.render_profile(&t, cx),
            _ => self.render_embedded(&t),
        };
        let banner = self.render_recovery_banner(&t, cx);
        let theme_menu = self.theme_menu.then(|| self.render_theme_menu(&t, cx));
        let generator = self.generator.is_some().then(|| self.render_generator(window, &t, cx));

        div()
            .id("instrument-shell")
            .relative()
            .size_full()
            .flex()
            .gap(px(12.))
            .p(px(12.))
            .bg(t.bg)
            .text_color(t.text)
            .font_family(fonts::LABEL)
            .key_context("InstrumentShell")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, _| {
                    vela_desktop_core::commands::session::notify_user_activity(&this.app_state);
                }),
            )
            .when(!mobile, |el| el.child(self.render_rail(wide, &t, cx)))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .gap(px(12.))
                    .child(if mobile { self.render_mobile_top(&t, cx).into_any_element() } else { self.render_top(wide, &t, cx).into_any_element() })
                    .children(banner)
                    .child(div().flex_1().min_h_0().min_w_0().relative().child(content))
                    .child(self.render_dock(&t, cx)),
            )
            .when(self.more_menu, |el| el.child(self.render_more(&t, cx)))
            .children(theme_menu)
            .children(generator)
            .when_some(self.modal.clone(), |d, m| d.child(m))
    }
}

impl InstrumentShell {
    pub(crate) fn handle_key(&mut self, event: &gpui::KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        vela_desktop_core::commands::session::notify_user_activity(&self.app_state);
        let ks = &event.keystroke;
        let ctrl = ks.modifiers.control || ks.modifiers.platform;
        match ks.key.as_str() {
            "k" if ctrl => {
                let handle = gpui::Focusable::focus_handle(self.search.read(cx), cx);
                handle.focus(window, cx);
                self.search.update(cx, |s, cx| s.select_document(cx));
                cx.stop_propagation();
            }
            "n" if ctrl && self.modal.is_none() => {
                self.new_item(cx);
                cx.stop_propagation();
            }
            "escape" => {
                if self.generator.is_some() || self.theme_menu || self.more_menu {
                    self.generator = None;
                    self.theme_menu = false;
                    self.more_menu = false;
                    cx.notify();
                } else if self.view == View::Vault && self.selected.is_some() && self.modal.is_none() {
                    self.select(None, cx);
                }
            }
            "down" | "up" if self.view == View::Vault && self.modal.is_none() && self.generator.is_none() => {
                if self.rows.is_empty() {
                    return;
                }
                let current = self
                    .selected_item()
                    .and_then(|(slot, _)| self.rows.iter().position(|r| *r == slot));
                let next = match (current, ks.key.as_str()) {
                    (None, _) => 0,
                    (Some(i), "down") => (i + 1).min(self.rows.len() - 1),
                    (Some(i), _) => i.saturating_sub(1),
                };
                let id = self.item_at(self.rows[next]).id().to_string();
                self.list_scroll.scroll_to_item(next, gpui::ScrollStrategy::Center);
                self.select(Some(id), cx);
                cx.stop_propagation();
            }
            _ => {}
        }
    }
}

/// Shared by overview and vault: a coloured `Hsla` per strength level.
pub(super) fn strength_color(level: u8, t: &Tok) -> Hsla {
    match level {
        0 | 1 => t.risk,
        2 => t.warn,
        _ => t.signal,
    }
}

pub(super) fn ago(days: i64) -> String {
    match days {
        d if d < 1 => "today".into(),
        d if d < 30 => format!("{d}d"),
        d if d < 365 => format!("{}mo", (d as f32 / 30.).round() as i64),
        d => {
            let y = d as f32 / 365.;
            if y < 2. {
                format!("{y:.1}y")
            } else {
                format!("{}y", y.round() as i64)
            }
        }
    }
}

pub(super) fn subtitle(item: &VaultItem) -> String {
    let domain = item
        .url()
        .map(|u| {
            u.trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_start_matches("www.")
                .split('/')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|d| !d.is_empty());
    match item {
        VaultItem::CreditCard { number, .. } => {
            let last: String = number.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
            format!("•••• {last}")
        }
        VaultItem::SecureNote { .. } => "Secure note".into(),
        VaultItem::Identity { first_name, last_name, .. } => format!("{first_name} {last_name}").trim().to_string(),
        _ => match (item.username().filter(|u| !u.is_empty()), domain) {
            (Some(u), Some(d)) => format!("{u} · {d}"),
            (Some(u), None) => u.to_string(),
            (None, Some(d)) => d,
            (None, None) => String::new(),
        },
    }
}

pub(super) fn heading(text: impl Into<SharedString>, size: f32, t: &Tok) -> gpui::Div {
    div()
        .font_family(fonts::HEADLINE)
        .font_weight(FontWeight::MEDIUM)
        .text_size(px(size))
        .line_height(relative(1.05))
        .text_color(t.text)
        .child(text.into())
}
