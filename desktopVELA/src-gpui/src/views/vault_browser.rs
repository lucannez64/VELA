//! Port of `desktopVELA/src/views/VaultBrowser.tsx` — searchable/filterable
//! item list + vault health panel. Calls the real (read-only)
//! `vela_desktop_core::commands::vault::{get_items, get_vault_health}` — the
//! same in-memory vault this process unlocked via BiometricGate.
//!
//! Alphabetical "A / B / C" section headers are ported via gpui's
//! variable-height `list` (not `uniform_list`, which requires uniform row
//! height) — header rows are shorter than item rows, matching the original's
//! `rows` grouping in `VaultBrowser.tsx`.
//!
//! Real favicon fetching (`vela_desktop_core::favicon::fetch_favicon`, same
//! DuckDuckGo-then-direct-site-then-HTML-discovery chain the shipped app
//! uses, SSRF-guarded) is wired per-row via the shared `crate::favicon_ui`
//! helper (also used by `ItemDetail`'s header icon) with an in-memory cache
//! — matches the original's `FaviconIcon.tsx` behavior (fallback to the
//! type icon until/unless a real favicon loads).
//!
//! Row copy (password → card number → username priority, matching the
//! original's `handleCopy`) and open-URL (native `open`/xdg-open, matching
//! `handleOpenUrl`) are both real and wired — neither mutates the vault, so
//! both are safe to fully port unlike the write-path actions elsewhere.

use std::sync::Arc;

use gpui::{
    div, list, prelude::*, px, Context, EventEmitter, IntoElement, ListAlignment, ListState,
    MouseButton, Render, SharedString, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::{get_items, get_vault_health, VaultHealth};
use vela_desktop_core::vault::{ItemType, VaultItem};
use vela_desktop_core::AppState;

use crate::animation;
use crate::favicon_ui::{self, FaviconCache};
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;
use crate::views::add_item_modal::{AddItemModal, AddItemModalEvent};

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    All,
    Login,
    CreditCard,
    SecureNote,
}

impl Filter {
    const ALL: [Filter; 4] = [Filter::All, Filter::Login, Filter::CreditCard, Filter::SecureNote];

    fn label(self) -> &'static str {
        match self {
            Filter::All => "All",
            Filter::Login => "Logins",
            Filter::CreditCard => "Cards",
            Filter::SecureNote => "Secure Notes",
        }
    }

    fn matches(self, item_type: ItemType) -> bool {
        match self {
            Filter::All => true,
            Filter::Login => item_type == ItemType::Login,
            Filter::CreditCard => item_type == ItemType::CreditCard,
            Filter::SecureNote => item_type == ItemType::SecureNote,
        }
    }
}

/// Matches the original's `getIcon(item.item_type)`.
fn type_icon_name(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::Login => "key",
        ItemType::CreditCard => "credit_card",
        ItemType::SecureNote => "note",
        _ => "shield",
    }
}

pub enum VaultBrowserEvent {
    ItemSelected(String),
    NavigateToBreachMonitor,
}
impl EventEmitter<VaultBrowserEvent> for VaultBrowser {}

/// One virtualized row: either an "A / B / C" section header or an item.
/// Matches the original's `Row` union in `VaultBrowser.tsx`.
enum Row {
    Header(SharedString),
    Item(VaultItem),
}

/// Groups already-alphabetically-sorted items into header+item rows, one
/// header per distinct leading letter — matches the original's `rows`
/// `useMemo` exactly (group by uppercased first character of the trimmed
/// name, `#` fallback for an empty name, groups sorted alphabetically —
/// already guaranteed here since `filtered_items` pre-sorts by name).
fn build_rows(items: &[VaultItem]) -> Vec<Row> {
    let mut rows = Vec::with_capacity(items.len() * 2);
    let mut current_letter: Option<char> = None;
    for item in items {
        let letter = item
            .name()
            .trim()
            .chars()
            .next()
            .map(|c| c.to_ascii_uppercase())
            .unwrap_or('#');
        if current_letter != Some(letter) {
            rows.push(Row::Header(letter.to_string().into()));
            current_letter = Some(letter);
        }
        rows.push(Row::Item(item.clone()));
    }
    rows
}

pub struct VaultBrowser {
    app_state: Arc<AppState>,
    items: Vec<VaultItem>,
    health: Option<VaultHealth>,
    error: Option<SharedString>,
    filter: Filter,
    search_state: gpui::Entity<EditableTextState>,
    add_item_modal: Option<gpui::Entity<AddItemModal>>,
    _add_item_subscription: Option<gpui::Subscription>,
    list_state: ListState,
    favicon_cache: FaviconCache,
}

impl VaultBrowser {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let search_state = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));

        cx.spawn({
            let app_state = app_state.clone();
            async move |this, cx| {
                let (items, health) = cx
                    .background_spawn(async move {
                        (get_items(&app_state), get_vault_health(&app_state))
                    })
                    .await;
                this.update(cx, |this, cx| {
                    match items {
                        Ok(items) => this.items = items,
                        Err(e) => this.error = Some(e.into()),
                    }
                    this.health = health.ok();
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();

        Self {
            app_state,
            items: Vec::new(),
            health: None,
            error: None,
            filter: Filter::All,
            search_state,
            add_item_modal: None,
            _add_item_subscription: None,
            list_state: ListState::new(0, ListAlignment::Top, px(400.)),
            favicon_cache: favicon_ui::new_cache(),
        }
    }

    pub fn open_add_item_modal(&mut self, cx: &mut Context<Self>) {
        let modal = cx.new({
            let app_state = self.app_state.clone();
            move |cx| AddItemModal::new(app_state, cx)
        });
        let subscription = cx.subscribe(&modal, |this, _modal, event, cx| match event {
            AddItemModalEvent::Close => {
                this.add_item_modal = None;
                this._add_item_subscription = None;
                cx.notify();
            }
            AddItemModalEvent::Created | AddItemModalEvent::Updated => {
                this.add_item_modal = None;
                this._add_item_subscription = None;
                this.reload_items(cx);
                cx.notify();
            }
        });
        self.add_item_modal = Some(modal);
        self._add_item_subscription = Some(subscription);
        cx.notify();
    }

    fn reload_items(&self, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let (items, health) = cx
                .background_spawn(async move { (get_items(&app_state), get_vault_health(&app_state)) })
                .await;
            this.update(cx, |this, cx| {
                match items {
                    Ok(items) => this.items = items,
                    Err(e) => this.error = Some(e.into()),
                }
                this.health = health.ok();
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn filtered_items(&self, cx: &Context<Self>) -> Vec<VaultItem> {
        let query = self.search_state.read(cx).as_str().to_lowercase();
        let mut items: Vec<VaultItem> = self
            .items
            .iter()
            .filter(|item| self.filter.matches(item.item_type()))
            .filter(|item| {
                if query.is_empty() {
                    return true;
                }
                item.name().to_lowercase().contains(&query)
                    || item
                        .username()
                        .map(|u| u.to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || item
                        .url()
                        .map(|u| u.to_lowercase().contains(&query))
                        .unwrap_or(false)
            })
            .cloned()
            .collect();
        items.sort_by(|a, b| a.name().to_lowercase().cmp(&b.name().to_lowercase()));
        items
    }

    fn type_count(&self, filter: Filter) -> usize {
        self.items
            .iter()
            .filter(|item| filter.matches(item.item_type()))
            .count()
    }
}

impl Render for VaultBrowser {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let filtered = self.filtered_items(cx);
        let rows = build_rows(&filtered);
        // Only reset (which invalidates cached measurements/scroll position)
        // when the row count actually changed — row *heights* never change
        // for a given row kind, so a same-length content change (e.g. one
        // search result swapped for another of the same total count) is
        // still measured correctly without a reset.
        if rows.len() != self.list_state.item_count() {
            self.list_state.reset(rows.len());
        }
        // `list`'s per-row render callback only gets `&mut App`, not
        // `Context<Self>` — a weak entity handle plus `WeakEntity::update`
        // is how a row's click handler reaches back into this view's state,
        // matching what `cx.listener` does internally but without needing
        // Context access from inside the callback.
        let weak_view = cx.weak_entity();

        // The add-item modal must NOT be a child of the scrollable div below
        // — it previously was, which meant its `.absolute().inset_0()`
        // backdrop resolved against the SCROLLABLE CONTENT's bounds (which
        // can be much taller than the visible window with 200+ items) rather
        // than the real viewport. That let clicks and scroll-wheel input
        // reach the vault list right through the "backdrop", and the
        // backdrop visibly drifted out of place while scrolling. Wrapping
        // the scrollable content in its own div and keeping the modal as a
        // sibling of this OUTER (non-scrolling) container fixes both.
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .id("vault-browser-scroll")
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
                    .items_center()
                    .gap_4()
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .child(
                                // `top_1_2()` alone (top: 50%) doesn't center
                                // an absolutely-positioned element — gpui has
                                // no transform/translate primitive to shift
                                // it back up by half its own height the way
                                // `-translate-y-1/2` does. Spanning the full
                                // parent height and flex-centering is the
                                // real fix (same issue found in
                                // BiometricGate's password-visibility icon).
                                div()
                                    .absolute()
                                    .left_3()
                                    .top_0()
                                    .bottom_0()
                                    .flex()
                                    .items_center()
                                    .child(icon("search", px(18.), palette.outline_variant)),
                            )
                            .child(
                                text_input("vault-search")
                                    .state(self.search_state.downgrade())
                                    .placeholder("Search vault…")
                                    .caret_blink_interval_500ms()
                                    .bg(palette.surface_container_lowest)
                                    .text_color(palette.on_surface)
                                    .rounded_xl()
                                    .py_3()
                                    .pl(px(44.))
                                    .pr_4()
                                    .w_full()
                                    .min_h_auto()
                                    .whitespace_nowrap()
                                    .overflow_x_scroll(),
                            ),
                    )
                    .child(
                        div()
                            .id("add-item")
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_5()
                            .py_3()
                            .rounded_xl()
                            .bg(palette.primary)
                            .text_color(palette.on_primary)
                            .cursor_pointer()
                            .child(icon("add", px(18.), palette.on_primary))
                            .child(div().font_weight(gpui::FontWeight::BOLD).child("Add Item"))
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.open_add_item_modal(cx);
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_6()
                    .children(Filter::ALL.iter().map(|&filter| {
                        let active = filter == self.filter;
                        let count = self.type_count(filter);
                        let text_color = if active { palette.primary } else { palette.on_surface_variant };
                        let chip_bg = if active {
                            gpui::Hsla { a: 0.1, ..palette.primary }
                        } else {
                            palette.surface_container_highest
                        };
                        div()
                            .id(SharedString::from(format!("filter-{}", filter.label())))
                            .flex()
                            .items_center()
                            .gap_2()
                            .pb_2()
                            .border_b_2()
                            .border_color(if active { palette.primary } else { gpui::transparent_black() })
                            .text_sm()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(text_color)
                            .cursor_pointer()
                            .child(filter.label())
                            .child(
                                div()
                                    .px_2()
                                    .py(px(1.))
                                    .rounded_md()
                                    .text_xs()
                                    .bg(chip_bg)
                                    .child(count.to_string()),
                            )
                            .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                                this.filter = filter;
                                cx.notify();
                            }))
                    })),
            )
            .when_some(self.error.clone(), |el, error| {
                el.child(div().text_sm().text_color(palette.error).child(error))
            })
            .child({
                // `list` (unlike `uniform_list`) virtualizes within an
                // explicit height, so it can't simply be `.flex_1()` inside
                // this now-scrollable page — that would consume all
                // remaining space and push the health panel / Dark Web
                // Monitor card (which the original renders directly below
                // the item grid, in the same scrolling page) out of reach
                // entirely. Bound it to its own content height (capped)
                // instead, matching the original's "whole page scrolls
                // together" behavior. Uses the SAME per-row-kind heights the
                // original's own `useVirtualizer` estimates with (48 for a
                // header, 84 for an item) rather than a flat average — a
                // flat average under-counted item-heavy lists (items are
                // taller than headers), clipping the last row even when the
                // page had visible room left below.
                const HEADER_ROW_HEIGHT: f32 = 48.;
                // 84 (the original's own per-item estimate) + 12 for the
                // `.pb_3()` wrapper this port adds around each item_row —
                // without accounting for that extra padding, the box was
                // consistently a little short, clipping the bottom of the
                // last row even when there was visibly empty space below it.
                const ITEM_ROW_HEIGHT: f32 = 96.;
                const MAX_LIST_HEIGHT: f32 = 600.;
                let content_height: f32 = rows
                    .iter()
                    .map(|row| match row {
                        Row::Header(_) => HEADER_ROW_HEIGHT,
                        Row::Item(_) => ITEM_ROW_HEIGHT,
                    })
                    .sum();
                let list_height = content_height.clamp(HEADER_ROW_HEIGHT, MAX_LIST_HEIGHT);
                let favicon_cache = self.favicon_cache.clone();
                list(
                    self.list_state.clone(),
                    move |ix, window, app| match &rows[ix] {
                        Row::Header(letter) => header_row(&palette, letter).into_any_element(),
                        Row::Item(item) => div()
                            .pb_3()
                            .child(item_row(
                                &palette,
                                item,
                                &favicon_cache,
                                weak_view.clone(),
                                window,
                                app,
                            ))
                            .into_any_element(),
                    },
                )
                .h(px(list_height))
                .w_full()
            })
                    .child(
                        div()
                            .flex()
                            .gap_6()
                            .child(div().flex_1().child(health_panel(&palette, self.health.as_ref())))
                            .child(div().w(px(260.)).child(dark_web_monitor_card(&palette, window, cx))),
                    ),
            )
            .when_some(self.add_item_modal.clone(), |el, modal| el.child(modal))
    }
}

/// Matches the original's header row exactly: big outline-tinted letter +
/// a thin divider line filling the rest of the row's width.
fn header_row(palette: &Palette, letter: &SharedString) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap_4()
        .mb_4()
        .pt_4()
        .child(
            div()
                .font_family(fonts::HEADLINE)
                .font_weight(gpui::FontWeight::BOLD)
                .text_2xl()
                .text_color(gpui::Hsla { a: 0.3, ..palette.outline_variant })
                .child(letter.clone()),
        )
        .child(
            div()
                .flex_1()
                .h(px(1.))
                .bg(gpui::Hsla { a: 0.1, ..palette.outline_variant }),
        )
}

fn item_row(
    palette: &Palette,
    item: &VaultItem,
    favicon_cache: &FaviconCache,
    weak_view: gpui::WeakEntity<VaultBrowser>,
    window: &mut Window,
    app: &mut gpui::App,
) -> impl IntoElement {
    let subtitle: SharedString = match item {
        VaultItem::CreditCard { number, .. } => {
            format!("Ending in •••• {}", &number[number.len().saturating_sub(4)..]).into()
        }
        _ => item
            .username()
            .or(item.url())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "••••••••".to_string())
            .into(),
    };
    let trailing: SharedString = match item {
        VaultItem::CreditCard { exp, .. } => format!("EXP: {exp}").into(),
        _ => "••••••••••••".into(),
    };
    let name: SharedString = item.name().to_string().into();
    let id = item.id().to_string();
    let icon_name = type_icon_name(item.item_type());
    let shared = item.shared();
    let is_received = item.is_received_share();
    // Matches the original's `handleCopy` priority: password, then card
    // number, then username, else nothing to copy.
    let copy_value: Option<(&'static str, String)> = if let Some(pass) = item.password() {
        Some(("Password", pass.to_string()))
    } else if let VaultItem::CreditCard { number, .. } = item {
        (!number.is_empty()).then(|| ("Card number", number.clone()))
    } else {
        item.username().map(|u| ("Username", u.to_string()))
    };
    let open_url: Option<String> = item.url().filter(|u| !u.is_empty()).map(|u| u.to_string());

    let hover_t = animation::hover_transition(format!("item-{id}"), window, app);
    let t = *hover_t.evaluate(window, app);
    let bg = animation::lerp_hsla(palette.surface_container_low, palette.surface_container, t);

    // Matches the original's `FaviconIcon`: only Login items with a
    // non-empty URL ever attempt a real favicon; everything else always
    // shows the type-icon fallback.
    let icon_box = match item {
        VaultItem::Login { url, .. } if !url.is_empty() => {
            let weak_view = weak_view.clone();
            favicon_ui::favicon_or_fallback(
                palette,
                url,
                icon_name,
                px(48.),
                favicon_cache,
                app,
                move |cx| {
                    weak_view.update(cx, |_, cx| cx.notify()).ok();
                },
            )
        }
        _ => favicon_ui::fallback_icon_box(palette, icon_name, px(48.)).into_any_element(),
    };

    div()
        .id(SharedString::from(format!("item-{id}")))
        .w_full()
        .p_4()
        .flex()
        .items_center()
        .justify_between()
        .gap_4()
        .rounded_xl()
        .bg(bg)
        .cursor_pointer()
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .min_w(px(0.))
                .child(icon_box)
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.))
                        .child(
                            div()
                                .font_family(fonts::BODY)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_color(palette.on_surface)
                                .text_ellipsis()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .child(name),
                        )
                        .child(
                            div()
                                .font_family(fonts::MONO)
                                .text_xs()
                                .text_color(gpui::Hsla { a: 0.6, ..palette.on_surface_variant })
                                .text_ellipsis()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .child(subtitle),
                        ),
                ),
        )
        .child(
            div()
                .flex_shrink_0()
                .flex()
                .items_center()
                .gap_4()
                .when(shared, |el| {
                    el.child(shared_badge(palette, is_received))
                })
                .child(
                    fonts::tracked_text(&trailing, px(12.), -0.05)
                        .font_family(fonts::MONO)
                        .text_xs()
                        .text_color(palette.outline_variant),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .opacity(t)
                        .child(
                            div()
                                .id(SharedString::from(format!("copy-{id}")))
                                .cursor_pointer()
                                .child(icon("content_copy", px(16.), palette.primary))
                                .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                    // Row-level `on_mouse_down` below would
                                    // otherwise also fire and navigate to
                                    // ItemDetail — stop it here, same as the
                                    // original's `e.stopPropagation()`.
                                    cx.stop_propagation();
                                    match &copy_value {
                                        Some((label, value)) => crate::clipboard::copy(label, value),
                                        None => tracing::info!("Nothing to copy for this item"),
                                    }
                                }),
                        )
                        .when_some(open_url.clone(), |el, url| {
                            el.child(
                                div()
                                    .id(SharedString::from(format!("open-url-{id}")))
                                    .cursor_pointer()
                                    .child(icon("open_in_new", px(16.), palette.on_surface_variant))
                                    .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                        cx.stop_propagation();
                                        if let Err(e) = open::that(&url) {
                                            tracing::warn!("Failed to open {url}: {e}");
                                        }
                                    }),
                            )
                        }),
                ),
        )
        .on_mouse_down(MouseButton::Left, move |_, _window, cx| {
            weak_view
                .update(cx, |_this, cx| {
                    cx.emit(VaultBrowserEvent::ItemSelected(id.clone()));
                })
                .ok();
        })
}

fn shared_badge(palette: &Palette, is_received: bool) -> impl IntoElement {
    let (icon_name, label, bg, text) = if is_received {
        ("download", "Received", palette.surface_container_highest, palette.secondary)
    } else {
        ("share", "Shared", gpui::Hsla { a: 0.1, ..palette.primary }, palette.primary)
    };
    div()
        .flex()
        .items_center()
        .gap_1()
        .px_2()
        .py(px(1.))
        .rounded_md()
        .bg(bg)
        .text_color(text)
        .text_xs()
        .font_weight(gpui::FontWeight::BOLD)
        .child(icon(icon_name, px(10.), text))
        .child(fonts::tracked_text(label, px(10.), 0.1).text_size(px(10.)))
}

fn health_panel(palette: &Palette, health: Option<&VaultHealth>) -> impl IntoElement {
    let status: SharedString = health
        .map(|h| h.status.clone())
        .unwrap_or_else(|| "LOADING…".to_string())
        .into();
    let score = health.map(|h| h.health_score.round() as i64).unwrap_or(0);
    let weak = health.map(|h| h.weak_passwords).unwrap_or(0);
    let reused = health.map(|h| h.reused_passwords).unwrap_or(0);

    // Matches the original's score-threshold color ramp exactly.
    let score_color = if score >= 90 {
        palette.primary
    } else if score >= 70 {
        gpui::rgb(0x4ade80).into()
    } else if score >= 50 {
        gpui::rgb(0xfbbf24).into()
    } else {
        gpui::rgb(0xf87171).into()
    };

    div()
        .p_6()
        .rounded_2xl()
        .bg(palette.surface_container)
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .text_xl()
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_color(palette.on_surface)
                        .child("Vault Health"),
                )
                .child(
                    div()
                        .px_3()
                        .py_1()
                        .rounded_full()
                        .text_xs()
                        .font_weight(gpui::FontWeight::BOLD)
                        .bg(gpui::Hsla { a: 0.2, ..palette.primary })
                        .text_color(palette.primary)
                        .child(status),
                ),
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
                        .font_family(fonts::LABEL)
                        .text_sm()
                        .child(
                            div().text_color(palette.on_surface_variant).child("SECURITY SCORE"),
                        )
                        .child(
                            div()
                                .font_family(fonts::MONO)
                                .text_color(palette.primary)
                                .child(format!("{score}%")),
                        ),
                )
                .child(
                    div()
                        .h(px(8.))
                        .rounded_full()
                        .bg(palette.surface_container_highest)
                        .overflow_hidden()
                        .child(
                            div()
                                .h_full()
                                .rounded_full()
                                .bg(score_color)
                                .w(gpui::relative((score as f32 / 100.).clamp(0., 1.))),
                        ),
                ),
        )
        .child(
            div()
                .flex()
                .gap_4()
                .child(stat_tile(
                    palette,
                    "WEAK PASSWORDS",
                    weak.to_string(),
                    if weak > 0 { gpui::rgb(0xfbbf24).into() } else { palette.on_surface },
                ))
                .child(stat_tile(
                    palette,
                    "REUSED ITEMS",
                    reused.to_string(),
                    if reused > 0 { palette.accent_violet } else { palette.on_surface },
                )),
        )
}

fn dark_web_monitor_card(
    palette: &Palette,
    window: &mut Window,
    cx: &mut Context<VaultBrowser>,
) -> impl IntoElement {
    let hover_t = animation::hover_transition("run-full-scan", window, cx);
    let t = *hover_t.evaluate(window, cx);
    let gradient = gpui::linear_gradient(
        135.,
        gpui::linear_color_stop(palette.surface_container_highest, 0.),
        gpui::linear_color_stop(palette.surface_container, 1.),
    );

    div()
        .h_full()
        .p_6()
        .rounded_2xl()
        .bg(gradient)
        .border_1()
        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
        .flex()
        .flex_col()
        .justify_between()
        .child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(icon("security", px(28.), palette.primary))
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_color(palette.on_surface)
                        .child("Dark Web Monitor"),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("We scan for leaked credentials in real-time across the obsidian network."),
                ),
        )
        .child(
            div()
                .id("run-full-scan")
                .flex()
                .items_center()
                .gap_2()
                .cursor_pointer()
                .font_family(fonts::LABEL)
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(palette.primary)
                .child(fonts::tracked_text("RUN FULL SCAN", px(12.), 0.2).text_xs())
                .child(
                    div()
                        .child(icon("arrow_forward", px(14.), palette.primary))
                        .ml(px(4. * t)),
                )
                .on_hover(move |is_hovered, _, cx| {
                    hover_t.update(cx, |v, cx| {
                        *v = *is_hovered as u8 as f32;
                        cx.notify();
                    });
                })
                .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                    cx.emit(VaultBrowserEvent::NavigateToBreachMonitor);
                })),
        )
}

fn stat_tile(
    palette: &Palette,
    label: &'static str,
    value: impl Into<SharedString>,
    value_color: gpui::Hsla,
) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .gap_1()
        .p_4()
        .rounded_xl()
        .bg(palette.surface_container_high)
        .child(fonts::tracked_text(label, px(10.), 0.1).text_size(px(10.)).font_family(fonts::LABEL).text_color(palette.outline_variant))
        .child(
            div()
                .font_family(fonts::HEADLINE)
                .text_2xl()
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(value_color)
                .child(value.into()),
        )
}
