//! Port of `desktopVELA/src/views/QuickSearchWindow.tsx` — the global-shortcut
//! popup: type to search the unlocked vault, arrow keys to move, Enter to open
//! the item in the main window, Esc to dismiss.
//!
//! Window shape matches `src-tauri/src/commands/window.rs`'s builder exactly
//! (640×440, undecorated, always-on-top, centered). One real difference:
//! gpui-ce's `Window` has no always-on-top primitive on Linux (the same gap
//! `titlebar.rs` documents for its pin button), so the popup is a normal
//! window that simply takes focus when opened.
//!
//! Lifecycle also differs, deliberately. The Tauri version *hides* the popup
//! and keeps the webview alive (hiding is cheap there because rebuilding a
//! webview is not), listening for a `quick-search-shown` event to reset its
//! state. Here the window is opened and closed for real each time: a gpui
//! window is cheap to construct, closing frees its GPU surface, and "reset
//! state on show" then falls out for free rather than needing an event hop.

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, size, App, AppContext, Bounds, Context, Entity, EventEmitter, Focusable,
    Global, IntoElement, KeyDownEvent, MouseButton, Render, SharedString, TitlebarOptions, Window,
    WindowBounds, WindowDecorations, WindowHandle, WindowOptions,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::search_items;
use vela_desktop_core::vault::{ItemType, VaultItem};
use vela_desktop_core::AppState;

use crate::fonts;
use crate::icon::icon;

/// Matches the original's `results.slice(0, 8)`.
const MAX_RESULTS: usize = 8;

/// Remembers the live popup so a second shortcut press focuses it instead of
/// stacking a duplicate window.
#[derive(Default)]
struct QuickSearchWindowHandle(Option<WindowHandle<QuickSearch>>);
impl Global for QuickSearchWindowHandle {}

/// What the popup asks the main window to do once the user picks something.
/// Delivered through a `Global` rather than a gpui event because the two live
/// in *different windows* — `cx.subscribe` needs both entities in one window's
/// tree, which these are not.
#[derive(Default)]
pub struct QuickSearchSelection(pub Option<VaultItem>, pub u64);
impl Global for QuickSearchSelection {}

pub fn toggle(cx: &mut App, app_state: Arc<AppState>) {
    if let Some(existing) = cx.try_global::<QuickSearchWindowHandle>().and_then(|h| h.0) {
        // Already open — just raise it. `update` failing means the user
        // already closed that window, in which case fall through and make a
        // fresh one.
        if existing.update(cx, |_, window, _| window.activate_window()).is_ok() {
            return;
        }
    }

    let bounds = Bounds::centered(None, size(px(640.), px(440.)), cx);
    let handle = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("VELA Quick Search".into()),
                appears_transparent: true,
                traffic_light_position: None,
            }),
            window_decorations: Some(WindowDecorations::Client),
            is_movable: true,
            ..Default::default()
        },
        |window, cx| cx.new(|cx| QuickSearch::new(app_state, window, cx)),
    );

    match handle {
        Ok(handle) => {
            handle.update(cx, |_, window, _| window.activate_window()).ok();
            cx.set_global(QuickSearchWindowHandle(Some(handle)));
        }
        Err(e) => tracing::warn!("Failed to open quick-search window: {e}"),
    }
}

pub struct QuickSearch {
    app_state: Arc<AppState>,
    query_state: Entity<EditableTextState>,
    results: Vec<VaultItem>,
    selected: usize,
    /// The vault is locked (or the search otherwise failed) — the original
    /// shows a "press Enter to open VELA" affordance in this state rather
    /// than an empty list.
    locked: bool,
    last_query: String,
    _subscription: gpui::Subscription,
}

pub enum QuickSearchEvent {
    Dismissed,
}
impl EventEmitter<QuickSearchEvent> for QuickSearch {}

impl QuickSearch {
    fn new(app_state: Arc<AppState>, _window: &mut Window, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let query_state = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));
        // The input owns the text; re-run the search whenever it changes.
        // `search_items` is a pure in-memory read over the already-decrypted
        // vault (no network, no disk), so running it inline per keystroke is
        // fine and avoids the original's out-of-order-response guard entirely
        // — there's no await point for responses to race across.
        let subscription = cx.observe(&query_state, |this: &mut Self, _, cx| {
            this.refresh_results(cx);
        });
        Self {
            app_state,
            query_state,
            results: Vec::new(),
            selected: 0,
            locked: false,
            last_query: String::new(),
            _subscription: subscription,
        }
    }

    fn refresh_results(&mut self, cx: &mut Context<Self>) {
        let query = self.query_state.read(cx).as_str().to_string();
        if query == self.last_query {
            return;
        }
        self.last_query = query.clone();

        if query.is_empty() {
            self.results.clear();
            self.selected = 0;
            self.locked = false;
            cx.notify();
            return;
        }

        match search_items(&self.app_state, &query) {
            Ok(mut items) => {
                items.truncate(MAX_RESULTS);
                self.results = items;
                self.locked = false;
            }
            Err(_) => {
                // `search_items` only fails via `require_unlocked`, so this is
                // the locked-vault case the original renders specially.
                self.results.clear();
                self.locked = true;
            }
        }
        self.selected = 0;
        cx.notify();
    }

    fn select(&mut self, item: Option<VaultItem>, window: &mut Window, cx: &mut Context<Self>) {
        // Bumping the counter is what makes repeat selections of the *same*
        // item still register as a fresh request — `observe_global` fires on
        // any set, but RootView needs to tell "picked again" from "unchanged".
        let next = cx.default_global::<QuickSearchSelection>().1.wrapping_add(1);
        cx.set_global(QuickSearchSelection(item, next));
        self.dismiss(window, cx);
    }

    fn dismiss(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        cx.set_global(QuickSearchWindowHandle(None));
        cx.emit(QuickSearchEvent::Dismissed);
        window.remove_window();
    }

    fn on_key_down(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        match event.keystroke.key.as_str() {
            "escape" => {
                cx.stop_propagation();
                self.dismiss(window, cx);
            }
            "down" => {
                cx.stop_propagation();
                if !self.results.is_empty() {
                    self.selected = (self.selected + 1).min(self.results.len() - 1);
                    cx.notify();
                }
            }
            "up" => {
                cx.stop_propagation();
                self.selected = self.selected.saturating_sub(1);
                cx.notify();
            }
            "enter" => {
                cx.stop_propagation();
                if self.locked {
                    self.select(None, window, cx);
                } else if let Some(item) = self.results.get(self.selected).cloned() {
                    self.select(Some(item), window, cx);
                }
            }
            _ => {}
        }
    }
}

fn item_icon_name(item_type: ItemType) -> &'static str {
    match item_type {
        ItemType::Login => "key",
        ItemType::CreditCard => "credit_card",
        ItemType::SecureNote => "note",
        _ => "shield",
    }
}

impl Render for QuickSearch {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        // The popup exists to be typed into the instant it appears (the
        // original sets `autoFocus` on its input for the same reason), and
        // its Esc/arrow/Enter handling below is hung off this same focus
        // handle — so without this the window would open inert.
        let focus_handle = self.query_state.read(cx).focus_handle(cx);
        if !focus_handle.is_focused(window) {
            window.focus(&focus_handle, cx);
        }
        let query_empty = self.query_state.read(cx).as_str().is_empty();
        let selected = self.selected;
        let weak = cx.weak_entity();

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(palette.surface_container)
            .border_1()
            .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
            .font_family(fonts::LABEL)
            .text_color(palette.on_surface)
            .overflow_hidden()
            .track_focus(&self.query_state.read(cx).focus_handle(cx))
            .on_key_down(cx.listener(Self::on_key_down))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .px_6()
                    .py_4()
                    .border_b_1()
                    .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
                    .child(icon("search", px(24.), palette.primary))
                    .child(
                        text_input("quick-search-input")
                            .state(self.query_state.downgrade())
                            .placeholder("Search vault...")
                            .caret_blink_interval_500ms()
                            .flex_1()
                            .whitespace_nowrap()
                            .overflow_x_scroll()
                            .text_lg()
                            .text_color(palette.on_surface),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(palette.outline)
                            .child("ESC to close"),
                    ),
            )
            .child(
                div()
                    .id("quick-search-results")
                    .flex_1()
                    .overflow_y_scroll()
                    .when(self.locked, |el| {
                        el.child(
                            div()
                                .id("quick-search-locked")
                                .w_full()
                                .px_6()
                                .py_8()
                                .flex()
                                .flex_col()
                                .items_center()
                                .gap_2()
                                .text_color(palette.outline)
                                .cursor_pointer()
                                .child(icon("lock", px(36.), palette.outline))
                                .child(
                                    div()
                                        .text_sm()
                                        .child("Vault is locked — press Enter to open VELA"),
                                )
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(|this, _, window, cx| this.select(None, window, cx)),
                                ),
                        )
                    })
                    .when(!self.locked && self.results.is_empty() && !query_empty, |el| {
                        el.child(
                            div()
                                .px_6()
                                .py_8()
                                .flex()
                                .flex_col()
                                .items_center()
                                .gap_2()
                                .text_color(palette.outline)
                                .child(icon("search_off", px(36.), palette.outline))
                                .child(div().text_sm().child("No results found")),
                        )
                    })
                    .children(self.results.iter().enumerate().map(|(index, item)| {
                        let is_selected = index == selected;
                        let name: SharedString = item.name().to_string().into();
                        let url = item.url().map(|u| SharedString::from(u.to_string()));
                        let item_for_click = item.clone();
                        let weak = weak.clone();

                        div()
                            .id(("quick-search-row", index))
                            .w_full()
                            .px_6()
                            .py_3()
                            .flex()
                            .items_center()
                            .gap_4()
                            .cursor_pointer()
                            .when(is_selected, |el| {
                                el.bg(gpui::Hsla { a: 0.1, ..palette.primary })
                                    .text_color(palette.primary)
                            })
                            .child(icon(
                                item_icon_name(item.item_type()),
                                px(20.),
                                if is_selected { palette.primary } else { palette.on_surface_variant },
                            ))
                            .child(
                                div()
                                    .flex_1()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .font_family(fonts::BODY)
                                            .text_color(palette.on_surface)
                                            .child(name),
                                    )
                                    .children(url.map(|url| {
                                        div()
                                            .text_xs()
                                            .text_color(palette.on_surface_variant)
                                            .child(url)
                                    })),
                            )
                            .when(is_selected, |el| {
                                el.child(
                                    div()
                                        .text_xs()
                                        .text_color(palette.primary)
                                        .child("Enter to select"),
                                )
                            })
                            .on_mouse_down(MouseButton::Left, move |_, window, cx| {
                                weak.update(cx, |this, cx| {
                                    this.select(Some(item_for_click.clone()), window, cx);
                                })
                                .ok();
                            })
                    })),
            )
    }
}
