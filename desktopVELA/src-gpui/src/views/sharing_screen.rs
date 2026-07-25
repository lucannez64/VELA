//! Port of `desktopVELA/src/views/SharingScreen.tsx` — received/sent share
//! tabs + a "Share item" modal.
//!
//! `get_shares`/`accept_share`/`decline_share`/`delete_share`/`send_share`
//! are all real (server calls + real vault writes — see
//! `vela_desktop_core::sharing`).
//!
//! Simplification: the original's item picker is an HTML `<select>`; gpui
//! has no native select (same simplification already used for
//! `SettingsScreen`'s theme picker) — replaced with a search box + a
//! vertical list of clickable, alphabetically-sorted item-name rows inside
//! the modal (the search box was added after a real vault with 200+ items
//! made an unsearchable scroll list genuinely unusable).

use std::sync::Arc;

use gpui::{div, prelude::*, px, Context, IntoElement, MouseButton, Render, SharedString, Task, Window};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::get_items;
use vela_desktop_core::sharing::{get_shares, Share, ShareDirection};
use vela_desktop_core::vault::VaultItem;
use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Received,
    Sent,
}

pub struct SharingScreen {
    app_state: Arc<AppState>,
    shares: Option<Vec<Share>>,
    error: Option<SharedString>,
    tab: Tab,
    show_share_modal: bool,
    shareable_items: Vec<VaultItem>,
    selected_item_id: Option<String>,
    recipient_state: gpui::Entity<EditableTextState>,
    share_search_state: gpui::Entity<EditableTextState>,
    action_error: Option<SharedString>,
    sending: bool,
    _pulse_task: Task<()>,
}

impl SharingScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        Self::load(&app_state, cx);

        Self {
            app_state,
            shares: None,
            error: None,
            tab: Tab::Received,
            show_share_modal: false,
            shareable_items: Vec::new(),
            selected_item_id: None,
            recipient_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            share_search_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            action_error: None,
            sending: false,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }

    fn load(app_state: &Arc<AppState>, cx: &mut Context<Self>) {
        let app_state = app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network call (ApiClient/reqwest) — must go through
            // gpui_tokio's bridge onto the actual tokio runtime, not
            // `cx.background_spawn` (a separate thread pool that never
            // entered that runtime and panics on real reactor I/O).
            let result = gpui_tokio::Tokio::spawn(cx, async move { get_shares(&app_state).await }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(shares)) => this.shares = Some(shares),
                    Ok(Err(e)) => this.error = Some(e.into()),
                    Err(e) => this.error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn accept_share(&mut self, share_id: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result =
                gpui_tokio::Tokio::spawn(cx, async move { vela_desktop_core::sharing::accept_share(&app_state, &share_id).await }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => this.action_error = Some(format!("Failed to accept share: {e}").into()),
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn decline_share(&mut self, share_id: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result =
                gpui_tokio::Tokio::spawn(cx, async move { vela_desktop_core::sharing::decline_share(&app_state, &share_id).await }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => this.action_error = Some(format!("Failed to decline share: {e}").into()),
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn delete_share(&mut self, share_id: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result =
                gpui_tokio::Tokio::spawn(cx, async move { vela_desktop_core::sharing::delete_share(&app_state, &share_id).await }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => this.action_error = Some(format!("Failed to remove share: {e}").into()),
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn submit_share(&mut self, cx: &mut Context<Self>) {
        let Some(item_id) = self.selected_item_id.clone() else { return };
        let recipient = self.recipient_state.read(cx).as_str().trim().to_string();
        if recipient.is_empty() {
            self.action_error = Some("Recipient user ID is required".into());
            cx.notify();
            return;
        }

        self.sending = true;
        self.action_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::sharing::send_share(&app_state, &item_id, &recipient, false).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.sending = false;
                match result {
                    Ok(Ok(_share)) => {
                        this.show_share_modal = false;
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => this.action_error = Some(format!("Failed to send share: {e}").into()),
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_share_modal(&mut self, cx: &mut Context<Self>) {
        self.open_share_modal_impl(None, cx);
    }

    /// Opens the share modal with `item_id` already selected — used when
    /// navigating here from `ItemDetail`'s "Share Access" button.
    pub fn open_share_modal_for_item(&mut self, item_id: String, cx: &mut Context<Self>) {
        self.open_share_modal_impl(Some(item_id), cx);
    }

    fn open_share_modal_impl(&mut self, preselect_item_id: Option<String>, cx: &mut Context<Self>) {
        self.show_share_modal = true;
        self.selected_item_id = preselect_item_id;
        self.share_search_state.update(cx, |state, cx| state.emplace("", cx));
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let items = cx.background_spawn(async move { get_items(&app_state) }).await;
            if let Ok(items) = items {
                this.update(cx, |this, cx| {
                    this.shareable_items = items.into_iter().filter(|i| !i.shared()).collect();
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();
        cx.notify();
    }
}

fn type_icon_name(item_type: &str) -> &'static str {
    match item_type {
        "login" => "key",
        "creditcard" | "credit_card" => "credit_card",
        "securenote" | "secure_note" => "note",
        _ => "shield",
    }
}

impl Render for SharingScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let tab = self.tab;
        let filtered: Vec<Share> = self
            .shares
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| match tab {
                Tab::Received => s.direction == ShareDirection::Received,
                Tab::Sent => s.direction == ShareDirection::Sent,
            })
            .collect();

        // The share modal must NOT be a child of the scrollable div below —
        // its `.absolute().inset_0()` backdrop would otherwise resolve
        // against the SCROLLABLE CONTENT's bounds (taller than the real
        // viewport once there are enough shares) instead of the true
        // window, letting clicks/scroll-wheel input reach the list right
        // through the "backdrop". Keeping the modal as a sibling of this
        // OUTER (non-scrolling) container fixes that.
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .id("sharing-scroll")
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
                    .mb_2()
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
                                    .child("Sharing"),
                            )
                            .child(
                                div()
                                    .text_color(palette.on_surface_variant)
                                    .child("Securely share vault items with other VELA users"),
                            ),
                    )
                    .child({
                        let hover_t = animation::hover_transition("share-item-button", window, cx);
                        let t = *hover_t.evaluate(window, cx);
                        let bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, t);
                        div()
                            .id("share-item-button")
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_6()
                            .py_3()
                            .rounded_xl()
                            .bg(bg)
                            .text_color(palette.on_primary)
                            .font_weight(gpui::FontWeight::BOLD)
                            .cursor_pointer()
                            .child(icon("share", px(18.), palette.on_primary))
                            .child("Share item")
                            .on_hover(move |is_hovered, _, cx| {
                                hover_t.update(cx, |v, cx| {
                                    *v = *is_hovered as u8 as f32;
                                    cx.notify();
                                });
                            })
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.open_share_modal(cx);
                            }))
                    }),
            )
            .child(
                div()
                    .flex()
                    .gap_4()
                    .my_6()
                    .child(tab_button(&palette, "Received", tab == Tab::Received, window, cx, |this, cx| {
                        this.tab = Tab::Received;
                        cx.notify();
                    }))
                    .child(tab_button(&palette, "Sent", tab == Tab::Sent, window, cx, |this, cx| {
                        this.tab = Tab::Sent;
                        cx.notify();
                    })),
            )
            .child(
                fonts::tracked_text(if tab == Tab::Received { "Received" } else { "Sent" }, px(12.), 0.1)
                    .font_family(fonts::LABEL)
                    .text_xs()
                    .text_color(palette.outline)
                    .mb_4(),
            )
            .map(|el| match &self.shares {
                None => el.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .py_16()
                        .child(icon("progress_activity", px(36.), palette.primary).opacity(animation::pulse_alpha(1.0))),
                ),
                Some(_) if filtered.is_empty() => el.child(empty_state(&palette, tab)),
                Some(_) => el.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .children(filtered.into_iter().map(|share| match tab {
                            Tab::Received => received_row(&palette, share, window, cx).into_any_element(),
                            Tab::Sent => sent_row(&palette, share, window, cx).into_any_element(),
                        })),
                ),
            })
                    .when_some(self.error.clone(), |el, error| {
                        el.child(div().text_sm().text_color(palette.error).child(error))
                    }),
            )
            .when(self.show_share_modal, |el| el.child(share_modal(&palette, self, window, cx)))
    }
}

fn tab_button(
    palette: &Palette,
    label: &'static str,
    active: bool,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
    on_click: impl Fn(&mut SharingScreen, &mut Context<SharingScreen>) + 'static,
) -> impl IntoElement {
    let base_bg = if active { gpui::Hsla { a: 0.1, ..palette.primary } } else { gpui::transparent_black() };
    let bg = if active {
        base_bg
    } else {
        let hover_t = animation::hover_transition(label, window, cx);
        let t = *hover_t.evaluate(window, cx);
        animation::lerp_hsla(base_bg, palette.surface_container, t)
    };
    let mut el = div()
        .id(label)
        .px_4()
        .py_2()
        .rounded_lg()
        .text_sm()
        .font_family(fonts::LABEL)
        .cursor_pointer()
        .bg(bg)
        .text_color(if active { palette.primary } else { palette.on_surface_variant })
        .child(label);
    if !active {
        let hover_t = animation::hover_transition(label, window, cx);
        el = el.on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        });
    }
    el.on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}

fn empty_state(palette: &Palette, tab: Tab) -> impl IntoElement {
    let (icon_name, text) = match tab {
        Tab::Received => ("inbox", "No items shared with you yet"),
        Tab::Sent => ("send", "You haven't shared any items yet"),
    };
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_2()
        .p_8()
        .rounded_xl()
        .bg(palette.surface_container)
        .child(icon(icon_name, px(36.), palette.outline_variant))
        .child(div().text_color(palette.on_surface_variant).child(text))
}

fn card_row(palette: &Palette) -> gpui::Div {
    div()
        .p_6()
        .rounded_xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.05, ..palette.outline_variant })
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
}

fn icon_box(palette: &Palette, icon_name: &'static str) -> impl IntoElement {
    div()
        .w(px(48.))
        .h(px(48.))
        .flex_shrink_0()
        .rounded_xl()
        .bg(palette.surface_bright)
        .flex()
        .items_center()
        .justify_center()
        .child(icon(icon_name, px(20.), palette.primary))
}

fn received_row(
    palette: &Palette,
    share: Share,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let icon_name = type_icon_name(&share.item_type);
    let date = share.shared_at.format("%b %-d").to_string();
    let name = share.item_name.clone();
    let from = share.from.clone();
    let id = share.id.clone();
    let id2 = id.clone();
    let id3 = id.clone();

    let right: gpui::AnyElement = match share.accepted {
        None => {
            let decline_id = SharedString::from(format!("decline-{id}"));
            let accept_id = SharedString::from(format!("accept-{id}"));
            let decline_hover = animation::hover_transition(decline_id.clone(), window, cx);
            let decline_t = *decline_hover.evaluate(window, cx);
            let decline_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, decline_t);
            let accept_hover = animation::hover_transition(accept_id.clone(), window, cx);
            let accept_t = *accept_hover.evaluate(window, cx);
            let accept_bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, accept_t);
            div()
                .flex()
                .gap_2()
                .flex_shrink_0()
                .child(
                    div()
                        .id(decline_id)
                        .px_4()
                        .py_2()
                        .rounded_lg()
                        .bg(decline_bg)
                        .text_sm()
                        .cursor_pointer()
                        .child("Decline")
                        .on_hover(move |is_hovered, _, cx| {
                            decline_hover.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                            this.decline_share(id2.clone(), cx);
                        })),
                )
                .child(
                    div()
                        .id(accept_id)
                        .px_4()
                        .py_2()
                        .rounded_lg()
                        .bg(accept_bg)
                        .text_color(palette.on_primary)
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_sm()
                        .cursor_pointer()
                        .child("Accept")
                        .on_hover(move |is_hovered, _, cx| {
                            accept_hover.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                            this.accept_share(id3.clone(), cx);
                        })),
                )
                .into_any_element()
        }
        Some(accepted) => {
            let id = share.id.clone();
            let dismiss_id = SharedString::from(format!("dismiss-{id}"));
            let hover_t = animation::hover_transition(dismiss_id.clone(), window, cx);
            let t = *hover_t.evaluate(window, cx);
            let icon_color = animation::lerp_hsla(palette.on_surface_variant, palette.on_surface, t);
            div()
                .flex()
                .items_center()
                .gap_3()
                .flex_shrink_0()
                .child(
                    div()
                        .px_3()
                        .py_1()
                        .rounded_full()
                        .text_xs()
                        .font_family(fonts::LABEL)
                        .bg(if accepted { gpui::Hsla { a: 0.1, ..palette.primary } } else { palette.surface_container_highest })
                        .text_color(if accepted { palette.primary } else { palette.on_surface_variant })
                        .child(if accepted { "Accepted" } else { "Declined" }),
                )
                .child(
                    div()
                        .id(dismiss_id)
                        .cursor_pointer()
                        .child(icon("close", px(16.), icon_color))
                        .on_hover(move |is_hovered, _, cx| {
                            hover_t.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                            this.delete_share(id.clone(), cx);
                        })),
                )
                .into_any_element()
        }
    };

    card_row(palette)
        .child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .min_w(px(0.))
                .child(icon_box(palette, icon_name))
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
                                .child(name),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(format!("From: {from} · {date}")),
                        ),
                ),
        )
        .child(right)
}

fn sent_row(
    palette: &Palette,
    share: Share,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let icon_name = type_icon_name(&share.item_type);
    let date = share.shared_at.format("%b %-d").to_string();
    let name = share.item_name.clone();
    let to = share.to.clone().unwrap_or_default();
    let id = share.id.clone();

    card_row(palette)
        .child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .min_w(px(0.))
                .child(icon_box(palette, icon_name))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .font_family(fonts::BODY)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_color(palette.on_surface)
                                .child(name)
                                .child(
                                    div()
                                        .font_weight(gpui::FontWeight::NORMAL)
                                        .text_color(palette.on_surface_variant)
                                        .child(format!("→ {to}")),
                                ),
                        )
                        .child(div().text_sm().text_color(palette.on_surface_variant).child(date)),
                ),
        )
        .child({
            let row_id = SharedString::from(format!("revoke-{id}"));
            let hover_t = animation::hover_transition(row_id.clone(), window, cx);
            let t = *hover_t.evaluate(window, cx);
            let bg = animation::lerp_hsla(gpui::transparent_black(), gpui::Hsla { a: 0.1, ..palette.error }, t);
            div()
                .id(row_id)
                .flex_shrink_0()
                .px_4()
                .py_2()
                .rounded_lg()
                .bg(bg)
                .text_sm()
                .text_color(palette.error)
                .cursor_pointer()
                .child("Revoke access")
                .on_hover(move |is_hovered, _, cx| {
                    hover_t.update(cx, |v, cx| {
                        *v = *is_hovered as u8 as f32;
                        cx.notify();
                    });
                })
                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                    this.delete_share(id.clone(), cx);
                }))
        })
}

fn share_modal(
    palette: &Palette,
    screen: &SharingScreen,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let selected_name = screen
        .selected_item_id
        .as_ref()
        .and_then(|id| screen.shareable_items.iter().find(|i| i.id() == id))
        .map(|i| i.name().to_string());
    let recipient_empty = screen.recipient_state.read(cx).as_str().trim().is_empty();
    let can_send = screen.selected_item_id.is_some() && !recipient_empty;

    div()
        .id("share-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            this.show_share_modal = false;
            cx.notify();
        }))
        .child(
            div()
                .id("share-modal-body")
                .w(px(420.))
                .max_h(px(560.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(
                            div()
                                .w(px(40.))
                                .h(px(40.))
                                .rounded_xl()
                                .bg(gpui::Hsla { a: 0.1, ..palette.primary })
                                .flex()
                                .items_center()
                                .justify_center()
                                .child(icon("share", px(18.), palette.primary)),
                        )
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Share vault item"),
                        ),
                )
                .child(
                    fonts::tracked_text("ITEM", px(12.), 0.1)
                        .font_family(fonts::LABEL)
                        .text_xs()
                        .text_color(palette.outline),
                )
                .child(
                    text_input("share-item-search")
                        .state(screen.share_search_state.downgrade())
                        .placeholder("Search items…")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_2()
                        .w_full()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                )
                .child({
                    let query = screen.share_search_state.read(cx).as_str().to_lowercase();
                    let mut matching: Vec<&VaultItem> = screen
                        .shareable_items
                        .iter()
                        .filter(|item| query.is_empty() || item.name().to_lowercase().contains(&query))
                        .collect();
                    matching.sort_by_key(|item| item.name().to_lowercase());
                    let no_matches = matching.is_empty();

                    div()
                        .id("share-item-list")
                        .max_h(px(160.))
                        .overflow_y_scroll()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .children(matching.into_iter().map(|item| {
                            let selected = screen.selected_item_id.as_deref() == Some(item.id());
                            let item_id = item.id().to_string();
                            div()
                                .id(SharedString::from(format!("share-item-{}", item.id())))
                                .px_3()
                                .py_2()
                                .rounded_lg()
                                .cursor_pointer()
                                .bg(if selected { gpui::Hsla { a: 0.1, ..palette.primary } } else { palette.surface_container_highest })
                                .text_color(if selected { palette.primary } else { palette.on_surface })
                                .text_sm()
                                .child(item.name().to_string())
                                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                                    this.selected_item_id = Some(item_id.clone());
                                    cx.notify();
                                }))
                        }))
                        .when(no_matches, |el| {
                            el.child(
                                div()
                                    .text_sm()
                                    .text_color(palette.on_surface_variant)
                                    .child(if screen.shareable_items.is_empty() {
                                        "No shareable items"
                                    } else {
                                        "No items match your search"
                                    }),
                            )
                        })
                })
                .when_some(selected_name, |el, name| {
                    el.child(
                        div()
                            .text_xs()
                            .text_color(palette.on_surface_variant)
                            .child(format!("Selected: {name}")),
                    )
                })
                .child(
                    fonts::tracked_text("RECIPIENT (USER ID)", px(12.), 0.1)
                        .font_family(fonts::LABEL)
                        .text_xs()
                        .text_color(palette.outline),
                )
                .child(
                    text_input("share-recipient")
                        .state(screen.recipient_state.downgrade())
                        .placeholder("Enter recipient's VELA user ID")
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
                .when_some(screen.action_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .mt_2()
                        .child({
                            let hover_t = animation::hover_transition("cancel-share", window, cx);
                            let t = *hover_t.evaluate(window, cx);
                            let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);
                            div()
                                .id("cancel-share")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_hover(move |is_hovered, _, cx| {
                                    hover_t.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.show_share_modal = false;
                                    cx.notify();
                                }))
                        })
                        .child({
                            let base_bg = if can_send { palette.primary } else { gpui::Hsla { a: 0.4, ..palette.primary } };
                            let hover_t = animation::hover_transition("send-share", window, cx);
                            let t = if can_send { *hover_t.evaluate(window, cx) } else { 0. };
                            let bg = animation::lerp_hsla(base_bg, gpui::Hsla { a: 0.9, ..palette.primary }, t);
                            div()
                                .id("send-share")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(bg)
                                .text_color(palette.on_primary)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(can_send, |el| el.cursor_pointer())
                                .child(if screen.sending { "Sharing…" } else { "Share" })
                                .when(can_send, |el| {
                                    el.on_hover(move |is_hovered, _, cx| {
                                        hover_t.update(cx, |v, cx| {
                                            *v = *is_hovered as u8 as f32;
                                            cx.notify();
                                        });
                                    })
                                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.submit_share(cx);
                                    }))
                                })
                        }),
                ),
        )
}
