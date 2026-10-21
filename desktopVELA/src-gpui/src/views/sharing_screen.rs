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

#[path="sharing_instrument.rs"]
mod instrument_view;

use std::sync::Arc;

use gpui::{
    div, prelude::*, px, Context, Focusable, IntoElement, MouseButton, Render, SharedString, Task,
    Window,
};
use gpui_elements::editable_text::{EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::get_items;
use vela_desktop_core::share_link::{
    create_share_link, list_share_links, revoke_share_link, CreateShareLinkRequest, ShareLinkRecord,
};
use vela_desktop_core::sharing::{get_shares, Share, ShareDirection};
use vela_desktop_core::vault::VaultItem;
use vela_desktop_core::AppState;

use crate::animation;
use crate::background::GuardedSpawn;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Received,
    Sent,
    Links,
}

pub struct SharingScreen {
    app_state: Arc<AppState>,
    shares: Option<Vec<Share>>,
    confirm_revoke: Option<String>,
    links: Option<Vec<ShareLinkRecord>>,
    error: Option<SharedString>,
    tab: Tab,
    show_share_modal: bool,
    show_link_modal: bool,
    shareable_items: Vec<VaultItem>,
    selected_item_id: Option<String>,
    picking_item: bool,
    picker_active: usize,
    picker_query: String,
    picker_scroll: gpui::UniformListScrollHandle,
    recipient_state: gpui::Entity<EditableTextState>,
    share_search_state: gpui::Entity<EditableTextState>,
    link_passphrase_state: gpui::Entity<EditableTextState>,
    link_ttl_secs: i64,
    link_view_once: bool,
    created_link_url: Option<SharedString>,
    link_copied: bool,
    action_error: Option<SharedString>,
    sending: bool,
    _pulse_task: Task<()>,
}

impl SharingScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify())
            .detach();
        let demo=cx.has_global::<crate::demo::DemoMode>();
        if !demo { Self::load(&app_state, cx); }
        // The preview has no pulse ticker: edits must invalidate the picker
        // and recipient action immediately, including paste and IME input.
        let recipient_state = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));
        let share_search_state = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));
        cx.observe(&recipient_state, |_, _, cx| cx.notify()).detach();
        cx.observe(&share_search_state, |_, _, cx| cx.notify()).detach();

        Self {
            app_state,
            shares: demo.then(Vec::new),
            confirm_revoke: None,
            links: demo.then(Vec::new),
            error: None,
            tab: if crate::instrument::is_instrument(cx) {Tab::Links} else {Tab::Received},
            show_share_modal: false,
            show_link_modal: false,
            shareable_items: Vec::new(),
            selected_item_id: None,
            picking_item: true,
            picker_active: 0,
            picker_query: String::new(),
            picker_scroll: gpui::UniformListScrollHandle::new(),
            recipient_state,
            share_search_state,
            link_passphrase_state: cx
                .new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            link_ttl_secs: 86400,
            link_view_once: false,
            created_link_url: None,
            link_copied: false,
            action_error: None,
            sending: false,
            _pulse_task: if crate::instrument::is_instrument(cx){Task::ready(())}else{animation::spawn_pulse_ticker(cx)},
        }
    }

    fn load(app_state: &Arc<AppState>, cx: &mut Context<Self>) {
        let app_state = app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network call (ApiClient/reqwest) — must go through
            // gpui_tokio's bridge onto the actual tokio runtime, not
            // `cx.background_spawn` (a separate thread pool that never
            // entered that runtime and panics on real reactor I/O).
            let result =
                gpui_tokio::Tokio::spawn(cx, async move { get_shares(&app_state).await }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(shares)) => this.shares = Some(shares),
                    Ok(Err(e)) => this.error = Some(e.into()),
                    Err(e) => this.error = Some(format!("Task failed: {e}").into()),
                }
                this.links = list_share_links(&this.app_state).ok();
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn open_link_modal(&mut self, cx: &mut Context<Self>) {
        self.show_link_modal = true;
        self.selected_item_id = None;
        self.picking_item = true;
        self.share_search_state
            .update(cx, |state, cx| state.emplace("", cx));
        self.created_link_url = None;
        self.link_copied = false;
        self.action_error = None;
        self.link_ttl_secs = 86400;
        self.link_view_once = false;
        self.link_passphrase_state
            .update(cx, |state, cx| state.emplace("", cx));
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let items =
                cx.background_spawn_guarded("load shareable items", async move {
                    get_items(&app_state)
                })
                .await
                .unwrap_or_else(|| Err("Loading the vault failed unexpectedly".to_string()));
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

    fn submit_create_link(&mut self, cx: &mut Context<Self>) {
        if self.sending {
            return;
        }
        let Some(item_id) = self.selected_item_id.clone() else {
            self.action_error = Some("Select an item".into());
            cx.notify();
            return;
        };
        let passphrase = self
            .link_passphrase_state
            .read(cx)
            .as_str()
            .trim()
            .to_string();
        let req = CreateShareLinkRequest {
            item_id,
            ttl_secs: Some(self.link_ttl_secs),
            max_views: None,
            view_once: self.link_view_once,
            passphrase: if passphrase.is_empty() {
                None
            } else {
                Some(passphrase)
            },
            label: None,
        };

        self.sending = true;
        self.action_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result =
                gpui_tokio::Tokio::spawn(
                    cx,
                    async move { create_share_link(&app_state, req).await },
                )
                .await;
            this.update(cx, |this, cx| {
                this.sending = false;
                match result {
                    Ok(Ok(created)) => {
                        this.created_link_url = Some(created.url.into());
                        this.links = list_share_links(&this.app_state).ok();
                    }
                    Ok(Err(e)) => {
                        this.action_error = Some(format!("Failed to create link: {e}").into())
                    }
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn revoke_link(&mut self, link_id: String, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                revoke_share_link(&app_state, &link_id).await
            })
            .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => this.links = list_share_links(&this.app_state).ok(),
                    Ok(Err(e)) => {
                        this.action_error = Some(format!("Failed to revoke link: {e}").into())
                    }
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
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
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::sharing::accept_share(&app_state, &share_id).await
            })
            .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => {
                        this.action_error = Some(format!("Failed to accept share: {e}").into())
                    }
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
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::sharing::decline_share(&app_state, &share_id).await
            })
            .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => {
                        this.action_error = Some(format!("Failed to decline share: {e}").into())
                    }
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
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::sharing::delete_share(&app_state, &share_id).await
            })
            .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(())) => {
                        let app_state = this.app_state.clone();
                        Self::load(&app_state, cx);
                    }
                    Ok(Err(e)) => {
                        this.action_error = Some(format!("Failed to remove share: {e}").into())
                    }
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn submit_share(&mut self, cx: &mut Context<Self>) {
        if self.sending {
            return;
        }
        let Some(item_id) = self.selected_item_id.clone() else {
            return;
        };
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
                vela_desktop_core::sharing::send_share(&app_state, &item_id, &recipient, false)
                    .await
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
                    Ok(Err(e)) => {
                        this.action_error = Some(format!("Failed to send share: {e}").into())
                    }
                    Err(e) => this.action_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn close_dialog(&mut self, cx: &mut Context<Self>) {
        if self.sending {
            return;
        }
        self.show_share_modal = false;
        self.show_link_modal = false;
        cx.notify();
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
        self.picking_item = preselect_item_id.is_none();
        self.selected_item_id = preselect_item_id;
        self.recipient_state
            .update(cx, |state, cx| state.emplace("", cx));
        self.action_error = None;
        self.share_search_state
            .update(cx, |state, cx| state.emplace("", cx));
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let items =
                cx.background_spawn_guarded("load shareable items", async move {
                    get_items(&app_state)
                })
                .await
                .unwrap_or_else(|| Err("Loading the vault failed unexpectedly".to_string()));
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
        let palette = crate::modal::palette(cx);
        let query = self.share_search_state.read(cx).as_str().to_string();
        if self.picker_query != query {
            self.picker_query = query;
            self.picker_active = 0;
            self.picker_scroll
                .scroll_to_item(0, gpui::ScrollStrategy::Top);
        }
        let tab = self.tab;
        let filtered: Vec<Share> = self
            .shares
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| match tab {
                Tab::Received => s.direction == ShareDirection::Received,
                Tab::Sent => s.direction == ShareDirection::Sent,
                Tab::Links => false,
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
            .child(if crate::instrument::is_instrument(cx) { self.render_instrument(window,cx) } else {
                div()
                    .id("sharing-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .bg(palette.surface)
                    .font_family(fonts::LABEL)
                    .p_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .flex_wrap()
                            .gap_4()
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
                                        div().text_color(palette.on_surface_variant).child(
                                            "Securely share vault items with other VELA users",
                                        ),
                                    ),
                            )
                            .child({
                                let hover_t =
                                    animation::hover_transition("share-item-button", window, cx);
                                let t = *hover_t.evaluate(window, cx);
                                let bg = animation::lerp_hsla(
                                    palette.primary,
                                    gpui::Hsla {
                                        a: 0.9,
                                        ..palette.primary
                                    },
                                    t,
                                );
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
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(|this, _, _, cx| {
                                            this.open_share_modal(cx);
                                        }),
                                    )
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_4()
                            .my_6()
                            .child(tab_button(
                                &palette,
                                "Received",
                                tab == Tab::Received,
                                window,
                                cx,
                                |this, cx| {
                                    this.tab = Tab::Received;
                                    cx.notify();
                                },
                            ))
                            .child(tab_button(
                                &palette,
                                "Sent",
                                tab == Tab::Sent,
                                window,
                                cx,
                                |this, cx| {
                                    this.tab = Tab::Sent;
                                    cx.notify();
                                },
                            ))
                            .child(tab_button(
                                &palette,
                                "Links",
                                tab == Tab::Links,
                                window,
                                cx,
                                |this, cx| {
                                    this.tab = Tab::Links;
                                    cx.notify();
                                },
                            )),
                    )
                    .child(if tab == Tab::Links {
                        link_section(&palette, self, window, cx).into_any_element()
                    } else {
                        let label = match tab {
                            Tab::Received => "Received",
                            Tab::Sent => "Sent",
                            Tab::Links => "Links",
                        };
                        let mut section = div().flex().flex_col().child(
                            fonts::tracked_text(label, px(12.), 0.1)
                                .font_family(fonts::LABEL)
                                .text_xs()
                                .text_color(palette.outline)
                                .mb_4(),
                        );
                        section = match &self.shares {
                            None => section.child(
                                div().flex().items_center().justify_center().py_16().child(
                                    icon("progress_activity", px(36.), palette.primary)
                                        .opacity(animation::pulse_alpha(1.0)),
                                ),
                            ),
                            Some(_) if filtered.is_empty() => {
                                section.child(empty_state(&palette, tab))
                            }
                            Some(_) => section.child(div().flex().flex_col().gap_4().children(
                                filtered.into_iter().map(|share| match tab {
                                    Tab::Received => {
                                        received_row(&palette, share, window, cx).into_any_element()
                                    }
                                    Tab::Sent => {
                                        sent_row(&palette, share, window, cx).into_any_element()
                                    }
                                    Tab::Links => div().into_any_element(),
                                }),
                            )),
                        };
                        section.into_any_element()
                    })
                    .when_some(self.error.clone(), |el, error| {
                        el.child(div().text_sm().text_color(palette.error).child(error))
                    }).into_any_element()
            })
            .when(self.show_share_modal, |el| {
                el.child(share_modal(&palette, self, window, cx))
            })
            .when(self.show_link_modal, |el| {
                el.child(link_modal(&palette, self, window, cx))
            })
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
    let base_bg = if active {
        gpui::Hsla {
            a: 0.1,
            ..palette.primary
        }
    } else {
        gpui::transparent_black()
    };
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
        .text_color(if active {
            palette.primary
        } else {
            palette.on_surface_variant
        })
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
    el.on_mouse_down(
        MouseButton::Left,
        cx.listener(move |this, _, _, cx| on_click(this, cx)),
    )
}

fn empty_state(palette: &Palette, tab: Tab) -> impl IntoElement {
    let (icon_name, text) = match tab {
        Tab::Received => ("inbox", "No items shared with you yet"),
        Tab::Sent => ("send", "You haven't shared any items yet"),
        Tab::Links => ("link_off", "No active share links"),
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
        .border_color(gpui::Hsla {
            a: 0.05,
            ..palette.outline_variant
        })
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
            let decline_bg = animation::lerp_hsla(
                palette.surface_container_highest,
                palette.surface_bright,
                decline_t,
            );
            let accept_hover = animation::hover_transition(accept_id.clone(), window, cx);
            let accept_t = *accept_hover.evaluate(window, cx);
            let accept_bg = animation::lerp_hsla(
                palette.primary,
                gpui::Hsla {
                    a: 0.9,
                    ..palette.primary
                },
                accept_t,
            );
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
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.decline_share(id2.clone(), cx);
                            }),
                        ),
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
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.accept_share(id3.clone(), cx);
                            }),
                        ),
                )
                .into_any_element()
        }
        Some(accepted) => {
            let id = share.id.clone();
            let dismiss_id = SharedString::from(format!("dismiss-{id}"));
            let hover_t = animation::hover_transition(dismiss_id.clone(), window, cx);
            let t = *hover_t.evaluate(window, cx);
            let icon_color =
                animation::lerp_hsla(palette.on_surface_variant, palette.on_surface, t);
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
                        .bg(if accepted {
                            gpui::Hsla {
                                a: 0.1,
                                ..palette.primary
                            }
                        } else {
                            palette.surface_container_highest
                        })
                        .text_color(if accepted {
                            palette.primary
                        } else {
                            palette.on_surface_variant
                        })
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
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.delete_share(id.clone(), cx);
                            }),
                        ),
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
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(date),
                        ),
                ),
        )
        .child({
            let row_id = SharedString::from(format!("revoke-{id}"));
            let hover_t = animation::hover_transition(row_id.clone(), window, cx);
            let t = *hover_t.evaluate(window, cx);
            let bg = animation::lerp_hsla(
                gpui::transparent_black(),
                gpui::Hsla {
                    a: 0.1,
                    ..palette.error
                },
                t,
            );
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
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        this.delete_share(id.clone(), cx);
                    }),
                )
        })
}

// ── One-off share links ─────────────────────────────────────────────────────

fn link_section(
    palette: &Palette,
    screen: &SharingScreen,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let links = screen.links.clone().unwrap_or_default();
    let mut section = div()
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    fonts::tracked_text("LINKS FOR PEOPLE WITHOUT VELA", px(12.), 0.1)
                        .font_family(fonts::LABEL)
                        .text_xs()
                        .text_color(palette.outline),
                )
                .child({
                    let hover_t = animation::hover_transition("create-link-button", window, cx);
                    let t = *hover_t.evaluate(window, cx);
                    let bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, t);
                    div()
                        .id("create-link-button")
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_4()
                        .py_2()
                        .rounded_lg()
                        .bg(bg)
                        .text_color(palette.on_primary)
                        .font_weight(gpui::FontWeight::BOLD)
                        .cursor_pointer()
                        .child(icon("link", px(16.), palette.on_primary))
                        .child("Create link")
                        .on_hover(move |is_hovered, _, cx| {
                            hover_t.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.open_link_modal(cx)))
                }),
        )
        .child(
            div()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child("A one-off encrypted link anyone can open in a browser — no account needed. The decryption key is in the link itself and never reaches the server."),
        );

    if links.is_empty() {
        section = section.child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap_2()
                .p_8()
                .rounded_xl()
                .bg(palette.surface_container)
                .child(icon("link_off", px(36.), palette.outline_variant))
                .child(
                    div()
                        .text_color(palette.on_surface_variant)
                        .child("No active share links"),
                ),
        );
    } else {
        section = section.child(
            div().flex().flex_col().gap_4().children(
                links
                    .into_iter()
                    .map(|link| link_row(palette, link, window, cx).into_any_element()),
            ),
        );
    }
    section
}

fn link_row(
    palette: &Palette,
    link: ShareLinkRecord,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let url = link.url.clone();
    let id = link.id.clone();
    let meta = format!(
        "Expires {}{}{}",
        link.expires_at.format("%b %-d"),
        if link.view_once {
            " · view once".to_string()
        } else if let Some(max) = link.max_views {
            format!(" · up to {max} views")
        } else {
            String::new()
        },
        if link.has_passphrase {
            " · passphrase"
        } else {
            ""
        },
    );

    card_row(palette)
        .child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .min_w_0()
                .child(icon_box(palette, "link"))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w_0()
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_color(palette.on_surface)
                                .child(link.item_name.clone()),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(meta),
                        ),
                ),
        )
        .child(
            div()
                .flex()
                .gap_2()
                .flex_shrink_0()
                .child({
                    let copy_id = SharedString::from(format!("copy-link-{id}"));
                    let hover_t = animation::hover_transition(copy_id.clone(), window, cx);
                    let t = *hover_t.evaluate(window, cx);
                    let bg = animation::lerp_hsla(
                        palette.surface_container_highest,
                        palette.surface_bright,
                        t,
                    );
                    div()
                        .id(copy_id)
                        .px_4()
                        .py_2()
                        .rounded_lg()
                        .bg(bg)
                        .text_color(palette.on_surface)
                        .text_sm()
                        .cursor_pointer()
                        .child("Copy link")
                        .on_hover(move |is_hovered, _, cx| {
                            hover_t.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |_this, _, _, cx| {
                                crate::clipboard::copy(cx, "Share link", &url);
                            }),
                        )
                })
                .child({
                    let revoke_id = SharedString::from(format!("revoke-link-{id}"));
                    let hover_t = animation::hover_transition(revoke_id.clone(), window, cx);
                    let t = *hover_t.evaluate(window, cx);
                    let bg = animation::lerp_hsla(
                        gpui::transparent_black(),
                        gpui::Hsla {
                            a: 0.1,
                            ..palette.error
                        },
                        t,
                    );
                    let link_id = id.clone();
                    div()
                        .id(revoke_id)
                        .px_4()
                        .py_2()
                        .rounded_lg()
                        .bg(bg)
                        .text_color(palette.error)
                        .text_sm()
                        .cursor_pointer()
                        .child("Revoke")
                        .on_hover(move |is_hovered, _, cx| {
                            hover_t.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.revoke_link(link_id.clone(), cx);
                            }),
                        )
                }),
        )
}

fn dialog_button(
    id: &'static str,
    label: &'static str,
    primary: bool,
    enabled: bool,
    palette: &Palette,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .debug_selector(move || id.to_owned())
        .flex_1()
        .min_w_0()
        .min_h(px(44.))
        .px_3()
        .py_2()
        .rounded_lg()
        .when(palette.instrument, |el| el.flex_initial().rounded_full().border_1().border_color(palette.outline_variant).text_size(px(13.)))
        .flex()
        .items_center()
        .justify_center()
        .text_sm()
        .font_weight(gpui::FontWeight::BOLD)
        .bg(if primary {
            palette.primary
        } else {
            palette.surface_container_highest
        })
        .text_color(if primary {
            palette.on_primary
        } else {
            palette.on_surface
        })
        .when(enabled, |el| el.cursor_pointer().hover(|el| el.bg(if primary {
            crate::instrument::alpha(palette.primary, 0.85)
        } else { palette.surface_bright })))
        .when(!enabled, |el| el.opacity(0.45))
        .child(label)
}

fn item_picker(
    screen: &SharingScreen,
    for_link: bool,
    window: &Window,
    cx: &mut Context<SharingScreen>,
) -> gpui::AnyElement {
    let palette = crate::modal::palette(cx);
    let query = screen
        .share_search_state
        .read(cx)
        .as_str()
        .trim()
        .to_lowercase();
    let mut matches: Vec<_> = screen
        .shareable_items
        .iter()
        .filter(|item| {
            !for_link || matches!(item, VaultItem::Login { .. } | VaultItem::SecureNote { .. })
        })
        .filter(|item| query.is_empty() || item.name().to_lowercase().contains(&query))
        .map(|item| {
            let (icon, kind) = match item {
                VaultItem::Login { .. } => ("key", "Login"),
                VaultItem::SecureNote { .. } => ("note", "Secure note"),
                _ => ("shield", "Vault item"),
            };
            (item.id().to_string(), item.name().to_string(), icon, kind)
        })
        .collect();
    matches.sort_by_key(|item| item.1.to_lowercase());
    let matches = Arc::new(matches);
    let count = matches.len();
    let weak = cx.weak_entity();
    let keyboard_matches = matches.clone();
    let active = screen.picker_active;
    let list = gpui::uniform_list("share-picker-results", count, move |range, _, _| {
        range
            .map(|ix| {
                let (id, name, glyph, kind) = &matches[ix];
                let id = id.clone();
                let weak = weak.clone();
                let hover_weak = weak.clone();
                div().h(px(64.)).pb_2().child(
                    div()
                        .id(SharedString::from(format!("pick-{id}")))
                        .size_full()
                        .min_w_0()
                        .flex()
                        .items_center()
                        .gap_3()
                        .px_3()
                        .rounded_lg()
                        .when(palette.instrument, |el| el.rounded(px(14.)).border_1().border_color(palette.outline_variant))
                        .cursor_pointer()
                        .bg(if ix == active {
                            gpui::Hsla {
                                a: 0.12,
                                ..palette.primary
                            }
                        } else {
                            palette.surface_container_high
                        })
                        .on_hover(move |hovered, _, app| {
                            if *hovered {
                                hover_weak.update(app, |this, cx| {
                                    if this.picker_active != ix {
                                        this.picker_active = ix;
                                        cx.notify();
                                    }
                                }).ok();
                            }
                        })
                        .hover(|el| el.bg(gpui::Hsla { a: 0.12, ..palette.primary }))
                        .child(icon(glyph, px(20.), palette.primary))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(
                                    div()
                                        .truncate()
                                        .font_weight(gpui::FontWeight::MEDIUM)
                                        .text_color(palette.on_surface)
                                        .child(name.clone()),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(palette.on_surface_variant)
                                        .child(*kind),
                                ),
                        )
                        .child(icon("chevron_right", px(18.), palette.on_surface_variant))
                        .on_mouse_down(MouseButton::Left, move |_, window, app| {
                            weak.update(app, |this, cx| {
                                this.selected_item_id = Some(id.clone());
                                this.picking_item = false;
                                if !for_link {
                                    this.recipient_state
                                        .read(cx)
                                        .focus_handle(cx)
                                        .focus(window, cx);
                                }
                                cx.notify();
                            })
                            .ok();
                        }),
                )
            })
            .collect::<Vec<_>>()
    })
    .debug_selector(|| "share-picker-results".into())
    .track_scroll(&screen.picker_scroll)
    .flex_1()
    .min_h_0()
    .w_full();

    div()
        .size_full()
        .flex()
        .flex_col()
        .gap_2()
        .px_4()
        .py_2()
        .text_size(px(14.))
        .child(
            div()
                .flex_shrink_0()
                .debug_selector(|| "share-picker-search".into())
                .capture_key_down(cx.listener(
                    move |this, event: &gpui::KeyDownEvent, window, cx| {
                        if keyboard_matches.is_empty() {
                            return;
                        }
                        match event.keystroke.key.as_str() {
                            "down" => {
                                this.picker_active =
                                    (this.picker_active + 1).min(keyboard_matches.len() - 1)
                            }
                            "up" => this.picker_active = this.picker_active.saturating_sub(1),
                            "enter" => {
                                this.selected_item_id = Some(
                                    keyboard_matches
                                        [this.picker_active.min(keyboard_matches.len() - 1)]
                                    .0
                                    .clone(),
                                );
                                this.picking_item = false;
                                if !for_link {
                                    this.recipient_state
                                        .read(cx)
                                        .focus_handle(cx)
                                        .focus(window, cx);
                                }
                            }
                            _ => return,
                        }
                        this.picker_scroll
                            .scroll_to_item(this.picker_active, gpui::ScrollStrategy::Nearest);
                        cx.stop_propagation();
                        cx.notify();
                    },
                ))
                .child(
                    crate::ui::text_field("share-picker-search", &screen.share_search_state, &palette).placeholder("Search vault items…"),
                ),
        )
        .when(window.viewport_size().height >= px(640.), |el| {
            el.child(
                div()
                    .flex_shrink_0()
                    .text_xs()
                    .text_color(palette.on_surface_variant)
                    .child(format!(
                        "{count} matching item{} · Select one to continue",
                        if count == 1 { "" } else { "s" }
                    )),
            )
        })
        .when(count > 0, |el| el.child(list))
        .when(count == 0, |el| {
            el.child(
                div()
                    .py_8()
                    .text_sm()
                    .text_color(palette.on_surface_variant)
                    .child(if screen.shareable_items.is_empty() {
                        "No items are available to share."
                    } else {
                        "No matching items. Try another search."
                    }),
            )
        })
        .into_any_element()
}

fn selected_item_summary(
    screen: &SharingScreen,
    palette: &Palette,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let name = screen
        .selected_item_id
        .as_ref()
        .and_then(|id| screen.shareable_items.iter().find(|item| item.id() == id))
        .map(|item| item.name().to_string())
        .unwrap_or_else(|| "Choose an item".into());
    div()
        .flex()
        .items_center()
        .gap_3()
        .p_3()
        .rounded_lg()
        .bg(palette.surface_container_high)
        .child(
            div()
                .flex_1()
                .min_w_0()
                .child(
                    div()
                        .text_xs()
                        .text_color(palette.on_surface_variant)
                        .child("Selected item"),
                )
                .child(
                    div()
                        .text_sm()
                        .truncate()
                        .text_color(palette.on_surface)
                        .child(name),
                ),
        )
        .child(
            div()
                .id("change-share-item")
                .debug_selector(|| "change-share-item".into())
                .flex_shrink_0()
                .px_3()
                .py_2()
                .rounded_lg()
                .bg(palette.surface_container_highest)
                .text_color(palette.primary)
                .text_sm()
                .cursor_pointer()
                .hover(|el| el.bg(palette.surface_bright))
                .child("Change")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, window, cx| {
                        if this.sending {
                            return;
                        }
                        this.picking_item = true;
                        this.share_search_state
                            .update(cx, |s, cx| s.emplace("", cx));
                        this.picker_scroll
                            .scroll_to_item(0, gpui::ScrollStrategy::Top);
                        this.share_search_state
                            .read(cx)
                            .focus_handle(cx)
                            .focus(window, cx);
                        cx.notify();
                    }),
                ),
        )
}

fn share_modal(
    palette: &Palette,
    screen: &SharingScreen,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    sharing_modal(palette, screen, false, window, cx)
}

fn link_modal(
    palette: &Palette,
    screen: &SharingScreen,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    sharing_modal(palette, screen, true, window, cx)
}

fn sharing_modal(
    palette: &Palette,
    screen: &SharingScreen,
    for_link: bool,
    window: &mut Window,
    cx: &mut Context<SharingScreen>,
) -> impl IntoElement {
    let picking = screen.picking_item || screen.selected_item_id.is_none();
    let created = for_link && screen.created_link_url.is_some();
    let title = if palette.instrument && picking {
        if for_link { "Create share link / Choose item" } else { "Share with a VELA user / Choose item" }
    } else if created {
        "Share link ready"
    } else if picking {
        "Choose an item"
    } else if for_link {
        "Create share link"
    } else {
        "Share item"
    };
    let close = crate::modal::close_button("close-sharing-modal", palette)
        .when(screen.sending, |el| el.opacity(0.45))
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|this, _, _, cx| this.close_dialog(cx)),
        );
    let header = crate::modal::header(title, close, palette);
    let body = if created {
        let url = screen.created_link_url.clone().unwrap();
        crate::modal::scroll_body("created-link-content", div()
            .child(div().text_sm().text_color(palette.on_surface_variant).child("Copy this link and send it to your recipient. If you set a passphrase, send that separately."))
            .child(div().id("created-link-url").mt_4().p_3().rounded_lg()
                .bg(palette.surface_container_highest).text_color(palette.on_surface)
                .font_family(fonts::MONO).text_sm().overflow_x_scroll().whitespace_nowrap().child(url.to_string())))
            .into_any_element()
    } else if picking {
        item_picker(screen, for_link, window, cx)
    } else {
        let mut content = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(selected_item_summary(screen, palette, cx));
        if for_link {
            content = content
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("Share with anyone, including people without a VELA account."),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface)
                        .child("Expires after"),
                )
                .child(
                    div().flex().flex_wrap().gap_2().children(
                        [
                            (3600, "1 hour"),
                            (86400, "1 day"),
                            (604800, "7 days"),
                            (2592000, "30 days"),
                        ]
                        .map(|(secs, label)| {
                            let selected = screen.link_ttl_secs == secs;
                            div()
                                .id(SharedString::from(format!("link-ttl-{secs}")))
                                .px_3()
                                .py_2()
                                .rounded_lg()
                                .when(palette.instrument, |el| el.rounded_full().border_1().border_color(palette.outline_variant))
                                .text_sm()
                                .cursor_pointer()
                                .bg(if selected {
                                    gpui::Hsla {
                                        a: 0.15,
                                        ..palette.primary
                                    }
                                } else {
                                    palette.surface_container_highest
                                })
                                .text_color(if selected {
                                    palette.primary
                                } else {
                                    palette.on_surface_variant
                                })
                                .when(!selected, |el| el.hover(|el| el.bg(palette.surface_bright).text_color(palette.on_surface)))
                                .when(palette.instrument && selected, |el| el.bg(palette.primary).text_color(palette.on_primary))
                                .child(label)
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |this, _, _, cx| {
                                        this.link_ttl_secs = secs;
                                        cx.notify();
                                    }),
                                )
                        }),
                    ),
                )
                .child(
                    div()
                        .id("link-view-once")
                        .rounded_lg()
                        .hover(|el| el.bg(palette.surface_container_high))
                        .flex()
                        .items_center()
                        .gap_2()
                        .cursor_pointer()
                        .text_sm()
                        .text_color(palette.on_surface)
                        .child(icon(
                            if screen.link_view_once {
                                "check_box"
                            } else {
                                "check_box_outline_blank"
                            },
                            px(20.),
                            palette.primary,
                        ))
                        .child("Delete after the first view")
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(|this, _, _, cx| {
                                this.link_view_once = !this.link_view_once;
                                cx.notify();
                            }),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface)
                        .child("Passphrase (optional)"),
                )
                .child(
                    crate::ui::text_field("link-passphrase", &screen.link_passphrase_state, palette).placeholder("Add a passphrase").mask_char(Some('*')),
                );
        } else {
            content = content
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("Send an invitation to another VELA user."),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface)
                        .child("Recipient's VELA user ID"),
                )
                .child(
                    div()
                        .on_key_down(crate::keyboard::submit_on_enter(cx, |this, _, cx| {
                            if !this.sending {
                                this.submit_share(cx);
                            }
                        }))
                        .child(
                            crate::ui::text_field("share-recipient", &screen.recipient_state, palette).placeholder("Enter user ID"),
                        ),
                );
        }
        content = content.when_some(screen.action_error.clone(), |el, error| {
            el.child(div().text_sm().text_color(palette.error).child(error))
        });
        crate::modal::scroll_body("sharing-options-content", content).into_any_element()
    };
    let mut footer = div().flex().gap_3().when(palette.instrument, |el| el.justify_end());
    if created {
        footer = footer
            .child(
                dialog_button("done-created-link", "Done", false, true, palette).on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| this.close_dialog(cx)),
                ),
            )
            .child(
                dialog_button(
                    "copy-created-link",
                    if screen.link_copied {
                        "Copied!"
                    } else {
                        "Copy link"
                    },
                    true,
                    true,
                    palette,
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| {
                        if let Some(url) = &this.created_link_url {
                            crate::clipboard::copy(cx, "Share link", url);
                            this.link_copied = true;
                            cx.notify();
                        }
                    }),
                ),
            );
    } else {
        footer = footer.child(
            dialog_button(
                "cancel-sharing-modal",
                "Cancel",
                false,
                !screen.sending,
                palette,
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| this.close_dialog(cx)),
            ),
        );
        if !picking {
            let ready = !screen.sending
                && screen.selected_item_id.is_some()
                && (for_link || !screen.recipient_state.read(cx).as_str().trim().is_empty());
            footer = footer.child(
                dialog_button(
                    "submit-sharing-modal",
                    if screen.sending {
                        "Working…"
                    } else if for_link {
                        "Create link"
                    } else {
                        "Share item"
                    },
                    true,
                    ready,
                    palette,
                )
                .when(ready, |el| {
                    el.on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            if this.sending {
                                return;
                            }
                            if for_link {
                                this.submit_create_link(cx);
                            } else {
                                this.submit_share(cx);
                            }
                        }),
                    )
                }),
            );
        }
    }
    let overlay = crate::modal::backdrop("sharing-modal-backdrop")
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|this, _, _, cx| this.close_dialog(cx)),
        )
        .child(
            crate::modal::frame(
                "sharing-modal-card",
                560.,
                if palette.instrument && !picking { if for_link { 600. } else { 440. } } else { 640. },
                header,
                body,
                footer,
                palette,
            )
            .map(|el| crate::keyboard::trap_tab(el, "sharing-modal-trap", window, cx))
            .on_key_down(cx.listener(|this, event: &gpui::KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" {
                    cx.stop_propagation();
                    this.close_dialog(cx);
                }
            }))
            .map(|card| crate::modal::animate(card, palette.instrument, false)),
        );
    crate::modal::present(window, overlay)
}

#[cfg(test)]
mod modal_tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{point, size, Modifiers, ScrollDelta, ScrollWheelEvent, TestAppContext};
    use vela_desktop_core::vault::VaultMeta;

    fn fixture(state: Arc<AppState>, link: bool, cx: &mut Context<SharingScreen>) -> SharingScreen {
        let field = |cx: &mut Context<SharingScreen>| {
            cx.new(|cx| EditableTextState::new(StringStorage::default(), cx))
        };
        let now = chrono::Utc::now();
        let items = (0..300)
            .map(|i| {
                let name = format!("Item {i:04}");
                VaultItem::SecureNote {
                    meta: VaultMeta {
                rich: Default::default(),
                        id: format!("item-{i}"),
                        name: name.clone(),
                        notes: None,
                        created_at: now,
                        updated_at: now,
                        last_modified_device: None,
                        favorite: false,
                        shared: false,
                        share_recipient: None,
                    },
                    title: name,
                    content: "Synthetic content".into(),
                }
            })
            .collect();
        SharingScreen {
            app_state: state,
            shares: Some(vec![]),
            confirm_revoke: None,
            links: Some(vec![]),
            error: None,
            tab: Tab::Received,
            show_share_modal: !link,
            show_link_modal: link,
            shareable_items: items,
            selected_item_id: None,
            picking_item: true,
            picker_active: 0,
            picker_query: String::new(),
            picker_scroll: gpui::UniformListScrollHandle::new(),
            recipient_state: field(cx),
            share_search_state: field(cx),
            link_passphrase_state: field(cx),
            link_ttl_secs: 86400,
            link_view_once: false,
            created_link_url: None,
            link_copied: false,
            action_error: None,
            sending: false,
            _pulse_task: gpui::Task::ready(()),
        }
    }

    #[gpui::test]
    fn sharing_picker_and_options_work_in_short_windows(cx: &mut TestAppContext) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let directory = tempfile::tempdir().unwrap();
        for link in [false, true] {
            for (width, height) in [(945., 508.), (360., 480.)] {
                let state = ui::state(&directory);
                let (host, cx) = cx.add_window_view(|_, cx| {
                    ui::fonts(cx);
                    ui::Host {
                        child: cx.new(|cx| fixture(state, link, cx)),
                    }
                });
                let screen = cx.update(|_, app| host.read(app).child.clone());
                cx.simulate_resize(size(px(width), px(height)));
                cx.run_until_parked();
                let close = ui::bounds(cx, "close-sharing-modal");
                let footer = ui::bounds(cx, "sharing-modal-card-footer");
                let list = ui::bounds(cx, "share-picker-results");
                assert!(footer.bottom() <= px(height) && list.size.height > px(64.));
                cx.simulate_event(ScrollWheelEvent {
                    position: list.center(),
                    delta: ScrollDelta::Pixels(point(px(0.), px(-800.))),
                    ..Default::default()
                });
                cx.run_until_parked();
                cx.update(|_, app| {
                    let scroll = &screen.read(app).picker_scroll;
                    assert!(
                        scroll.0.borrow().base_handle.offset().y < px(0.),
                        "picker did not scroll at {width}×{height}, link={link}"
                    );
                });
                assert_eq!(ui::bounds(cx, "close-sharing-modal"), close);
                // Search and Enter must select an item without sending a request.
                let search = ui::bounds(cx, "share-picker-search");
                cx.simulate_click(search.center(), Modifiers::default());
                cx.simulate_input("Item 0299");
                cx.simulate_keystrokes("enter");
                cx.run_until_parked();
                cx.update(|_, app| {
                    assert_eq!(
                        screen.read(app).selected_item_id.as_deref(),
                        Some("item-299")
                    );
                    assert!(!screen.read(app).picking_item);
                    assert!(!screen.read(app).sending);
                });
                // The selected item is summarized; the picker does not remain nested in the form.
                assert!(cx.debug_bounds("share-picker-results").is_none());
                let close = ui::bounds(cx, "close-sharing-modal");
                let body = ui::bounds(cx, "sharing-options-content");
                cx.simulate_event(ScrollWheelEvent {
                    position: body.center(),
                    delta: ScrollDelta::Pixels(point(px(0.), px(-2000.))),
                    ..Default::default()
                });
                cx.run_until_parked();
                assert_eq!(ui::bounds(cx, "close-sharing-modal"), close);
                assert_eq!(ui::bounds(cx, "sharing-modal-card-footer"), footer);
                if link {
                    screen.update(cx, |this, cx| {
                        this.created_link_url =
                            Some("https://example.invalid/send?id=layout#synthetic".into());
                        cx.notify();
                    });
                    cx.run_until_parked();
                    let copy = ui::bounds(cx, "copy-created-link");
                    assert!(copy.bottom() <= px(height));
                }
                let close = ui::bounds(cx, "close-sharing-modal");
                cx.simulate_click(close.center(), Modifiers::default());
                cx.run_until_parked();
                cx.update(|_, app| {
                    assert!(!screen.read(app).show_share_modal);
                    assert!(!screen.read(app).show_link_modal);
                });
            }
        }
    }
}
