//! Port of `desktopVELA/src/views/BreachMonitorScreen.tsx` — email/password
//! breach monitoring.
//!
//! `check_email_breach`/`check_all_vault_emails`/`check_all_vault_passwords`
//! are all real now (see `vela_desktop_core::breach`) — real outbound
//! network requests to HaveIBeenPwned/Pwned-Passwords, and the single-email
//! "Check & Add" flow performs a real `add_item` with the result, exactly
//! matching the original's `handleAddEmail`.

use std::sync::Arc;

use chrono::{DateTime, Local, Utc};
use gpui::{div, prelude::*, px, Context, IntoElement, MouseButton, Render, SharedString, Task, Window};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::commands::vault::get_items;
use vela_desktop_core::vault::VaultItem;
use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

pub struct BreachMonitorScreen {
    app_state: Arc<AppState>,
    items: Option<Vec<VaultItem>>,
    error: Option<SharedString>,
    show_add_email: bool,
    email_state: gpui::Entity<EditableTextState>,
    checking_emails: bool,
    checking_passwords: bool,
    adding_email: bool,
    status_message: Option<SharedString>,
    _pulse_task: Task<()>,
}

impl BreachMonitorScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let app_state_clone = app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async move { get_items(&app_state_clone) }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(items) => this.items = Some(items),
                    Err(e) => this.error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();

        Self {
            app_state,
            items: None,
            error: None,
            show_add_email: false,
            email_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            checking_emails: false,
            checking_passwords: false,
            adding_email: false,
            status_message: None,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }

    fn reload_items(&self, cx: &mut Context<Self>) {
        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async move { get_items(&app_state) }).await;
            this.update(cx, |this, cx| {
                if let Ok(items) = result {
                    this.items = Some(items);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn check_all_emails(&mut self, cx: &mut Context<Self>) {
        self.checking_emails = true;
        self.status_message = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::breach::check_all_vault_emails(&app_state).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.checking_emails = false;
                this.status_message = Some(match result {
                    Ok(Ok(total)) => format!("Found {total} total breaches across all vault emails").into(),
                    Ok(Err(e)) => format!("Check failed: {e}").into(),
                    Err(e) => format!("Task failed: {e}").into(),
                });
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn check_all_passwords(&mut self, cx: &mut Context<Self>) {
        self.checking_passwords = true;
        self.status_message = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::breach::check_all_vault_passwords(&app_state).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.checking_passwords = false;
                this.status_message = Some(match result {
                    Ok(Ok(results)) => {
                        let breached = results.iter().filter(|r| r.breached).count();
                        format!("Checked {} passwords — {breached} found in breaches", results.len()).into()
                    }
                    Ok(Err(e)) => format!("Check failed: {e}").into(),
                    Err(e) => format!("Task failed: {e}").into(),
                });
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn check_and_add_email(&mut self, cx: &mut Context<Self>) {
        let email = self.email_state.read(cx).as_str().trim().to_string();
        if email.is_empty() || !email.contains('@') {
            self.status_message = Some("Please enter a valid email address".into());
            cx.notify();
            return;
        }

        self.adding_email = true;
        self.status_message = None;
        cx.notify();

        let app_state = self.app_state.clone();
        let email_for_item = email.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::breach::check_email_breach(&email).await
            })
            .await;
            let breaches = match result {
                Ok(Ok(breaches)) => breaches,
                Ok(Err(e)) => {
                    this.update(cx, |this, cx| {
                        this.adding_email = false;
                        this.status_message = Some(format!("Failed to check email: {e}").into());
                        cx.notify();
                    })
                    .ok();
                    return;
                }
                Err(e) => {
                    this.update(cx, |this, cx| {
                        this.adding_email = false;
                        this.status_message = Some(format!("Task failed: {e}").into());
                        cx.notify();
                    })
                    .ok();
                    return;
                }
            };

            let now = Utc::now();
            let breach_count = breaches.len() as u32;
            let item = VaultItem::BreachMonitor {
                meta: vela_desktop_core::vault::VaultMeta {
                    id: String::new(),
                    name: email_for_item.clone(),
                    notes: None,
                    created_at: now,
                    updated_at: now,
                    last_modified_device: None,
                    favorite: false,
                    shared: false,
                    share_recipient: None,
                },
                email: email_for_item.clone(),
                checked_at: Some(now),
                breach_count,
                breaches,
            };
            let add_result = gpui_tokio::Tokio::spawn(cx, {
                let app_state = app_state.clone();
                async move { vela_desktop_core::commands::vault::add_item(&app_state, item).await }
            })
            .await;

            this.update(cx, |this, cx| {
                this.adding_email = false;
                match add_result {
                    Ok(Ok(_)) => {
                        this.status_message =
                            Some(format!("Added {email_for_item}. Found {breach_count} breaches.").into());
                        this.show_add_email = false;
                        this.email_state.update(cx, |state, cx| state.emplace("", cx));
                        this.reload_items(cx);
                    }
                    Ok(Err(e)) => this.status_message = Some(format!("Failed to save: {e}").into()),
                    Err(e) => this.status_message = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

fn format_checked_at(dt: Option<DateTime<Utc>>) -> String {
    match dt {
        None => "Never".to_string(),
        Some(dt) => dt.with_timezone(&Local).format("%b %-d, %Y, %I:%M %p").to_string(),
    }
}

impl Render for BreachMonitorScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        // Matches the original's `md:` breakpoint (768px) intent for the two
        // title+button header rows on this screen — below it they stack
        // vertically instead of fighting for one row's width. gpui has no
        // CSS media-query equivalent, so this is checked imperatively each
        // render (same pattern as `Sidebar`/`DevicesScreen`). Uses a larger
        // threshold than the original's literal 768px, same reasoning as
        // `DevicesScreen`'s `header_stacked`: a real browser rarely goes
        // below ~700-800px wide, while this undecorated window can be
        // resized much narrower and still needs the buttons reachable.
        let header_stacked = window.viewport_size().width < px(1000.);

        let breach_items: Vec<VaultItem> = self
            .items
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| matches!(i, VaultItem::BreachMonitor { .. }))
            .collect();

        div()
            .id("breach-monitor-scroll")
            .size_full()
            .overflow_y_scroll()
            .bg(palette.surface)
            .font_family(fonts::LABEL)
            .p_8()
            .child({
                let mut header = div().flex().gap_4().mb_8();
                header = if header_stacked {
                    header.flex_col()
                } else {
                    header.flex_row().items_center().justify_between()
                };
                header
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .font_family(fonts::HEADLINE)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_3xl()
                                    .text_color(palette.on_surface)
                                    .child("Breach Monitor"),
                            )
                            .child(
                                div()
                                    .text_color(palette.on_surface_variant)
                                    .child("Monitor your emails for data breaches"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                pill_button(
                                    "check-all-emails",
                                    if self.checking_emails { "Checking…" } else { "Check All Vault Emails" },
                                    palette.primary,
                                    window,
                                    cx,
                                    |this, cx| this.check_all_emails(cx),
                                ),
                            )
                            .child(
                                div()
                                    .id("add-email-button")
                                    .px_4()
                                    .py_2()
                                    .rounded_xl()
                                    .bg(palette.primary)
                                    .text_color(palette.on_primary)
                                    .font_family(fonts::LABEL)
                                    .text_sm()
                                    .cursor_pointer()
                                    .child("+ Add Email")
                                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.show_add_email = true;
                                        cx.notify();
                                    })),
                            ),
                    )
            })
            .when(self.show_add_email, |el| el.child(add_email_form(&palette, self, cx)))
            .map(|el| match &self.items {
                None => el.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .py_16()
                        .child(icon("progress_activity", px(36.), palette.primary).opacity(animation::pulse_alpha(1.0))),
                ),
                Some(_) if breach_items.is_empty() => el.child(no_emails_state(&palette)),
                Some(_) => el.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .children(breach_items.into_iter().map(|item| breach_item_card(&palette, item, cx))),
                ),
            })
            .when_some(self.error.clone(), |el, error| {
                el.child(div().text_sm().text_color(palette.error).child(error))
            })
            .when_some(self.status_message.clone(), |el, message| {
                el.child(div().text_sm().text_color(palette.on_surface_variant).child(message))
            })
            .child(password_breach_section(&palette, header_stacked, self.checking_passwords, window, cx))
            .child(how_it_works(&palette))
    }
}

fn pill_button(
    id: &'static str,
    label: &'static str,
    accent: gpui::Hsla,
    window: &mut Window,
    cx: &mut Context<BreachMonitorScreen>,
    on_click: impl Fn(&mut BreachMonitorScreen, &mut Context<BreachMonitorScreen>) + 'static,
) -> impl IntoElement {
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = animation::lerp_hsla(
        gpui::Hsla { a: 0.1, ..accent },
        gpui::Hsla { a: 0.2, ..accent },
        t,
    );

    div()
        .id(id)
        .px_4()
        .py_2()
        .rounded_xl()
        .bg(bg)
        .text_color(accent)
        .font_family(fonts::LABEL)
        .text_sm()
        .cursor_pointer()
        .child(label)
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}

fn add_email_form(palette: &Palette, screen: &BreachMonitorScreen, cx: &mut Context<BreachMonitorScreen>) -> impl IntoElement {
    div()
        .p_6()
        .mb_6()
        .rounded_xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .font_family(fonts::BODY)
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(palette.on_surface)
                .child("Add email to monitor"),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .child(
                    text_input("breach-email-input")
                        .state(screen.email_state.downgrade())
                        .placeholder("email@example.com")
                        .caret_blink_interval_500ms()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_xl()
                        .p_3()
                        .flex_1()
                        .min_h_auto()
                        .whitespace_nowrap()
                        .overflow_x_scroll(),
                )
                .child(
                    div()
                        .id("check-and-add-email")
                        .px_6()
                        .py_3()
                        .rounded_xl()
                        .bg(palette.primary)
                        .text_color(palette.on_primary)
                        .font_family(fonts::LABEL)
                        .text_sm()
                        .cursor_pointer()
                        .child(if screen.adding_email { "Checking…" } else { "Check & Add" })
                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                            this.check_and_add_email(cx);
                        })),
                )
                .child(
                    div()
                        .id("cancel-add-email")
                        .px_6()
                        .py_3()
                        .rounded_xl()
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .font_family(fonts::LABEL)
                        .text_sm()
                        .cursor_pointer()
                        .child("Cancel")
                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                            this.show_add_email = false;
                            cx.notify();
                        })),
                ),
        )
}

fn no_emails_state(palette: &Palette) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_2()
        .py_16()
        .child(
            div()
                .w(px(64.))
                .h(px(64.))
                .rounded_full()
                .bg(palette.surface_container)
                .flex()
                .items_center()
                .justify_center()
                .mb_2()
                .child(icon("security", px(28.), palette.on_surface_variant)),
        )
        .child(
            div()
                .font_family(fonts::BODY)
                .text_lg()
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(palette.on_surface)
                .child("No emails monitored"),
        )
        .child(
            div()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child("Add an email to start monitoring for breaches"),
        )
}

fn breach_item_card(palette: &Palette, item: VaultItem, cx: &mut Context<BreachMonitorScreen>) -> impl IntoElement {
    let VaultItem::BreachMonitor { email, checked_at, breach_count, breaches, .. } = &item else {
        return div().into_any_element();
    };
    let email = email.clone();
    let checked = format_checked_at(*checked_at);
    let count = *breach_count;
    let email_for_click = email.clone();

    div()
        .p_6()
        .rounded_xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
        .flex()
        .flex_col()
        .gap_4()
        .child(
            div()
                .flex()
                .items_start()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.))
                        .child(
                            div()
                                .font_family(fonts::BODY)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_lg()
                                .text_color(palette.on_surface)
                                .child(email),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(format!("Last checked: {checked}")),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(if count > 0 {
                            div()
                                .px_3()
                                .py_1()
                                .rounded_full()
                                .bg(gpui::Hsla { a: 0.1, ..palette.error })
                                .text_color(palette.error)
                                .text_xs()
                                .font_family(fonts::LABEL)
                                .font_weight(gpui::FontWeight::BOLD)
                                .child(format!("{count} BREACH{}", if count > 1 { "ES" } else { "" }))
                        } else {
                            div()
                                .px_3()
                                .py_1()
                                .rounded_full()
                                .bg(gpui::Hsla { a: 0.1, ..palette.primary })
                                .text_color(palette.primary)
                                .text_xs()
                                .font_family(fonts::LABEL)
                                .font_weight(gpui::FontWeight::BOLD)
                                .child("NO BREACHES")
                        })
                        .child(
                            div()
                                .id(SharedString::from(format!("refresh-{email_for_click}")))
                                .p_2()
                                .rounded_lg()
                                .cursor_pointer()
                                .child(icon("refresh", px(20.), palette.on_surface_variant))
                                .on_mouse_down(MouseButton::Left, cx.listener(move |_this, _, _, _cx| {
                                    tracing::info!(
                                        "Refresh breach check for {email_for_click} — check_email_breach \
                                         not wired (write-path safety)"
                                    );
                                })),
                        ),
                ),
        )
        .when(!breaches.is_empty(), |el| {
            el.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .font_family(fonts::LABEL)
                            .text_xs()
                            .text_color(palette.outline)
                            .child("Breached Sites"),
                    )
                    .children(breaches.iter().map(|breach| {
                        div()
                            .p_4()
                            .rounded_lg()
                            .bg(palette.surface_container_highest)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .items_start()
                                    .justify_between()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .font_family(fonts::BODY)
                                                    .font_weight(gpui::FontWeight::MEDIUM)
                                                    .text_color(palette.on_surface)
                                                    .child(breach.title.clone()),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(palette.on_surface_variant)
                                                    .child(format!("({})", breach.domain)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(palette.on_surface_variant)
                                            .child(breach.breach_date.clone()),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_1()
                                    .children(breach.data_classes.iter().map(|dc| {
                                        div()
                                            .px_2()
                                            .py(px(1.))
                                            .rounded_sm()
                                            .bg(palette.surface_bright)
                                            .text_size(px(10.))
                                            .text_color(palette.on_surface_variant)
                                            .child(dc.clone())
                                    })),
                            )
                    })),
            )
        })
        .into_any_element()
}

fn password_breach_section(
    palette: &Palette,
    header_stacked: bool,
    checking_passwords: bool,
    window: &mut Window,
    cx: &mut Context<BreachMonitorScreen>,
) -> impl IntoElement {
    div()
        .mt_8()
        .pt_8()
        .border_t_1()
        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
        .child({
            let mut header = div().flex().gap_4().mb_6();
            header = if header_stacked {
                header.flex_col()
            } else {
                header.flex_row().items_center().justify_between()
            };
            header
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_2xl()
                                .text_color(palette.on_surface)
                                .child("Password Breach Check"),
                        )
                        .child(
                            div()
                                .text_color(palette.on_surface_variant)
                                .child("Check if your vault passwords have been exposed in data breaches"),
                        ),
                )
                .child(pill_button(
                    "check-all-passwords",
                    if checking_passwords { "Checking…" } else { "Check All Vault Passwords" },
                    gpui::rgb(0xf59e0b).into(),
                    window,
                    cx,
                    |this, cx| this.check_all_passwords(cx),
                ))
        })
}

fn how_it_works(palette: &Palette) -> impl IntoElement {
    div()
        .mt_8()
        .p_4()
        .rounded_xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .font_family(fonts::LABEL)
                .text_xs()
                .text_color(palette.outline)
                .child("How it works"),
        )
        .child(how_it_works_row(palette, "Email monitoring:", "Add emails to check against HaveIBeenPwned for breach data"))
        .child(how_it_works_row(palette, "Password checking:", "Uses k-anonymity — only the first 5 chars of the password hash leave your device"))
        .child(how_it_works_row(palette, "Privacy:", "Passwords are hashed with SHA-1 locally; no plaintext passwords are ever sent"))
        .child(how_it_works_row(palette, "No API key needed:", "Uses the free Pwned Passwords API (rate-limited to 1 req/sec)"))
}

fn how_it_works_row(palette: &Palette, label: &'static str, body: &'static str) -> impl IntoElement {
    // `body` needs `flex_1()` + `min_w(0)` to actually wrap within the
    // remaining row width — without it, this text rendered at its own
    // unwrapped natural width, overflowing straight past the card's right
    // edge instead of wrapping like inline text does in the original.
    div()
        .flex()
        .items_start()
        .gap_1()
        .text_sm()
        .text_color(palette.on_surface_variant)
        .child(
            div()
                .flex_shrink_0()
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(palette.on_surface)
                .child(label),
        )
        .child(div().flex_1().min_w(px(0.)).child(body))
}
