//! Port of `desktopVELA/src/views/DevicesScreen.tsx` — enrolled-device list
//! + temporary web sessions.
//!
//! `get_devices`/`list_web_sessions`/`revoke_device`/`revoke_web_session`/
//! `generate_enrollment_code` are all real now (server calls — see
//! `vela_desktop_core::commands::{devices, web_session}`). Enrollment
//! renders the resulting code as a real QR (via `crate::qr`, backed by the
//! `qrcode`+`image` crates) plus an out-of-band verification code and a
//! manual-entry fallback, mirroring the original's QR-carousel modal.

use std::sync::Arc;

use chrono::{DateTime, Local, Utc};
use gpui::{
    div, img, prelude::*, px, Context, Image, ImageSource, IntoElement, MouseButton, Render, SharedString, Task,
    Window,
};
use gpui_elements::editable_text::{text_area, EditableTextState, StringStorage};

use vela_desktop_core::api::WebSessionInfo;
use vela_desktop_core::commands::devices::{get_devices, Device, DeviceType};
use vela_desktop_core::commands::web_session::list_web_sessions;
use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

/// A generated-and-uploaded enrollment ceremony, ready to display. `code` is
/// the full un-chunked locator string (used for the manual "Copy code"
/// fallback); `chunks`/`qr_images` are the QR-sized pieces (usually just
/// one) with their pre-rendered QR images.
#[derive(Clone)]
struct EnrollmentSession {
    code: String,
    verification_code: String,
    chunks: Vec<String>,
    current_chunk: usize,
    qr_images: Vec<Arc<Image>>,
}

pub struct DevicesScreen {
    app_state: Arc<AppState>,
    devices: Option<Vec<Device>>,
    web_sessions: Option<Vec<WebSessionInfo>>,
    error: Option<SharedString>,
    hide_revoked: bool,
    revoke_confirm: Option<Device>,
    revoking: bool,
    revoke_error: Option<SharedString>,
    enrolling: bool,
    enroll_error: Option<SharedString>,
    enrollment: Option<EnrollmentSession>,
    show_web_access_modal: bool,
    web_access_code_state: gpui::Entity<EditableTextState>,
    web_access_mode: WebAccessMode,
    web_access_show_advanced: bool,
    web_access_ttl_secs: i64,
    granting_web_access: bool,
    web_access_error: Option<SharedString>,
    web_access_success: Option<SharedString>,
    _pulse_task: Task<()>,
}

#[derive(Clone, Copy, PartialEq)]
enum WebAccessMode {
    ReadOnly,
    ReadWrite,
}

impl WebAccessMode {
    fn as_str(self) -> &'static str {
        match self {
            WebAccessMode::ReadOnly => "ro",
            WebAccessMode::ReadWrite => "rw",
        }
    }
}

const WEB_ACCESS_TTL_PRESETS: &[(&str, i64)] =
    &[("30 minutes", 30 * 60), ("1 hour", 60 * 60), ("8 hours", 8 * 60 * 60), ("24 hours", 24 * 60 * 60)];

impl DevicesScreen {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        Self::load_devices(&app_state, cx);
        Self::load_web_sessions(&app_state, cx);

        Self {
            app_state,
            devices: None,
            web_sessions: None,
            error: None,
            hide_revoked: false,
            revoke_confirm: None,
            revoking: false,
            revoke_error: None,
            enrolling: false,
            enroll_error: None,
            enrollment: None,
            show_web_access_modal: false,
            web_access_code_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            web_access_mode: WebAccessMode::ReadOnly,
            web_access_show_advanced: false,
            web_access_ttl_secs: WEB_ACCESS_TTL_PRESETS[0].1,
            granting_web_access: false,
            web_access_error: None,
            web_access_success: None,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }

    fn open_web_access_modal(&mut self, cx: &mut Context<Self>) {
        self.web_access_code_state.update(cx, |s, cx| s.emplace("", cx));
        self.web_access_mode = WebAccessMode::ReadOnly;
        self.web_access_show_advanced = false;
        self.web_access_ttl_secs = WEB_ACCESS_TTL_PRESETS[0].1;
        self.web_access_error = None;
        self.show_web_access_modal = true;
        cx.notify();
    }

    fn close_web_access_modal(&mut self, cx: &mut Context<Self>) {
        self.show_web_access_modal = false;
        cx.notify();
    }

    fn approve_web_access(&mut self, cx: &mut Context<Self>) {
        let code = self.web_access_code_state.read(cx).as_str().trim().to_string();
        if code.is_empty() {
            self.web_access_error = Some("Paste the web access code first".into());
            cx.notify();
            return;
        }

        self.granting_web_access = true;
        self.web_access_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        let mode = self.web_access_mode;
        let ttl_secs = self.web_access_ttl_secs;
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::web_session::grant_web_session(&app_state, &code, mode.as_str(), ttl_secs)
                    .await
            })
            .await;
            this.update(cx, |this, cx| {
                this.granting_web_access = false;
                match result {
                    Ok(Ok(res)) => {
                        this.show_web_access_modal = false;
                        let until = DateTime::parse_from_rfc3339(&res.expires_at)
                            .map(|dt| format_date(dt.with_timezone(&Utc)))
                            .unwrap_or(res.expires_at);
                        this.web_access_success = Some(
                            format!(
                                "Web access granted ({}) until {until}",
                                if res.mode == "rw" { "read & write" } else { "read-only" }
                            )
                            .into(),
                        );
                        let app_state = this.app_state.clone();
                        Self::load_web_sessions(&app_state, cx);
                    }
                    Ok(Err(e)) => this.web_access_error = Some(format!("Could not grant web access: {e}").into()),
                    Err(e) => this.web_access_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn start_enrollment(&mut self, cx: &mut Context<Self>) {
        self.enrolling = true;
        self.enroll_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::devices::generate_enrollment_code(&app_state).await
            })
            .await;

            let session = match result {
                Ok(Ok(code)) => {
                    let verification_code =
                        vela_desktop_core::commands::devices::enrollment_verification_code(&code);
                    let chunks = vela_desktop_core::commands::devices::create_enrollment_qr_chunks(&code);
                    let qr_images: Vec<Arc<Image>> = chunks
                        .iter()
                        .filter_map(|chunk| crate::qr::render_qr_image(chunk, 6).map(Arc::new))
                        .collect();
                    Ok(EnrollmentSession { code, verification_code, chunks, current_chunk: 0, qr_images })
                }
                Ok(Err(e)) => Err(e),
                Err(e) => Err(format!("Task failed: {e}")),
            };

            this.update(cx, |this, cx| {
                this.enrolling = false;
                match session {
                    Ok(s) => this.enrollment = Some(s),
                    Err(e) => this.enroll_error = Some(e.into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn close_enrollment(&mut self, cx: &mut Context<Self>) {
        self.enrollment = None;
        self.enroll_error = None;
        let app_state = self.app_state.clone();
        Self::load_devices(&app_state, cx);
        cx.notify();
    }

    fn revoke_device(&mut self, device_id: String, cx: &mut Context<Self>) {
        self.revoking = true;
        self.revoke_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::devices::revoke_device(&app_state, &device_id).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.revoking = false;
                match result {
                    Ok(Ok(())) => {
                        this.revoke_confirm = None;
                        let app_state = this.app_state.clone();
                        Self::load_devices(&app_state, cx);
                    }
                    Ok(Err(e)) => this.revoke_error = Some(e.into()),
                    Err(e) => this.revoke_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn load_devices(app_state: &Arc<AppState>, cx: &mut Context<Self>) {
        let app_state = app_state.clone();
        cx.spawn(async move |this, cx| {
            // Real network call (ApiClient/reqwest) — must run via
            // gpui_tokio's bridge onto the actual tokio runtime, not
            // `cx.background_spawn` (a separate thread pool that never
            // entered that runtime and panics on real reactor I/O).
            let result = gpui_tokio::Tokio::spawn(cx, async move { get_devices(&app_state).await }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(devices)) => this.devices = Some(devices),
                    Ok(Err(e)) => this.error = Some(e.into()),
                    Err(e) => this.error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn load_web_sessions(app_state: &Arc<AppState>, cx: &mut Context<Self>) {
        let app_state = app_state.clone();
        cx.spawn(async move |this, cx| {
            let result =
                gpui_tokio::Tokio::spawn(cx, async move { list_web_sessions(&app_state).await }).await;
            this.update(cx, |this, cx| {
                if let Ok(Ok(sessions)) = result {
                    this.web_sessions = Some(sessions);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

fn device_icon(device_type: &DeviceType) -> &'static str {
    match device_type {
        DeviceType::Desktop => "laptop_mac",
        DeviceType::Mobile => "smartphone",
    }
}

fn format_date(dt: DateTime<Utc>) -> String {
    dt.with_timezone(&Local).format("%b %-d, %Y").to_string()
}

fn format_last_active(dt: Option<DateTime<Utc>>) -> String {
    let Some(dt) = dt else { return "Never".to_string() };
    let hours = (Utc::now() - dt).num_hours();
    if hours < 1 {
        "Just now".to_string()
    } else if hours < 24 {
        format!("{hours} hour{} ago", if hours > 1 { "s" } else { "" })
    } else {
        let days = hours / 24;
        if days < 7 {
            format!("{days} day{} ago", if days > 1 { "s" } else { "" })
        } else {
            format_date(dt)
        }
    }
}

fn format_time_until(dt: DateTime<Utc>) -> String {
    let diff = dt - Utc::now();
    let secs = diff.num_seconds();
    if secs <= 0 {
        return "Expired".to_string();
    }
    let hours = secs / 3600;
    if hours < 1 {
        let minutes = (secs / 60).max(1);
        return format!("in {minutes} minute{}", if minutes > 1 { "s" } else { "" });
    }
    if hours < 24 {
        return format!("in {hours} hour{}", if hours > 1 { "s" } else { "" });
    }
    let days = hours / 24;
    format!("in {days} day{}", if days > 1 { "s" } else { "" })
}

impl Render for DevicesScreen {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let hide_revoked = self.hide_revoked;
        // Matches the original's `sm:` breakpoint (640px) for the device/
        // web-session cards — below it they stack vertically instead of the
        // row layout Tailwind only applies at/above `sm:`. gpui has no CSS
        // media-query equivalent, so this is checked imperatively each
        // render (same pattern already used for `Sidebar`'s icon-only
        // collapse, just a different breakpoint/purpose).
        let narrow = window.viewport_size().width < px(640.);
        // The top "My Devices" + Web access/Enroll buttons row needs more
        // room than a card does — Tailwind's `sm:` number doesn't transfer
        // 1:1 here since a real browser rarely goes below ~700-800px wide,
        // while this undecorated window can be resized much narrower and
        // still needs to look right. 640px left "Enroll new device" clipped
        // off the right edge with no horizontal scroll to reach it at a
        // very ordinary ~945px window width, so this row gets its own,
        // larger threshold instead of reusing `narrow`.
        let header_stacked = window.viewport_size().width < px(1000.);

        let mut display_devices: Vec<Device> = self
            .devices
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|d| !hide_revoked || !d.revoked)
            .collect();
        display_devices.sort_by(|a, b| {
            let status = |d: &Device| if d.pending { 0 } else if d.revoked { 2 } else { 1 };
            status(a).cmp(&status(b)).then(b.enrolled_at.cmp(&a.enrolled_at))
        });
        let device_count = display_devices.len();

        // The revoke-confirm modal must NOT be a child of the scrollable div
        // below — its `.absolute().inset_0()` backdrop would otherwise
        // resolve against the SCROLLABLE CONTENT's bounds (taller than the
        // real viewport once there are enough devices) instead of the true
        // window, letting clicks/scroll-wheel input reach the device list
        // right through the "backdrop". Keeping the modal as a sibling of
        // this OUTER (non-scrolling) container fixes that.
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .id("devices-scroll")
                    .size_full()
                    .overflow_y_scroll()
                    .bg(palette.surface)
                    .font_family(fonts::LABEL)
                    .p_8()
                    .child({
                let mut header_row = div().flex().gap_4().mb_8();
                header_row = if header_stacked {
                    header_row.flex_col()
                } else {
                    header_row.flex_row().items_center().justify_between()
                };
                header_row
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
                                    .child("My Devices"),
                            )
                            .child(
                                div()
                                    .text_color(palette.on_surface_variant)
                                    .child("Manage devices that have access to your vault"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(header_button(&palette, "web-access", "public", "Web access", false, window, cx, |this, cx| {
                                this.open_web_access_modal(cx);
                            }))
                            .child(header_button(&palette, "enroll-device", "add", "Enroll new device", true, window, cx, |this, cx| {
                                this.start_enrollment(cx);
                            })),
                    )
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .mb_4()
                    .child(
                        div()
                            .text_sm()
                            .text_color(palette.on_surface_variant)
                            .child(format!("{device_count} device{}", if device_count != 1 { "s" } else { "" })),
                    )
                    .child(
                        div()
                            .id("hide-revoked")
                            .flex()
                            .items_center()
                            .gap_2()
                            .cursor_pointer()
                            .child(
                                div()
                                    .w(px(16.))
                                    .h(px(16.))
                                    .rounded_md()
                                    .bg(if hide_revoked { palette.primary } else { palette.surface_container_highest })
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .when(hide_revoked, |el| el.child(icon("check", px(12.), palette.on_primary))),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(palette.on_surface_variant)
                                    .child("Hide revoked"),
                            )
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.hide_revoked = !this.hide_revoked;
                                cx.notify();
                            })),
                    ),
            )
            .map(|el| match &self.devices {
                None => el.child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .py_16()
                        .child(icon("progress_activity", px(36.), palette.primary).opacity(animation::pulse_alpha(1.0))),
                ),
                Some(_) => el.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .children(display_devices.into_iter().map(|d| device_card(&palette, d, narrow, window, cx))),
                ),
            })
                    .when_some(self.error.clone(), |el, error| {
                        el.child(div().text_sm().text_color(palette.error).child(error))
                    })
                    .when_some(self.web_access_success.clone(), |el, msg| {
                        el.child(div().text_sm().text_color(palette.primary).child(msg))
                    })
                    .child(web_sessions_section(&palette, self.web_sessions.as_deref(), narrow, window, cx)),
            )
            .when_some(self.revoke_confirm.clone(), |el, device| {
                el.child(revoke_modal(&palette, device, self.revoking, self.revoke_error.clone(), window, cx))
            })
            .when(self.enrolling, |el| el.child(enrollment_loading_modal(&palette)))
            .when_some(
                self.enroll_error.clone().filter(|_| !self.enrolling && self.enrollment.is_none()),
                |el, error| el.child(enrollment_error_modal(&palette, error, window, cx)),
            )
            .when_some(self.enrollment.clone(), |el, session| {
                el.child(enrollment_modal(&palette, session, window, cx))
            })
            .when(self.show_web_access_modal, |el| el.child(web_access_modal(&palette, self, window, cx)))
    }
}

fn header_button(
    palette: &Palette,
    id: &'static str,
    icon_name: &'static str,
    label: &'static str,
    primary: bool,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
    on_click: impl Fn(&mut DevicesScreen, &mut Context<DevicesScreen>) + 'static,
) -> impl IntoElement {
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = if primary {
        animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, t)
    } else {
        animation::lerp_hsla(palette.surface, palette.surface_container_high, t)
    };

    div()
        .id(id)
        .flex()
        .items_center()
        .gap_2()
        .px_5()
        .py_3()
        .rounded_xl()
        .font_weight(gpui::FontWeight::BOLD)
        .cursor_pointer()
        .bg(bg)
        .when(primary, |el| el.text_color(palette.on_primary))
        .when(!primary, |el| {
            el.text_color(palette.on_surface).border_1().border_color(gpui::Hsla {
                a: 0.2,
                ..palette.outline_variant
            })
        })
        .child(icon(icon_name, px(18.), if primary { palette.on_primary } else { palette.on_surface }))
        .child(label)
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}

fn device_card(
    palette: &Palette,
    device: Device,
    narrow: bool,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let icon_name = device_icon(&device.device_type);
    let subtitle = if device.pending {
        format!("Enrollment code generated · Last active: {}", format_last_active(device.last_active))
    } else {
        format!("Enrolled: {} · Last active: {}", format_date(device.enrolled_at), format_last_active(device.last_active))
    };
    let revoke_label = if device.pending {
        "Cancel enrollment"
    } else if device.this_device {
        "Revoke (signs out everywhere)"
    } else {
        "Revoke"
    };
    let revoked = device.revoked;
    let pending = device.pending;
    let name = device.name.clone();
    let this_device = device.this_device;

    let mut card = div()
        .p_6()
        .rounded_xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(if revoked { gpui::Hsla { a: 0.3, ..palette.error } } else { gpui::Hsla { a: 0.05, ..palette.outline_variant } })
        .when(revoked, |el| el.opacity(0.6))
        .flex()
        .gap_3();
    card = if narrow {
        card.flex_col().items_start()
    } else {
        card.flex_row().items_center().justify_between()
    };
    card
        .child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .min_w(px(0.))
                .child(
                    div()
                        .w(px(56.))
                        .h(px(56.))
                        .flex_shrink_0()
                        .rounded_xl()
                        .bg(palette.surface_bright)
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(icon(icon_name, px(24.), palette.primary)),
                )
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
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .font_family(fonts::BODY)
                                        .font_weight(gpui::FontWeight::BOLD)
                                        .text_color(palette.on_surface)
                                        .child(name)
                                        .when(this_device, |el| {
                                            el.child(
                                                div()
                                                    .text_xs()
                                                    .text_color(palette.primary)
                                                    .ml_2()
                                                    .child("(this device)"),
                                            )
                                        }),
                                )
                                .when(revoked, |el| {
                                    el.child(
                                        div()
                                            .px_2()
                                            .py(px(1.))
                                            .rounded_sm()
                                            .bg(gpui::Hsla { a: 0.2, ..palette.error })
                                            .text_color(palette.error)
                                            .text_xs()
                                            .child("Revoked"),
                                    )
                                })
                                .when(pending && !revoked, |el| {
                                    el.child(
                                        div()
                                            .px_2()
                                            .py(px(1.))
                                            .rounded_sm()
                                            .bg(gpui::rgb(0x78350f))
                                            .text_color(gpui::rgb(0xfcd34d))
                                            .text_xs()
                                            .child("Pending"),
                                    )
                                }),
                        )
                        .child(div().text_sm().text_color(palette.on_surface_variant).child(subtitle)),
                ),
        )
        .when(!revoked, |el| {
            let device_for_click = device.clone();
            let id = SharedString::from(format!("revoke-{}", device.id));
            let hover_t = animation::hover_transition(id.clone(), window, cx);
            let t = *hover_t.evaluate(window, cx);
            let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);
            el.child(
                div()
                    .id(id)
                    .flex_shrink_0()
                    .px_4()
                    .py_2()
                    .rounded_lg()
                    .bg(bg)
                    .text_color(palette.error)
                    .text_sm()
                    .cursor_pointer()
                    .child(revoke_label)
                    .on_hover(move |is_hovered, _, cx| {
                        hover_t.update(cx, |v, cx| {
                            *v = *is_hovered as u8 as f32;
                            cx.notify();
                        });
                    })
                    .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                        this.revoke_confirm = Some(device_for_click.clone());
                        cx.notify();
                    })),
            )
        })
}

fn web_sessions_section(
    palette: &Palette,
    sessions: Option<&[WebSessionInfo]>,
    narrow: bool,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let refresh_hover_t = animation::hover_transition("refresh-web-sessions", window, cx);
    let refresh_t = *refresh_hover_t.evaluate(window, cx);
    let refresh_bg = animation::lerp_hsla(gpui::transparent_black(), palette.surface_container_high, refresh_t);

    div()
        .mt_10()
        .child({
            let mut header = div().flex().gap_3().mb_4();
            header = if narrow {
                header.flex_col()
            } else {
                header.flex_row().items_center().justify_between()
            };
            header.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Temporary Web Sessions"),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child("Active browser sessions approved from this account"),
                        ),
                )
                .child(
                    div()
                        .id("refresh-web-sessions")
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_4()
                        .py_2()
                        .rounded_xl()
                        .border_1()
                        .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                        .bg(refresh_bg)
                        .text_color(palette.on_surface)
                        .text_sm()
                        .cursor_pointer()
                        .child(icon("refresh", px(14.), palette.on_surface))
                        .child("Refresh")
                        .on_hover(move |is_hovered, _, cx| {
                            refresh_hover_t.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                            let app_state = this.app_state.clone();
                            DevicesScreen::load_web_sessions(&app_state, cx);
                        })),
                )
        })
        .map(|el| match sessions {
            None | Some([]) => el.child(
                div()
                    .p_6()
                    .rounded_xl()
                    .bg(palette.surface_container)
                    .border_1()
                    .border_color(gpui::Hsla { a: 0.05, ..palette.outline_variant })
                    .text_sm()
                    .text_color(palette.on_surface_variant)
                    .child("No active web sessions."),
            ),
            Some(sessions) => el.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .children(sessions.iter().cloned().map(|ws| web_session_row(palette, ws, narrow, window, cx))),
            ),
        })
}

fn web_session_row(
    palette: &Palette,
    session: WebSessionInfo,
    narrow: bool,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let is_rw = session.mode == "rw";
    let created = DateTime::parse_from_rfc3339(&session.created_at)
        .map(|dt| format_date(dt.with_timezone(&Utc)))
        .unwrap_or_else(|_| session.created_at.clone());
    let expiry = session
        .expires_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| format_time_until(dt.with_timezone(&Utc)));
    let id = session.id.clone();

    let mut row = div()
        .p_5()
        .rounded_xl()
        .bg(palette.surface_container)
        .border_1()
        .border_color(gpui::Hsla { a: 0.05, ..palette.outline_variant })
        .flex()
        .gap_3();
    row = if narrow {
        row.flex_col().items_start()
    } else {
        row.flex_row().items_center().justify_between()
    };
    row
        .child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .min_w(px(0.))
                .child(
                    div()
                        .w(px(44.))
                        .h(px(44.))
                        .flex_shrink_0()
                        .rounded_xl()
                        .bg(palette.surface_bright)
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(icon("language", px(18.), palette.primary)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
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
                                        .child("Web Browser"),
                                )
                                .child(
                                    div()
                                        .px_2()
                                        .py(px(1.))
                                        .rounded_sm()
                                        .text_xs()
                                        .font_family(fonts::LABEL)
                                        .bg(if is_rw {
                                            gpui::Hsla { a: 0.2, ..palette.accent_violet }
                                        } else {
                                            gpui::Hsla { a: 0.2, ..palette.primary }
                                        })
                                        .text_color(if is_rw { palette.accent_violet } else { palette.primary })
                                        .child(if is_rw { "Read-Write" } else { "Read-Only" }),
                                ),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(match expiry {
                                    Some(exp) => format!("Started {created} · Expires {exp}"),
                                    None => format!("Started {created}"),
                                }),
                        ),
                ),
        )
        .child({
            let row_id = SharedString::from(format!("revoke-ws-{id}"));
            let hover_t = animation::hover_transition(row_id.clone(), window, cx);
            let t = *hover_t.evaluate(window, cx);
            let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);
            div()
                .id(row_id)
                .flex_shrink_0()
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
                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                    let app_state = this.app_state.clone();
                    let session_id = id.clone();
                    cx.spawn(async move |this, cx| {
                        let result = gpui_tokio::Tokio::spawn(cx, async move {
                            vela_desktop_core::commands::web_session::revoke_web_session(&app_state, &session_id)
                                .await
                        })
                        .await;
                        this.update(cx, |this, cx| {
                            match result {
                                Ok(Ok(())) => {
                                    let app_state = this.app_state.clone();
                                    DevicesScreen::load_web_sessions(&app_state, cx);
                                }
                                Ok(Err(e)) => this.error = Some(format!("Failed to revoke session: {e}").into()),
                                Err(e) => this.error = Some(format!("Task failed: {e}").into()),
                            }
                            cx.notify();
                        })
                        .ok();
                    })
                    .detach();
                }))
        })
}

fn revoke_modal(
    palette: &Palette,
    device: Device,
    revoking: bool,
    revoke_error: Option<SharedString>,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let title = if device.pending { "Cancel pending enrollment?".to_string() } else { format!("Revoke {}?", device.name) };
    let body = if device.pending {
        "This deletes the unused enrollment slot. The code will no longer work."
    } else {
        "This will immediately sign out that device and prevent it from accessing your vault. \
         It cannot be undone — the device must be re-enrolled to regain access."
    };
    let confirm_label = if device.pending { "Cancel enrollment" } else { "Revoke device" };
    let device_id = device.id.clone();

    div()
        .id("revoke-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            this.revoke_confirm = None;
            cx.notify();
        }))
        .child(
            div()
                .id("revoke-modal-body")
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
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_xl()
                        .text_color(palette.on_surface)
                        .child(title),
                )
                .child(div().text_sm().text_color(palette.on_surface_variant).child(body))
                .when_some(revoke_error, |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child({
                            let hover_t = animation::hover_transition("cancel-revoke", window, cx);
                            let t = *hover_t.evaluate(window, cx);
                            let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);
                            div()
                                .id("cancel-revoke")
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
                                    this.revoke_confirm = None;
                                    cx.notify();
                                }))
                        })
                        .child({
                            let hover_t = animation::hover_transition("confirm-revoke", window, cx);
                            let t = *hover_t.evaluate(window, cx);
                            let bg = animation::lerp_hsla(palette.error, gpui::Hsla { a: 0.85, ..palette.error }, t);
                            div()
                                .id("confirm-revoke")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(bg)
                                .text_color(gpui::white())
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child(if revoking { "Revoking…" } else { confirm_label })
                                .on_hover(move |is_hovered, _, cx| {
                                    hover_t.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                                    this.revoke_device(device_id.clone(), cx);
                                }))
                        }),
                ),
        )
}

/// Shown while `generate_enrollment_code`'s real network/crypto ceremony is
/// in flight — no dismiss action, since the ceremony can't be cancelled
/// mid-flight (the server call either lands or fails on its own).
fn enrollment_loading_modal(palette: &Palette) -> impl IntoElement {
    div()
        .id("enrollment-loading-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .w(px(360.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .items_center()
                .gap_4()
                .child(icon("progress_activity", px(32.), palette.primary).opacity(animation::pulse_alpha(1.0)))
                .child(
                    div()
                        .text_color(palette.on_surface)
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .child("Generating enrollment code…"),
                ),
        )
}

fn enrollment_error_modal(
    palette: &Palette,
    error: SharedString,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let hover_t = animation::hover_transition("dismiss-enroll-error", window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t);

    div()
        .id("enrollment-error-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            this.enroll_error = None;
            cx.notify();
        }))
        .child(
            div()
                .id("enrollment-error-body")
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
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_xl()
                        .text_color(palette.on_surface)
                        .child("Couldn't enroll device"),
                )
                .child(div().text_sm().text_color(palette.error).child(error))
                .child(
                    div()
                        .id("dismiss-enroll-error")
                        .py_3()
                        .rounded_xl()
                        .flex()
                        .items_center()
                        .justify_center()
                        .bg(bg)
                        .text_color(palette.on_surface)
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .cursor_pointer()
                        .child("Close")
                        .on_hover(move |is_hovered, _, cx| {
                            hover_t.update(cx, |v, cx| {
                                *v = *is_hovered as u8 as f32;
                                cx.notify();
                            });
                        })
                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                            this.enroll_error = None;
                            cx.notify();
                        })),
                ),
        )
}

/// The real QR-carousel modal — shown after `generate_enrollment_code`
/// succeeds. Displays the current chunk's QR image (rendered via
/// `crate::qr::render_qr_image`), the out-of-band verification code (which
/// the enrolling device and this device must show identically — confirms
/// no MITM tampered with the enrollment package), prev/next navigation when
/// the code didn't fit in a single QR, and a manual "Copy code" fallback
/// for when scanning isn't possible.
fn enrollment_modal(
    palette: &Palette,
    session: EnrollmentSession,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let total = session.chunks.len();
    let current = session.current_chunk;
    let multi = total > 1;
    let qr_image = session.qr_images.get(current).cloned();
    let code_for_copy = session.code.clone();

    let copy_hover_t = animation::hover_transition("enroll-copy-code", window, cx);
    let copy_t = *copy_hover_t.evaluate(window, cx);
    let copy_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, copy_t);

    let done_hover_t = animation::hover_transition("enroll-done", window, cx);
    let done_t = *done_hover_t.evaluate(window, cx);
    let done_bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, done_t);

    div()
        .id("enrollment-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .id("enrollment-modal-body")
                .w(px(420.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                .flex()
                .flex_col()
                .items_center()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    div()
                        .w_full()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_xl()
                        .text_color(palette.on_surface)
                        .child("Enroll New Device"),
                )
                .child(
                    div()
                        .w_full()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("Scan this code on the new device, or enter it manually. Confirm the verification code matches on both devices before continuing."),
                )
                .child(match qr_image {
                    Some(image) => div()
                        .p_3()
                        .rounded_xl()
                        .bg(gpui::white())
                        .child(img(ImageSource::Image(image)).w(px(220.)).h(px(220.)))
                        .into_any_element(),
                    None => div()
                        .w(px(220.))
                        .h(px(220.))
                        .rounded_xl()
                        .bg(palette.surface_bright)
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("QR unavailable — use manual code below")
                        .into_any_element(),
                })
                .when(multi, |el| {
                    let can_prev = current > 0;
                    let can_next = current + 1 < total;
                    el.child(
                        div()
                            .flex()
                            .items_center()
                            .gap_4()
                            .child(
                                div()
                                    .id("enroll-qr-prev")
                                    .w(px(32.))
                                    .h(px(32.))
                                    .rounded_full()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .bg(palette.surface_container_highest)
                                    .when(can_prev, |el| el.cursor_pointer())
                                    .opacity(if can_prev { 1.0 } else { 0.4 })
                                    .child(icon("chevron_left", px(16.), palette.on_surface))
                                    .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                                        if let Some(s) = this.enrollment.as_mut() {
                                            s.current_chunk = s.current_chunk.saturating_sub(1);
                                        }
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(palette.on_surface_variant)
                                    .child(format!("Part {} of {total}", current + 1)),
                            )
                            .child(
                                div()
                                    .id("enroll-qr-next")
                                    .w(px(32.))
                                    .h(px(32.))
                                    .rounded_full()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .bg(palette.surface_container_highest)
                                    .when(can_next, |el| el.cursor_pointer())
                                    .opacity(if can_next { 1.0 } else { 0.4 })
                                    .child(icon("chevron_right", px(16.), palette.on_surface))
                                    .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                                        if let Some(s) = this.enrollment.as_mut() {
                                            if s.current_chunk + 1 < total {
                                                s.current_chunk += 1;
                                            }
                                        }
                                        cx.notify();
                                    })),
                            ),
                    )
                })
                .child(
                    div()
                        .w_full()
                        .flex()
                        .flex_col()
                        .items_center()
                        .gap_1()
                        .child(fonts::tracked_text("VERIFICATION CODE", px(10.), 0.2).text_color(palette.on_surface_variant))
                        .child(
                            fonts::tracked_text(&session.verification_code, px(22.), 0.1)
                                .font_family(fonts::MONO)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_color(palette.on_surface),
                        ),
                )
                .child(
                    div()
                        .w_full()
                        .flex()
                        .gap_3()
                        .child(
                            div()
                                .id("enroll-copy-code")
                                .flex_1()
                                .flex()
                                .items_center()
                                .justify_center()
                                .gap_2()
                                .py_3()
                                .rounded_xl()
                                .bg(copy_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child(icon("content_copy", px(16.), palette.on_surface))
                                .child("Copy code")
                                .on_hover(move |is_hovered, _, cx| {
                                    copy_hover_t.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                    crate::clipboard::copy(cx, "Enrollment code", &code_for_copy);
                                }),
                        )
                        .child(
                            div()
                                .id("enroll-done")
                                .flex_1()
                                .flex()
                                .items_center()
                                .justify_center()
                                .py_3()
                                .rounded_xl()
                                .bg(done_bg)
                                .text_color(palette.on_primary)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Done")
                                .on_hover(move |is_hovered, _, cx| {
                                    done_hover_t.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.close_enrollment(cx);
                                })),
                        ),
                ),
        )
}

/// Port of `WebAccessModal.tsx` — approve a browser's ephemeral, revocable
/// web access to this vault by pasting the code it displays. Real:
/// `approve_web_access` calls `vela_desktop_core::commands::web_session::
/// grant_web_session`, which seals a read-only vault snapshot (or, in
/// "advanced" read-write mode, the live master seed) to the browser's
/// ephemeral key.
fn web_access_modal(
    palette: &Palette,
    screen: &DevicesScreen,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
) -> impl IntoElement {
    let show_advanced = screen.web_access_show_advanced;
    let mode = screen.web_access_mode;
    let ttl_secs = screen.web_access_ttl_secs;
    let granting = screen.granting_web_access;

    let cancel_hover = animation::hover_transition("web-access-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    let approve_hover = animation::hover_transition("web-access-approve", window, cx);
    let approve_t = *approve_hover.evaluate(window, cx);
    let approve_bg = animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, approve_t);

    div()
        .id("web-access-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_web_access_modal(cx)))
        .child(
            div()
                .id("web-access-modal-body")
                .map(|el| crate::keyboard::trap_tab(el, "web-access-modal-trap", window, cx))
                .w(px(520.))
                .max_h(px(640.))
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
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_xl()
                        .text_color(palette.on_surface)
                        .child("Approve web access"),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(
                            "Temporarily open this vault in a browser, with no install and no \
                             permanent device. Access expires automatically and can be revoked \
                             any time.",
                        ),
                )
                .child(fonts::tracked_text("WEB ACCESS CODE", px(10.), 0.15).text_xs().text_color(palette.outline))
                .child(
                    text_area("web-access-code-input")
                        .state(screen.web_access_code_state.downgrade())
                        .placeholder("Paste the code shown by the web page…")
                        .font_family(fonts::MONO)
                        .bg(palette.surface_container_highest)
                        .text_color(palette.on_surface)
                        .rounded_lg()
                        .p_3()
                        .w_full()
                        .min_h(px(72.))
                        .max_h(px(96.))
                        .whitespace_normal()
                        .overflow_y_scroll(),
                )
                .child(fonts::tracked_text("DURATION", px(10.), 0.15).text_xs().text_color(palette.outline))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .children(WEB_ACCESS_TTL_PRESETS.iter().map(|(label, secs)| {
                            let selected = *secs == ttl_secs;
                            let id = SharedString::from(format!("web-access-ttl-{secs}"));
                            let hover_t = animation::hover_transition(id.clone(), window, cx);
                            let t = *hover_t.evaluate(window, cx);
                            let bg = if selected {
                                palette.primary
                            } else {
                                animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t)
                            };
                            let secs = *secs;
                            div()
                                .id(id)
                                .px_4()
                                .py_2()
                                .rounded_lg()
                                .bg(bg)
                                .text_sm()
                                .cursor_pointer()
                                .text_color(if selected { palette.on_primary } else { palette.on_surface })
                                .child(*label)
                                .on_hover(move |is_hovered, _, cx| {
                                    hover_t.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                                    this.web_access_ttl_secs = secs;
                                    cx.notify();
                                }))
                        })),
                )
                .when(!show_advanced, |el| {
                    el.child(
                        div()
                            .id("web-access-show-advanced")
                            .text_sm()
                            .text_color(palette.on_surface_variant)
                            .cursor_pointer()
                            .child("Advanced — I trust this device")
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.web_access_show_advanced = true;
                                cx.notify();
                            })),
                    )
                })
                .when(show_advanced, |el| {
                    let ro_selected = mode == WebAccessMode::ReadOnly;
                    let rw_selected = mode == WebAccessMode::ReadWrite;
                    el.child(fonts::tracked_text("MODE", px(10.), 0.15).text_xs().text_color(palette.outline)).child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .child(mode_button(palette, "web-access-mode-ro", "Read-only (safer)", ro_selected, window, cx, WebAccessMode::ReadOnly))
                                    .child(mode_button(palette, "web-access-mode-rw", "Read & write", rw_selected, window, cx, WebAccessMode::ReadWrite)),
                            )
                            .when(rw_selected, |el| {
                                el.child(
                                    div().text_xs().text_color(gpui::rgb(0xf59e0b)).child(
                                        "Read & write sends this device's master key to the browser \
                                         for the session. Only use it on a device you trust.",
                                    ),
                                )
                            }),
                    )
                })
                .when_some(screen.web_access_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap_3()
                        .child(
                            div()
                                .id("web-access-cancel")
                                .px_6()
                                .py_3()
                                .rounded_xl()
                                .bg(cancel_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::BOLD)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_hover(move |is_hovered, _, cx| {
                                    cancel_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.close_web_access_modal(cx);
                                })),
                        )
                        .child(
                            div()
                                .id("web-access-approve")
                                .px_6()
                                .py_3()
                                .rounded_xl()
                                .bg(approve_bg)
                                .text_color(palette.on_primary)
                                .font_weight(gpui::FontWeight::BOLD)
                                .when(!granting, |el| el.cursor_pointer())
                                .opacity(if granting { 0.6 } else { 1.0 })
                                .child(if granting { "Approving…" } else { "Approve" })
                                .on_hover(move |is_hovered, _, cx| {
                                    approve_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .when(!granting, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.approve_web_access(cx);
                                    }))
                                }),
                        ),
                ),
        )
}

fn mode_button(
    palette: &Palette,
    id: &'static str,
    label: &'static str,
    selected: bool,
    window: &mut Window,
    cx: &mut Context<DevicesScreen>,
    mode: WebAccessMode,
) -> impl IntoElement {
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = if selected {
        palette.primary
    } else {
        animation::lerp_hsla(palette.surface, palette.surface_container_high, t)
    };

    div()
        .id(id)
        .flex_1()
        .py_3()
        .rounded_xl()
        .flex()
        .items_center()
        .justify_center()
        .bg(bg)
        .border_1()
        .border_color(if selected { palette.primary } else { gpui::Hsla { a: 0.2, ..palette.outline_variant } })
        .text_sm()
        .font_family(fonts::LABEL)
        .text_color(if selected { palette.on_primary } else { palette.on_surface })
        .cursor_pointer()
        .child(label)
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
            this.web_access_mode = mode;
            cx.notify();
        }))
}
