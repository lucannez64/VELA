//! Full port of `desktopVELA/src/components/TitleBar.tsx` — custom window
//! chrome (replacing Tauri's `decorations: false` + CSS `app-region: drag`)
//! plus the real session countdown, lock button, and always-on-top toggle
//! that the original always shows here, on every screen (mounted once by
//! `RootView`, above whichever screen is active — matches `App.tsx`
//! rendering `<TitleBar/>` unconditionally in all four of its return
//! branches).
//!
//! Session countdown: polls the real (cheap, no network — just two lock
//! reads) `vela_desktop_core::commands::session::get_session_status` every
//! second. Its `remaining_time()` is computed from a real absolute
//! `expires_at` timestamp on the backend, so this is a real, correctly-
//! ticking countdown, not a synthetic client-side timer — actually simpler
//! than the original's approach (which reconstructs idle-based remaining
//! time in JS from a locally-tracked last-activity timestamp).
//!
//! Always-on-top: gpui has no window-level "always on top" primitive
//! (checked `Window`'s full method list — only `minimize_window`/
//! `zoom_window`/`remove_window`/`start_window_move` exist, no
//! `set_window_level`/`always_on_top`). The toggle button still renders and
//! flips its own local highlighted state (matching the visual), but logs
//! instead of taking real effect — a genuine platform-layer gap, not a
//! skipped feature.
//!
//! Not ported: "close to tray" semantics (`remove_window` really closes the
//! window; the original's close button instead hides to a system tray icon,
//! which isn't built in this port yet — tracked in the plan's System
//! Integration phase).

use std::sync::Arc;
use std::time::Duration;

use gpui::{
    div, prelude::*, px, Context, EventEmitter, IntoElement, MouseButton, MouseDownEvent, Render,
    Task, Window,
};

use vela_desktop_core::commands::session::get_session_status;
use vela_desktop_core::session::SessionStatus;
use vela_desktop_core::AppState;

use crate::background::GuardedSpawn;
use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

pub enum TitleBarEvent {
    Locked,
}
impl EventEmitter<TitleBarEvent> for TitleBar {}

pub struct TitleBar {
    app_state: Arc<AppState>,
    session: Option<SessionStatus>,
    always_on_top: bool,
    _poll_task: Task<()>,
    _pulse_task: Task<()>,
}

impl TitleBar {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();

        let poll_task = cx.spawn({
            let app_state = app_state.clone();
            async move |this, cx| loop {
                let app_state = app_state.clone();
                let status = cx
                    .background_spawn_guarded("poll session status", async move {
                        get_session_status(&app_state).await
                    })
                    .await
                    .unwrap_or_else(|| Err("Session status poll failed unexpectedly".to_string()));
                let alive = this
                    .update(cx, |this, cx| {
                        if let Ok(status) = status {
                            // `get_session_status` correctly *reports*
                            // `active: false` once the countdown reaches
                            // zero, but doesn't itself clear the decrypted
                            // vault/crypto state or tell the UI to switch
                            // screens (by design — see its own doc comment:
                            // callers do that "in whatever toolkit-specific
                            // way applies"). Nothing was doing that here, so
                            // auto-lock silently expired the *reported*
                            // status while the real vault stayed decrypted
                            // in memory and the screen never switched to
                            // BiometricGate. Detecting the active→inactive
                            // transition here and driving both for real
                            // closes that gap.
                            let was_active = this.session.as_ref().map(|s| s.active).unwrap_or(false);
                            if was_active && !status.active {
                                tracing::info!("Session auto-locked (idle timeout) — showing BiometricGate");
                                vela_desktop_core::commands::session::lock_session(&this.app_state);
                                crate::clipboard::clear(cx);
                                crate::toast::show(
                                    cx,
                                    "Session locked (idle timeout)",
                                    crate::toast::ToastKind::Info,
                                );
                                cx.emit(TitleBarEvent::Locked);
                            }
                            this.session = Some(status);
                        }
                        cx.notify();
                    })
                    .is_ok();
                if !alive {
                    break;
                }
                cx.background_spawn(async { std::thread::sleep(Duration::from_secs(1)) }).await;
            }
        });

        Self {
            app_state,
            session: None,
            always_on_top: false,
            _poll_task: poll_task,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }

    fn handle_lock(&mut self, cx: &mut Context<Self>) {
        vela_desktop_core::commands::session::lock_session(&self.app_state);
        crate::clipboard::clear(cx);
        crate::toast::show(cx, "Session locked", crate::toast::ToastKind::Info);
        cx.emit(TitleBarEvent::Locked);
        cx.notify();
    }
}

fn format_time(secs: u64) -> String {
    format!("{}m {:02}s", secs / 60, secs % 60)
}

impl Render for TitleBar {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let active = self.session.as_ref().map(|s| s.active).unwrap_or(false);
        let remaining = self.session.as_ref().map(|s| s.session_time_remaining_secs).unwrap_or(0);

        let (timer_color, timer_pulses) = if !active {
            (palette.outline, false)
        } else if remaining <= 60 {
            (palette.error, true)
        } else if remaining <= 180 {
            (gpui::rgb(0xf59e0b).into(), false)
        } else {
            (palette.on_surface_variant, false)
        };
        let timer_opacity = if timer_pulses { animation::pulse_alpha(1.0) } else { 1.0 };
        let timer_text = if active { format_time(remaining) } else { "--".to_string() };

        let always_on_top = self.always_on_top;

        div()
            .id("titlebar")
            .h(px(56.))
            .w_full()
            .flex()
            .items_center()
            .justify_between()
            .px_4()
            .bg(palette.surface)
            .border_b_1()
            .border_color(gpui::Hsla { a: 0.1, ..palette.outline_variant })
            .on_mouse_down(MouseButton::Left, |event: &MouseDownEvent, window, _cx| {
                if event.click_count >= 2 {
                    window.zoom_window();
                } else {
                    window.start_window_move();
                }
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .w(px(32.))
                            .h(px(32.))
                            .rounded_lg()
                            .bg(palette.surface_container)
                            .border_1()
                            .border_color(gpui::Hsla { a: 0.2, ..palette.primary })
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(icon("shield_lock", px(18.), palette.primary)),
                    )
                    .child(
                        fonts::tracked_text("VELA", px(18.), 0.2)
                            .font_family(fonts::HEADLINE)
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_lg()
                            .text_color(palette.primary),
                    )
                    .child(
                        // `.security-pulse` (`index.css`: 4s pulse, slower
                        // than plain `animate-pulse`'s 2s) wraps the WHOLE
                        // badge in the original — the dot itself carries no
                        // animation class there.
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .ml_4()
                            .px_3()
                            .py_1()
                            .rounded_full()
                            .bg(gpui::Hsla { a: 0.1, ..palette.secondary })
                            .opacity(animation::pulse_alpha(4.0))
                            .child(div().w(px(8.)).h(px(8.)).rounded_full().bg(palette.primary))
                            .child(
                                fonts::tracked_text("Zero-Knowledge Active", px(10.), 0.1)
                                    .font_family(fonts::LABEL)
                                    .text_size(px(10.))
                                    .text_color(palette.primary),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .font_family(fonts::LABEL)
                            .text_xs()
                            .text_color(palette.outline)
                            .child("Session:")
                            .child(
                                div()
                                    .font_family(fonts::MONO)
                                    .text_color(timer_color)
                                    .opacity(timer_opacity)
                                    .child(timer_text),
                            ),
                    )
                    .child(icon_button(&palette, "lock-now", "lock_open", palette.outline, window, cx, |this, cx| {
                        this.handle_lock(cx);
                    }))
                    .child(
                        icon_button(
                            &palette,
                            "always-on-top",
                            if always_on_top { "keep" } else { "push_pin" },
                            if always_on_top { palette.primary } else { palette.outline },
                            window,
                            cx,
                            |this, cx| {
                                this.always_on_top = !this.always_on_top;
                                tracing::info!(
                                    "Always-on-top toggled locally — gpui has no window-level \
                                     always-on-top primitive, no real effect"
                                );
                                cx.notify();
                            },
                        ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .ml_2()
                            .child(window_button(&palette, "minimize", "remove", window, cx, false, |window| {
                                window.minimize_window();
                            }))
                            .child(window_button(&palette, "maximize", "crop_square", window, cx, false, |window| {
                                window.zoom_window();
                            }))
                            .child(window_button(&palette, "close", "close", window, cx, true, |window| {
                                window.remove_window();
                            })),
                    ),
            )
    }
}

fn icon_button(
    palette: &Palette,
    id: &'static str,
    icon_name: &'static str,
    color: gpui::Hsla,
    window: &mut Window,
    cx: &mut Context<TitleBar>,
    on_click: impl Fn(&mut TitleBar, &mut Context<TitleBar>) + 'static,
) -> impl IntoElement {
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = animation::lerp_hsla(gpui::transparent_black(), palette.surface_container, t);

    div()
        .id(id)
        .p_2()
        .rounded_lg()
        .bg(bg)
        .cursor_pointer()
        .child(icon(icon_name, px(20.), color))
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        // Without this, a click here also bubbles up to the titlebar's own
        // drag/double-click-to-maximize handler (since that's registered on
        // the whole titlebar row these buttons live inside), so every
        // button click also attempted a window move.
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
            cx.stop_propagation();
            on_click(this, cx);
        }))
}

fn window_button(
    palette: &Palette,
    id: &'static str,
    icon_name: &'static str,
    window: &mut Window,
    cx: &mut Context<TitleBar>,
    is_close: bool,
    action: impl Fn(&mut Window) + 'static,
) -> impl IntoElement {
    let text = palette.on_surface_variant;
    let hover_target = if is_close { palette.error } else { palette.surface_container };
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = if is_close {
        animation::lerp_hsla(gpui::transparent_black(), gpui::Hsla { a: 0.2, ..hover_target }, t)
    } else {
        animation::lerp_hsla(gpui::transparent_black(), hover_target, t)
    };
    let icon_color = if is_close { animation::lerp_hsla(text, palette.error, t) } else { text };

    div()
        .id(id)
        .w(px(28.))
        .h(px(28.))
        .flex()
        .items_center()
        .justify_center()
        .rounded_md()
        .bg(bg)
        .cursor_pointer()
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        // Same reason as `icon_button`: without stopping propagation here,
        // clicking minimize/maximize/close also bubbled up to the
        // titlebar's own drag handler and attempted a window move.
        .on_mouse_down(MouseButton::Left, move |_: &MouseDownEvent, window, cx| {
            cx.stop_propagation();
            action(window);
        })
        .child(icon(icon_name, px(16.), icon_color))
}
