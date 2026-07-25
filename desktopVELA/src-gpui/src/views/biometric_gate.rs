//! Port of `desktopVELA/src/views/BiometricGate.tsx` — the unlock gate.
//! Auto-triggers biometric auth on mount if available, falls back to a
//! master-password field, tracks failed attempts with a 30s lockout after 5.
//!
//! Real end-to-end unlock: calls the same
//! `vela_desktop_core::commands::session::{unlock_session, unlock_session_with_password}`
//! the shipped Tauri app uses, against the same on-disk vault (`Store::new()`
//! resolves the same OS data dir either way) — a successful unlock here
//! really does decrypt the real vault into this process. No IPC hop.
//!
//! "Can't access your vault? Reset" now opens a real typed-DELETE
//! confirmation and calls the real `reset_vault` (same backend call as
//! Settings' Delete Vault).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use gpui::{
    div, img, prelude::*, px, Context, EventEmitter, Focusable, ImageSource, IntoElement,
    MouseButton, ObjectFit, Render, SharedString, Task, Window,
};
use gpui_elements::editable_text::{text_input, EditableTextState, StringStorage};

use vela_desktop_core::biometric::BiometricProvider;
use vela_desktop_core::commands::session;
use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: u32 = 30;

#[derive(PartialEq)]
enum Mode {
    Biometric,
    Password,
}

pub enum BiometricGateEvent {
    Unlocked,
    /// The vault was actually, permanently reset — go back to Welcome
    /// (first-launch), not stay on this gate (there's no vault left to
    /// unlock).
    VaultReset,
}
impl EventEmitter<BiometricGateEvent> for BiometricGate {}

pub struct BiometricGate {
    app_state: Arc<AppState>,
    mode: Mode,
    biometric_available: bool,
    checking_biometric: bool,
    is_authenticating: bool,
    error: Option<SharedString>,
    retry_count: u32,
    lockout_seconds_left: u32,
    password_state: gpui::Entity<EditableTextState>,
    password_revealed: bool,
    show_reset_modal: bool,
    reset_confirm_state: gpui::Entity<EditableTextState>,
    resetting: bool,
    reset_error: Option<SharedString>,
    _lockout_task: Option<Task<()>>,
    _pulse_task: Task<()>,
}

impl BiometricGate {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let password_state = cx.new(|cx| EditableTextState::new(StringStorage::default(), cx));

        cx.spawn(async move |this, cx| {
            let status = cx
                .background_spawn(async { vela_desktop_core::biometric::check_enrollment() })
                .await;
            let available = status.enrolled
                && !matches!(
                    status.provider,
                    BiometricProvider::None | BiometricProvider::MasterPassword
                );
            this.update(cx, |this, cx| {
                this.biometric_available = available;
                this.checking_biometric = false;
                if available {
                    this.trigger_biometric_auth(cx);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();

        Self {
            app_state,
            mode: Mode::Biometric,
            biometric_available: true,
            checking_biometric: true,
            is_authenticating: false,
            error: None,
            retry_count: 0,
            lockout_seconds_left: 0,
            password_state,
            password_revealed: false,
            show_reset_modal: false,
            reset_confirm_state: cx.new(|cx| EditableTextState::new(StringStorage::default(), cx)),
            resetting: false,
            reset_error: None,
            _lockout_task: None,
            _pulse_task: animation::spawn_pulse_ticker(cx),
        }
    }

    fn open_reset_modal(&mut self, cx: &mut Context<Self>) {
        self.reset_confirm_state.update(cx, |s, cx| s.emplace("", cx));
        self.reset_error = None;
        self.show_reset_modal = true;
        cx.notify();
    }

    fn close_reset_modal(&mut self, cx: &mut Context<Self>) {
        self.show_reset_modal = false;
        cx.notify();
    }

    fn confirm_reset(&mut self, cx: &mut Context<Self>) {
        let confirm_text = self.reset_confirm_state.read(cx).as_str().to_string();
        self.resetting = true;
        self.reset_error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            // `reset_vault` may perform a real server auth challenge (when
            // unlocked with a server configured) — must run via gpui_tokio's
            // bridge onto the actual tokio runtime, not `cx.background_spawn`
            // (a separate thread pool that never entered that runtime and
            // panics on real reactor I/O).
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                vela_desktop_core::commands::session::reset_vault(&app_state, Some(confirm_text), None).await
            })
            .await;
            this.update(cx, |this, cx| {
                this.resetting = false;
                match result {
                    Ok(Ok(())) => {
                        this.show_reset_modal = false;
                        cx.emit(BiometricGateEvent::VaultReset);
                    }
                    Ok(Err(e)) => this.reset_error = Some(format!("Failed to reset vault: {e}").into()),
                    Err(e) => this.reset_error = Some(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn is_locked(&self) -> bool {
        self.lockout_seconds_left > 0
    }

    fn record_failure(&mut self, message: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.error = Some(message.into());
        self.retry_count += 1;
        self.is_authenticating = false;
        if self.retry_count >= MAX_ATTEMPTS {
            self.start_lockout(cx);
        }
        cx.notify();
    }

    fn start_lockout(&mut self, cx: &mut Context<Self>) {
        self.lockout_seconds_left = LOCKOUT_SECS;
        self._lockout_task = Some(cx.spawn(async move |this, cx| loop {
            cx.background_spawn(async { std::thread::sleep(Duration::from_secs(1)) })
                .await;
            let should_continue = this
                .update(cx, |this, cx| {
                    if this.lockout_seconds_left <= 1 {
                        this.lockout_seconds_left = 0;
                        this.retry_count = 0;
                        cx.notify();
                        false
                    } else {
                        this.lockout_seconds_left -= 1;
                        cx.notify();
                        true
                    }
                })
                .unwrap_or(false);
            if !should_continue {
                break;
            }
        }));
    }

    fn trigger_biometric_auth(&mut self, cx: &mut Context<Self>) {
        self.is_authenticating = true;
        self.error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let auth_result = cx
                .background_spawn(async { vela_desktop_core::biometric::authenticate() })
                .await;

            if !auth_result.success {
                let message = auth_result
                    .error_message
                    .unwrap_or_else(|| "Authentication failed".to_string());
                this.update(cx, |this, cx| this.record_failure(message, cx)).ok();
                return;
            }

            let unlock_result = session::unlock_session(&app_state).await;
            this.update(cx, |this, cx| match unlock_result {
                Ok(_status) => {
                    this.is_authenticating = false;
                    cx.emit(BiometricGateEvent::Unlocked);
                    cx.notify();
                }
                Err(e) => this.record_failure(e, cx),
            })
            .ok();
        })
        .detach();
    }

    fn trigger_password_auth(&mut self, cx: &mut Context<Self>) {
        let password = self.password_state.read(cx).as_str().to_string();
        if password.trim().is_empty() {
            self.error = Some("Please enter your password".into());
            cx.notify();
            return;
        }

        self.is_authenticating = true;
        self.error = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let unlock_result = session::unlock_session_with_password(&app_state, password).await;
            this.update(cx, |this, cx| match unlock_result {
                Ok(_status) => {
                    this.is_authenticating = false;
                    cx.emit(BiometricGateEvent::Unlocked);
                    cx.notify();
                }
                Err(e) => this.record_failure(e, cx),
            })
            .ok();
        })
        .detach();
    }
}

impl Render for BiometricGate {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let locked = self.is_locked();

        let content: gpui::AnyElement = if self.mode == Mode::Password || !self.biometric_available {
            password_view(self, &palette, locked, window, cx)
        } else {
            biometric_view(self, &palette, locked, window, cx)
        };

        div()
            .relative()
            .size_full()
            .child(content)
            .when(self.show_reset_modal, |el| el.child(reset_confirm_modal(&palette, self, window, cx)))
            .into_any_element()
    }
}

fn header(palette: &Palette) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_2()
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .w(px(40.))
                        .h(px(40.))
                        .rounded_lg()
                        .bg(palette.surface_container)
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(icon("shield_lock", px(22.), palette.primary)),
                )
                .child(
                    fonts::tracked_text("VELA", px(30.), 0.25)
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .text_3xl()
                        .text_color(palette.primary),
                ),
        )
        .child(
            fonts::tracked_text("ZERO-KNOWLEDGE VAULT", px(12.), 0.4)
                .font_family(fonts::LABEL)
                .text_xs()
                .text_color(gpui::Hsla { a: 0.6, ..palette.on_surface_variant }),
        )
}

/// Divider row above the "Master Password" fallback button — port of the
/// original's `── Alternative Access ──` row.
fn alt_access_divider(palette: &Palette) -> impl IntoElement {
    let line_color = gpui::Hsla { a: 0.2, ..palette.outline_variant };
    div()
        .w_full()
        .flex()
        .items_center()
        .gap_4()
        .px_12()
        .child(div().flex_1().h(px(1.)).bg(line_color))
        .child(
            div()
                .font_family(fonts::LABEL)
                .text_size(px(10.))
                .text_color(palette.on_surface_variant)
                .child("ALTERNATIVE ACCESS"),
        )
        .child(div().flex_1().h(px(1.)).bg(line_color))
}

/// "Can't access your vault? Reset" link, shown on both the biometric and
/// password views in the original. Opens the real typed-DELETE confirmation
/// modal (`reset_confirm_modal`) wired to the real `reset_vault`.
enum Corner {
    TopLeft,
    BottomRight,
}

/// Decorative corner bracket — port of the original's absolutely-positioned
/// `border-t border-l rounded-tl-3xl` (and the bottom-right mirror), present
/// in the original but missing from an earlier pass of this port.
fn corner_bracket(palette: &Palette, corner: Corner) -> impl IntoElement {
    let border_color = gpui::Hsla { a: 0.4, ..palette.accent_violet };
    let base = div().absolute().w(px(128.)).h(px(128.)).opacity(0.2);
    match corner {
        Corner::TopLeft => base
            .top_0()
            .left_0()
            .border_t_1()
            .border_l_1()
            .border_color(border_color)
            .rounded_tl(px(24.)),
        Corner::BottomRight => base
            .bottom_0()
            .right_0()
            .border_b_1()
            .border_r_1()
            .border_color(border_color)
            .rounded_br(px(24.)),
    }
}

/// Top-right "Secure Session Active" badge with a ping ripple, present in
/// the original but missing from an earlier pass of this port.
fn secure_session_badge(palette: &Palette, ping: f32) -> impl IntoElement {
    let ring_scale = 1. + ping;
    let ring_opacity = 1. - ping;
    div()
        .absolute()
        .top_4()
        .right_4()
        .flex()
        .items_center()
        .gap_3()
        .px_4()
        .py_2()
        .rounded_full()
        .bg(gpui::Hsla { a: 0.4, ..palette.surface_container_high })
        .border_1()
        .border_color(gpui::Hsla { a: 0.1, ..palette.secondary })
        .child(
            div()
                .relative()
                .w(px(8.))
                .h(px(8.))
                .child(
                    div()
                        .absolute()
                        .inset_0()
                        .rounded_full()
                        .bg(palette.secondary)
                        .opacity(ring_opacity * 0.75)
                        .w(px(8. * ring_scale))
                        .h(px(8. * ring_scale)),
                )
                .child(div().absolute().inset_0().rounded_full().bg(palette.secondary)),
        )
        .child(
            div()
                .font_family(fonts::LABEL)
                .font_weight(gpui::FontWeight::BOLD)
                .text_size(px(10.))
                .text_color(palette.secondary)
                .child("SECURE SESSION ACTIVE"),
        )
}

/// Exact reproduction of `.obsidian-gradient` (`index.css`):
/// `radial-gradient(ellipse 90% 60% at 75% -10%, accent-violet/0.14, transparent),`
/// `radial-gradient(ellipse 70% 55% at 15% 110%, primary/0.09, transparent),`
/// `rgb(var(--color-surface))`.
///
/// Two earlier attempts tried to fake this with gpui primitives and both
/// visibly failed a pixel-sampled comparison against the original: a
/// full-bleed diagonal `linear_gradient` (wrong shape entirely — a band,
/// not a cornered blob), then a "zero-size point + huge blurred `.shadow()`"
/// trick that turned out to be a hard no-op (confirmed by reading
/// `gpui_wgpu/src/shaders.wgsl`'s `fs_shadow`: its blur integrates over
/// `[-half_size, +half_size]` on both axes, so a literal 0×0 source
/// collapses that range to a point and the accumulated alpha is always
/// `0.0`). A real, sized blurred ellipse fixed the no-op but still used
/// gaussian-ish blur falloff (`erf`-based, see `blur_along_x`) — a
/// fundamentally different curve from CSS radial-gradient's *linear* alpha
/// ramp from center to edge, so no amount of size/blur tuning could ever
/// match exactly.
///
/// gpui-ce has no radial-gradient primitive at all (confirmed via source
/// search of `color.rs`), but it can render an arbitrary image
/// (`favicon_ui.rs` already does, for favicons). So instead of
/// approximating with a primitive that draws the wrong curve, this computes
/// the CSS radial-gradient formula directly — same ellipse-normalized
/// distance, same linear `alpha = stop0 * (1 - d)` ramp, same top-to-bottom
/// layer compositing CSS itself does for multiple backgrounds (first-listed
/// gradient is topmost, `background-color` is the base) — into a small
/// RGBA bitmap, then displays it via `ObjectFit::Fill` so it stretches to
/// the container's actual size. Because the gradient math is itself
/// evaluated in the same 0..1-of-box-size units CSS uses, stretching a
/// bitmap computed this way to fill any box reproduces the CSS output
/// exactly (up to the bitmap's raster resolution, chosen high enough here
/// that it's imperceptible on a smooth gradient with no hard edges).
///
/// Cached per distinct `(surface, accent_violet, primary)` triple (there
/// are only 4 themes, so at most 4 entries ever exist) so the ~10fps pulse
/// ticker driving this view's re-renders doesn't re-rasterize + re-encode a
/// PNG every frame — only regenerated the first time a given theme's colors
/// are seen.
fn obsidian_gradient_overlay(palette: &Palette) -> impl IntoElement {
    let image = cached_obsidian_gradient_image(palette);
    div().absolute().inset_0().child(
        img(ImageSource::Image(image))
            .size_full()
            .object_fit(ObjectFit::Fill),
    )
}

fn cached_obsidian_gradient_image(palette: &Palette) -> Arc<gpui::Image> {
    static CACHE: OnceLock<Mutex<HashMap<(u32, u32, u32), Arc<gpui::Image>>>> = OnceLock::new();
    let key = (
        hsla_bits(palette.surface),
        hsla_bits(palette.accent_violet),
        hsla_bits(palette.primary),
    );
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().expect("gradient image cache poisoned");
    if let Some(image) = guard.get(&key) {
        return image.clone();
    }
    let image = Arc::new(render_obsidian_gradient_image(palette));
    guard.insert(key, image.clone());
    image
}

/// Cheap identity for cache-keying a color by its bit pattern (colors here
/// only ever come from a small, fixed set of theme palettes, so exact
/// float equality via bits is fine — no arithmetic is done on the key).
fn hsla_bits(color: gpui::Hsla) -> u32 {
    color.h.to_bits() ^ color.s.to_bits() ^ color.l.to_bits() ^ color.a.to_bits()
}

fn render_obsidian_gradient_image(palette: &Palette) -> gpui::Image {
    // High enough that the smooth gradient shows no banding once stretched
    // to a real window size, low enough to compute + encode in well under
    // a millisecond.
    const WIDTH: u32 = 512;
    const HEIGHT: u32 = 360;

    let base = hsla_to_rgb_f32(palette.surface);
    let violet = hsla_to_rgb_f32(palette.accent_violet);
    let primary = hsla_to_rgb_f32(palette.primary);

    let mut buffer = image::RgbaImage::new(WIDTH, HEIGHT);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let u = (x as f32 + 0.5) / WIDTH as f32;
            let v = (y as f32 + 0.5) / HEIGHT as f32;
            // Painted bottom-to-top, same as CSS's multiple-background
            // layering (first-listed gradient ends up on top).
            let mut rgb = base;
            rgb = composite_radial_wash(rgb, primary, u, v, 0.15, 1.10, 0.70, 0.55, 0.09);
            rgb = composite_radial_wash(rgb, violet, u, v, 0.75, -0.10, 0.90, 0.60, 0.14);
            buffer.put_pixel(
                x,
                y,
                image::Rgba([
                    (rgb.0 * 255.0).round() as u8,
                    (rgb.1 * 255.0).round() as u8,
                    (rgb.2 * 255.0).round() as u8,
                    255,
                ]),
            );
        }
    }

    let mut png_bytes = Vec::new();
    buffer
        .write_to(&mut std::io::Cursor::new(&mut png_bytes), image::ImageFormat::Png)
        .expect("encoding a freshly-built in-memory RgbaImage to PNG cannot fail");
    gpui::Image::from_bytes(gpui::ImageFormat::Png, png_bytes)
}

/// One CSS `radial-gradient(ellipse rx% ry% at cx% cy%, color/max_alpha, transparent)`
/// stop, composited "over" the color computed so far — `d` is the
/// ellipse-normalized distance from center (0 at center, 1 at the ellipse's
/// edge), and CSS's linear color-stop interpolation makes alpha ramp
/// linearly from `max_alpha` at `d=0` to `0` at `d=1` while the RGB stays
/// fixed (a "transparent" stop is the same color at alpha 0, not black).
fn composite_radial_wash(
    under: (f32, f32, f32),
    color: (f32, f32, f32),
    u: f32,
    v: f32,
    cx: f32,
    cy: f32,
    rx: f32,
    ry: f32,
    max_alpha: f32,
) -> (f32, f32, f32) {
    let dx = (u - cx) / rx;
    let dy = (v - cy) / ry;
    let d = (dx * dx + dy * dy).sqrt();
    if d >= 1.0 {
        return under;
    }
    let alpha = max_alpha * (1.0 - d);
    (
        color.0 * alpha + under.0 * (1.0 - alpha),
        color.1 * alpha + under.1 * (1.0 - alpha),
        color.2 * alpha + under.2 * (1.0 - alpha),
    )
}

fn hsla_to_rgb_f32(color: gpui::Hsla) -> (f32, f32, f32) {
    let rgba: gpui::Rgba = color.into();
    (rgba.r, rgba.g, rgba.b)
}

fn reset_link(palette: &Palette, cx: &mut Context<BiometricGate>) -> impl IntoElement {
    div()
        .id("reset-vault-link")
        .text_size(px(11.))
        .text_color(gpui::Hsla { a: 0.4, ..palette.on_surface_variant })
        .cursor_pointer()
        .child("Can't access your vault? Reset")
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
            this.open_reset_modal(cx);
        }))
}

fn biometric_view(
    gate: &BiometricGate,
    palette: &Palette,
    locked: bool,
    window: &mut Window,
    cx: &mut Context<BiometricGate>,
) -> gpui::AnyElement {
    let status_text: SharedString = if locked {
        format!("Too many attempts — wait {}s", gate.lockout_seconds_left).into()
    } else {
        "Touch sensor to unlock".into()
    };
    let remaining = MAX_ATTEMPTS.saturating_sub(gate.retry_count);
    let error = gate.error.clone();
    let disabled = gate.is_authenticating || locked;
    let fingerprint_opacity = if gate.is_authenticating { animation::pulse_alpha(1.5) } else { 1.0 };
    let ready_dot_opacity = animation::pulse_alpha(2.0);
    let ping = animation::ping_progress(1.5);
    let hover_t = animation::hover_transition("biometric-button", window, cx);
    let border_t = *hover_t.evaluate(window, cx);

    div()
        .relative()
        .size_full()
        .flex()
        .flex_col()
        .items_center()
        .justify_between()
        .bg(palette.surface)
        .py_12()
        .gap_8()
        .child(obsidian_gradient_overlay(palette))
        .child(corner_bracket(palette, Corner::TopLeft))
        .child(corner_bracket(palette, Corner::BottomRight))
        .child(secure_session_badge(palette, ping))
        .child(header(palette))
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap_4()
                .child(
                    // Two static decorative rings behind the button, matching
                    // the original's nested absolutely-positioned circles.
                    div()
                        .relative()
                        .w(px(140.))
                        .h(px(140.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(
                            div()
                                .absolute()
                                .w(px(220.))
                                .h(px(220.))
                                .rounded_full()
                                .border_1()
                                .border_color(gpui::Hsla { a: 0.1, ..palette.accent_violet }),
                        )
                        .child(
                            div()
                                .absolute()
                                .w(px(170.))
                                .h(px(170.))
                                .rounded_full()
                                .border_1()
                                .border_color(gpui::Hsla { a: 0.2, ..palette.accent_violet }),
                        )
                        .child({
                            let border_color = animation::lerp_hsla(
                                gpui::Hsla { a: 0.3, ..palette.accent_violet },
                                palette.accent_violet,
                                border_t,
                            );
                            // `.biometric-glow` (`index.css`): a static
                            // `box-shadow: 0 0 60px -15px accent-violet/0.3`
                            // soft halo — no per-element approximation
                            // needed, gpui's real `.shadow()` primitive maps
                            // 1:1 onto CSS box-shadow's offset/blur/spread.
                            let mut circle = div()
                                .id("biometric-button")
                                .relative()
                                .w(px(140.))
                                .h(px(140.))
                                .rounded_full()
                                .bg(palette.surface_container_high)
                                .border_1()
                                .border_color(border_color)
                                .shadow(vec![gpui::BoxShadow {
                                    color: gpui::Hsla { a: 0.3, ..palette.accent_violet },
                                    offset: gpui::point(px(0.), px(0.)),
                                    blur_radius: px(60.),
                                    spread_radius: px(-15.),
                                    inset: false,
                                }])
                                .flex()
                                .items_center()
                                .justify_center()
                                .child(
                                    icon("fingerprint", px(64.), palette.accent_violet)
                                        .opacity(fingerprint_opacity),
                                );
                            if !disabled {
                                circle = circle
                                    .cursor_pointer()
                                    .on_hover(move |is_hovered, _, cx| {
                                        hover_t.update(cx, |v, cx| {
                                            *v = *is_hovered as u8 as f32;
                                            cx.notify();
                                        });
                                    })
                                    .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.trigger_biometric_auth(cx);
                                    }));
                            } else {
                                circle = circle.opacity(0.6);
                            }
                            circle
                        }),
                )
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::LIGHT)
                        .text_2xl()
                        .text_color(palette.on_surface)
                        .child(status_text),
                )
                .child(
                    // "AUTHENTICATION READY" / "RETRY IN Ns" pulsing-dot row —
                    // present in the original directly under the status
                    // heading, missing from an earlier pass of this port.
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .w(px(6.))
                                .h(px(6.))
                                .rounded_full()
                                .bg(palette.primary)
                                .opacity(ready_dot_opacity),
                        )
                        .child(
                            div()
                                .font_family(fonts::LABEL)
                                .text_sm()
                                .text_color(palette.on_surface_variant)
                                .child(if locked {
                                    format!("RETRY IN {}S", gate.lockout_seconds_left)
                                } else {
                                    "AUTHENTICATION READY".to_string()
                                }),
                        ),
                )
                .when_some(error, |el, error| {
                    el.child(
                        div()
                            .font_family(fonts::LABEL)
                            .text_sm()
                            .text_color(palette.error)
                            .child(format!("{error} — try again ({remaining} attempts remaining)")),
                    )
                }),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap_4()
                .w_full()
                .max_w(px(420.))
                .child(alt_access_divider(palette))
                .child(
                    div()
                        .id("use-password")
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_5()
                        .py_2()
                        .rounded_lg()
                        .bg(palette.surface_container)
                        .text_color(palette.on_surface)
                        .cursor_pointer()
                        .child(icon("password", px(18.), palette.on_surface))
                        .child(div().font_family(fonts::BODY).child("Master Password"))
                        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                            this.mode = Mode::Password;
                            this.error = None;
                            cx.notify();
                        })),
                )
                .child(
                    div()
                        .font_family(fonts::BODY)
                        .text_xs()
                        .text_color(gpui::Hsla { a: 0.4, ..palette.on_surface_variant })
                        .child("Securely encrypted with Post-Quantum AES-256"),
                )
                .child(reset_link(palette, cx)),
        )
        .into_any_element()
}

fn password_view(
    gate: &BiometricGate,
    palette: &Palette,
    locked: bool,
    window: &mut Window,
    cx: &mut Context<BiometricGate>,
) -> gpui::AnyElement {
    let disabled = gate.is_authenticating || locked;
    let error = gate.error.clone();
    let subtitle: SharedString = if gate.biometric_available {
        "Biometric authentication failed".into()
    } else {
        "Biometric not available on this device".into()
    };

    div()
        .relative()
        .size_full()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .bg(palette.surface)
        .gap_6()
        .child(obsidian_gradient_overlay(palette))
        .child(header(palette))
        .child(icon("password", px(56.), palette.accent_violet))
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .gap_1()
                .child(
                    div()
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::LIGHT)
                        .text_2xl()
                        .text_color(palette.on_surface)
                        .child("Enter Master Password"),
                )
                .child(
                    div()
                        .font_family(fonts::BODY)
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(subtitle),
                ),
        )
        .child(
            div()
                .w(px(360.))
                .flex()
                .flex_col()
                .gap_3()
                .child({
                    // gpui has no CSS-`transform` equivalent, so an
                    // absolutely-positioned `top_1_2()` (top: 50%) alone
                    // cannot vertically center the eye icon the way
                    // `top-1/2 -translate-y-1/2` does in the original — it
                    // just pins the icon's own top edge to the midline.
                    // Spanning the icon wrapper the full height of the
                    // `.relative()` parent (`top_0().bottom_0()`) and
                    // flex-centering it is the real gpui-native fix.
                    let is_focused =
                        gate.password_state.read(cx).focus_handle(cx).is_focused(window);
                    let focus_t = animation::hover_transition("password-field-focus", window, cx);
                    focus_t.update(cx, |v, _cx| *v = is_focused as u8 as f32);
                    let t = *focus_t.evaluate(window, cx);
                    let border_color =
                        animation::lerp_hsla(palette.outline_variant, palette.primary, t);

                    let revealed = gate.password_revealed;

                    div()
                        .relative()
                        .child(
                            text_input("password-field")
                                .state(gate.password_state.downgrade())
                                .placeholder("Enter your master password")
                                .caret_blink_interval_500ms()
                                // A single-byte ASCII mask char (not '•',
                                // which is 3 bytes in UTF-8): the underlying
                                // widget's caret/selection positions are
                                // byte offsets into the REAL text, reused
                                // as-is against the MASKED shaped line — a
                                // multi-byte mask char desyncs that mapping
                                // for ordinary (1-byte-per-char) ASCII
                                // passwords, visibly misplacing the caret.
                                .mask_char((!revealed).then_some('*'))
                                .border_1()
                                .rounded_lg()
                                .border_color(border_color)
                                .bg(palette.surface_container)
                                .font_family(fonts::MONO)
                                .text_color(palette.on_surface)
                                .caret_color(palette.on_surface)
                                .p_3()
                                .pr(px(44.))
                                .w_full()
                                .min_h_auto()
                                .whitespace_nowrap()
                                .overflow_x_scroll(),
                        )
                        .child(
                            // Real masking via the vendored `gpui_elements`
                            // patch's `.mask_char()` — the masked string IS
                            // what's shaped/measured, so caret, selection,
                            // and internal scrolling all stay correct
                            // automatically (unlike the earlier overlay-based
                            // attempt, which desynced on longer text).
                            div()
                                .id("toggle-password-visible")
                                .absolute()
                                .right_3()
                                .top_0()
                                .bottom_0()
                                .flex()
                                .items_center()
                                .cursor_pointer()
                                .child(icon(
                                    if revealed { "visibility_off" } else { "visibility" },
                                    px(18.),
                                    palette.on_surface_variant,
                                ))
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.password_revealed = !this.password_revealed;
                                    cx.notify();
                                })),
                        )
                })
                .when_some(error, |el, error| {
                    el.child(
                        div()
                            .font_family(fonts::BODY)
                            .text_sm()
                            .text_color(palette.error)
                            .child(error),
                    )
                })
                .child({
                    let text = palette.on_primary;
                    let gradient = gpui::linear_gradient(
                        90.,
                        gpui::linear_color_stop(palette.primary, 0.),
                        gpui::linear_color_stop(palette.primary_dim, 1.),
                    );
                    let mut btn = div()
                        .id("unlock-button")
                        .py_3()
                        .rounded_lg()
                        .bg(gradient)
                        .text_color(text)
                        .font_family(fonts::HEADLINE)
                        .font_weight(gpui::FontWeight::BOLD)
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(if gate.is_authenticating {
                            "Unlocking…"
                        } else {
                            "Unlock"
                        });
                    if !disabled {
                        btn = btn
                            .cursor_pointer()
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.trigger_password_auth(cx);
                            }));
                    } else {
                        btn = btn.opacity(0.5);
                    }
                    btn
                })
                .when(gate.biometric_available, |el| {
                    el.child(
                        div()
                            .id("use-biometric")
                            .flex()
                            .items_center()
                            .justify_center()
                            .gap_2()
                            .font_family(fonts::BODY)
                            .text_sm()
                            .text_color(palette.primary)
                            .cursor_pointer()
                            .child(icon("fingerprint", px(16.), palette.primary))
                            .child("Use biometric instead")
                            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                this.mode = Mode::Biometric;
                                this.error = None;
                                cx.notify();
                            })),
                    )
                })
                .child(
                    div()
                        .flex()
                        .justify_center()
                        .mt_2()
                        .child(reset_link(palette, cx)),
                ),
        )
        .into_any_element()
}

/// Port of `ConfirmResetModal.tsx` — typed-"DELETE" confirmation gate for
/// `reset_vault`, reachable from the "Can't access your vault? Reset" link
/// on both views above. Same real backend call as `SettingsScreen`'s Delete
/// Vault action, just reached from a locked-out/can't-unlock context rather
/// than from within an already-unlocked vault.
fn reset_confirm_modal(palette: &Palette, gate: &BiometricGate, window: &mut Window, cx: &mut Context<BiometricGate>) -> impl IntoElement {
    let confirm_text = gate.reset_confirm_state.read(cx).as_str().to_string();
    let can_reset = confirm_text == "DELETE";
    let resetting = gate.resetting;

    let cancel_hover = animation::hover_transition("reset-cancel", window, cx);
    let cancel_t = *cancel_hover.evaluate(window, cx);
    let cancel_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, cancel_t);

    div()
        .id("reset-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
        .flex()
        .items_center()
        .justify_center()
        .p_4()
        .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close_reset_modal(cx)))
        .child(
            div()
                .id("reset-modal-body")
                .w(px(420.))
                .p_8()
                .rounded_2xl()
                .bg(palette.surface_container)
                .border_1()
                .border_color(gpui::Hsla { a: 0.3, ..palette.error })
                .flex()
                .flex_col()
                .gap_4()
                .on_mouse_down(MouseButton::Left, |_, _, _| {})
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(icon("warning", px(24.), palette.error))
                        .child(
                            div()
                                .font_family(fonts::HEADLINE)
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_xl()
                                .text_color(palette.on_surface)
                                .child("Reset vault?"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(
                            "This action is irreversible. All vault data and credentials on \
                             this device will be permanently deleted. Type DELETE to confirm.",
                        ),
                )
                .when_some(gate.reset_error.clone(), |el, error| {
                    el.child(div().text_sm().text_color(palette.error).child(error))
                })
                .child(
                    text_input("reset-confirm-input")
                        .state(gate.reset_confirm_state.downgrade())
                        .placeholder("Type DELETE")
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
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(
                            div()
                                .id("cancel-reset")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(cancel_bg)
                                .text_color(palette.on_surface)
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .cursor_pointer()
                                .child("Cancel")
                                .on_hover(move |is_hovered, _, cx| {
                                    cancel_hover.update(cx, |v, cx| {
                                        *v = *is_hovered as u8 as f32;
                                        cx.notify();
                                    });
                                })
                                .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                    this.close_reset_modal(cx);
                                })),
                        )
                        .child(
                            div()
                                .id("confirm-reset")
                                .flex_1()
                                .py_3()
                                .rounded_xl()
                                .flex()
                                .items_center()
                                .justify_center()
                                .bg(if can_reset { palette.error } else { gpui::Hsla { a: 0.4, ..palette.error } })
                                .text_color(gpui::white())
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .when(can_reset, |el| el.cursor_pointer())
                                .child(if resetting { "Resetting…" } else { "Reset forever" })
                                .when(can_reset, |el| {
                                    el.on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| {
                                        this.confirm_reset(cx);
                                    }))
                                }),
                        ),
                ),
        )
}
