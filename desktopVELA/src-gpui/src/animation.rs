//! Continuous decorative animations (pulse/ping) matching the original's CSS
//! `@keyframes pulse`/`@keyframes ping` (see `desktopVELA/src/index.css`).
//!
//! These are driven by a `cx.spawn` notify-loop in the owning view (same
//! idiom as `BiometricGate`'s lockout countdown / `ItemDetail`'s TOTP tick),
//! not gpui's `Transition` — `Transition` only animates in response to a
//! goal change (e.g. hover on/off, see [`hover_transition`]), it has no
//! built-in repeat/loop. A real infinite CSS keyframe animation still needs
//! *something* to keep nudging state forward forever; the perf-conscious
//! choice here is a low frequency tick (10fps, not 60fps — plenty smooth for
//! a slow "breathing" dot) that's skipped whenever no window is focused,
//! mirroring `index.css`'s own `html.anim-paused` rule that freezes these
//! exact animations when the app is unfocused/occluded so the compositor
//! isn't repainting every frame for no one to see. This matters more than
//! usual in this codebase specifically — the last five commits before this
//! migration started were entirely about killing idle CPU/memory burn in
//! the old WebKit shell, so reintroducing an unconditional 60fps decorative
//! loop here would undo exactly what this rewrite is for.
//!
//! Hover color transitions use gpui's real `Transition<T>` /
//! `window.use_keyed_transition` (confirmed via source: `Transition::
//! evaluate` only calls `window.request_animation_frame()` while the
//! transition is actually in progress, so it stops driving repaints the
//! moment it settles — no custom shader or manual interpolation loop
//! needed, gpui's own GPU-composited paint pipeline already handles the
//! actual drawing efficiently).

use std::time::{SystemTime, UNIX_EPOCH};

use gpui::{ease_in_out, App, AppContext, Context, Hsla, Lerp, Rgba, Task, Window};

/// Tick interval for continuous pulse/ping animations. 10fps is smooth
/// enough for a slow decorative breathing/ping effect and far cheaper than
/// a 60fps loop.
pub const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
/// How long to sleep between activity checks while no window is focused —
/// matches `index.css`'s `anim-paused` freeze, just polled instead of
/// event-driven since gpui has no direct "resumed" callback wired here.
const IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

fn elapsed_secs() -> f32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f32()
}

/// Breathing opacity oscillation matching `@keyframes pulse` (opacity
/// 1 → 0.7 → 1 over a 2s period): `period_secs` lets callers slow/speed it
/// per-use without changing the shape.
pub fn pulse_alpha(period_secs: f32) -> f32 {
    let t = elapsed_secs();
    0.85 + 0.15 * (t * std::f32::consts::TAU / period_secs).cos()
}

/// 0..1 sawtooth for a "ping" ripple (`@keyframes ping`: scale 1→2, opacity
/// 1→0, restarting every `period_secs`). Callers derive scale as
/// `1. + progress` and opacity as `1. - progress`.
pub fn ping_progress(period_secs: f32) -> f32 {
    (elapsed_secs() / period_secs).fract()
}

/// `Hsla` doesn't implement gpui's `Lerp` trait (only `Rgba` does), so hover
/// transitions on this codebase's `Hsla`-typed `Palette` colors go through
/// an `Rgba` round-trip — which also matches how CSS itself blends color
/// transitions (in sRGB space) more closely than a naive per-channel HSL
/// lerp would (HSL lerp can swing through unrelated hues when interpolating
/// alpha-only or lightness-only differences, which is all every call site
/// in this codebase actually needs).
pub fn lerp_hsla(from: Hsla, to: Hsla, t: f32) -> Hsla {
    let from: Rgba = from.into();
    let to: Rgba = to.into();
    from.lerp(&to, t).into()
}

/// Spawns the perf-conscious notify-loop described above. Callers store the
/// returned `Task` in a struct field (dropping it cancels the loop) and read
/// `pulse_alpha`/`ping_progress` directly in `render()` — this task's only
/// job is to keep asking for repaints while something is actually animating
/// and a window is focused.
pub fn spawn_pulse_ticker<T: 'static>(cx: &mut Context<T>) -> Task<()> {
    cx.spawn(async move |this, cx| loop {
        let active = cx.update(|cx| cx.active_window().is_some());
        if !active {
            cx.background_spawn(async { std::thread::sleep(IDLE_POLL_INTERVAL) }).await;
            continue;
        }
        let alive = this.update(cx, |_, cx| cx.notify()).is_ok();
        if !alive {
            break;
        }
        cx.background_spawn(async { std::thread::sleep(TICK_INTERVAL) }).await;
    })
}

/// Smooth hover color transition — the real gpui `Transition` primitive
/// (ease-in-out, 150ms), not a manual lerp loop. Returns the transition
/// handle; callers `.evaluate(window, cx)` it for this frame's value and
/// clone it into an `.on_hover(...)` callback to drive the next one:
///
/// ```ignore
/// let hover_t = animation::hover_transition("my-button", window, cx);
/// let t = *hover_t.evaluate(window, cx);
/// let bg = base.lerp(&hover_bg, t);
/// div().bg(bg).on_hover({
///     let hover_t = hover_t.clone();
///     move |is_hovered, _window, cx| {
///         hover_t.update(cx, |v, cx| { *v = *is_hovered as u8 as f32; cx.notify(); });
///     }
/// })
/// ```
///
/// Takes `cx: &mut App` directly (not `Context<T>`) so it also works inside
/// `uniform_list`'s per-row callback, which only hands out `&mut Window` +
/// `&mut App` — a plain `&mut Context<T>` coerces to this via `DerefMut`
/// at every other call site, so nothing else needs to change.
pub fn hover_transition(
    id: impl Into<gpui::ElementId>,
    window: &mut Window,
    cx: &mut App,
) -> gpui::Transition<f32> {
    window
        .use_keyed_transition(id, cx, std::time::Duration::from_millis(150), |_, _| 0_f32)
        .with_easing(ease_in_out)
}
