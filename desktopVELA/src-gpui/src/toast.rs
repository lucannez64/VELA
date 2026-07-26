//! Native port of the original's global toast notification
//! (`src/context/AppContext.tsx`'s `showToast()` + `src/components/Toast.tsx`):
//! a single, bottom-center, 3s-auto-dismissing message with 3 color/icon
//! variants (success/error/info).
//!
//! Backed by a plain gpui [`Global`] rather than an `Entity` owned by one
//! view, so any screen can call [`show`] the same way the original's
//! components call `useApp().showToast()` from anywhere in the component
//! tree, with no need to thread a shared entity handle through every call
//! site. [`render`] is mounted once at the app root (`RootView`) and reads
//! the global directly.

use std::time::Duration;

use gpui::{div, prelude::*, px, App, Global, Hsla, IntoElement, SharedString, Task};

use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

struct ToastEntry {
    message: SharedString,
    kind: ToastKind,
    id: u64,
}

/// `pub(crate)` only so `main.rs` can name it for `cx.observe_global::<...>`
/// to trigger a repaint when a toast appears/disappears — its fields stay
/// private, nothing outside this module touches them.
#[derive(Default)]
pub(crate) struct ToastGlobal {
    current: Option<ToastEntry>,
    next_id: u64,
    _dismiss_task: Option<Task<()>>,
}
impl Global for ToastGlobal {}

/// Matches the original's `toastTimerRef` timeout (`AppContext.tsx`) exactly.
const DISMISS_AFTER: Duration = Duration::from_secs(3);

/// Shows a toast, replacing whatever's currently showing — same single-slot,
/// timer-reset behavior as the original (a new toast cancels the old
/// dismiss timer rather than queuing behind it).
pub fn show(cx: &mut App, message: impl Into<SharedString>, kind: ToastKind) {
    let message = message.into();
    let id = {
        let global = cx.default_global::<ToastGlobal>();
        global.next_id += 1;
        global.next_id
    };
    let dismiss_task = cx.spawn(async move |cx| {
        cx.background_executor().timer(DISMISS_AFTER).await;
        cx.update(|cx| {
            let still_current = cx
                .try_global::<ToastGlobal>()
                .and_then(|g| g.current.as_ref())
                .map(|t| t.id)
                == Some(id);
            if still_current {
                cx.global_mut::<ToastGlobal>().current = None;
            }
        });
    });
    let global = cx.global_mut::<ToastGlobal>();
    global.current = Some(ToastEntry { message, kind, id });
    global._dismiss_task = Some(dismiss_task);
}

/// Renders the active toast, or `None` if none is showing. Caller is
/// responsible for placing this inside a `.relative()` ancestor sized to
/// the whole window (see `main.rs`'s `RootView::render`) — matches the
/// original's `fixed bottom-6 left-1/2 -translate-x-1/2 z-50` positioning,
/// just expressed via flex-centering instead of a CSS transform (gpui has
/// no transform primitive for this).
pub fn render(palette: &Palette, cx: &App) -> Option<impl IntoElement> {
    let entry = cx.try_global::<ToastGlobal>()?.current.as_ref()?;
    let message = entry.message.clone();
    let (accent, icon_name): (Hsla, &'static str) = match entry.kind {
        ToastKind::Success => (palette.primary, "check_circle"),
        ToastKind::Error => (palette.error, "error"),
        ToastKind::Info => (palette.secondary, "info"),
    };

    Some(
        div()
            .absolute()
            .bottom_6()
            .left_0()
            .right_0()
            .flex()
            .justify_center()
            .px_4()
            .child(
                div()
                    .max_w(px(480.))
                    .px_6()
                    .py_3()
                    .rounded_xl()
                    .border_1()
                    .border_color(accent)
                    .bg(gpui::Hsla { a: 0.85, ..palette.surface_container_high })
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(icon(icon_name, px(18.), accent))
                    .child(
                        div()
                            .font_family(fonts::BODY)
                            .text_sm()
                            .text_color(palette.on_surface)
                            .child(message),
                    ),
            ),
    )
}
