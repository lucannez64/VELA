//! Enroll a new device (enrollment v3, audit P-1). Peer of
//! `desktopVELA/src/components/EnrollDeviceModal.tsx`.
//!
//! The QR here carries a one-time grant and a server URL and nothing else. The
//! joining device generates its own keys and sends only the public half, so a
//! photograph of this screen buys an enrollment *attempt* — where a v2 code was
//! the vault itself, permanently.
//!
//! That moves the risk onto the fingerprint step, so the question asked there is
//! deliberately not "do these match?". Yes is the habitual answer and a yes/no
//! prompt fails open. The real fingerprint is shown among indistinguishable
//! decoys and the user picks the one their other device displays, so not looking
//! fails three times in four.
//!
//! Neither of the two things that make that real is decided here: the candidate
//! list is built once per claim by `vela_desktop_core` and cached, and a wrong
//! pick discards the enrollment there rather than offering another guess. This
//! view cannot re-roll the list or retry a rejected pick, and should not gain
//! the ability to.

use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::{
    div, img, prelude::*, px, Context, EventEmitter, Image, ImageSource, IntoElement, MouseButton,
    Render, SharedString, Task, Window,
};

use vela_desktop_core::commands::enrollment_v3::{
    cancel_enrollment, confirm_enrollment, open_enrollment_invite, poll_enrollment_claim,
    ClaimedDevice,
};
use vela_desktop_core::AppState;

use crate::animation;
use crate::fonts;
use crate::icon::icon;
use crate::theme::Palette;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub enum EnrollDeviceModalEvent {
    Close,
    /// A device was really enrolled — the owner should reload its device list.
    Enrolled,
}
impl EventEmitter<EnrollDeviceModalEvent> for EnrollDeviceModal {}

/// What is on screen. The states are exclusive: once a claim arrives the QR is
/// gone, and once a pick is made there is nothing to go back to.
enum Phase {
    Opening,
    /// Grant is live, nobody has claimed it yet.
    Waiting,
    /// A device claimed it; the user has to pick its fingerprint.
    Claimed(ClaimedDevice),
    Confirming,
    Enrolled(SharedString),
    /// Wrong pick. Not a retry state — the enrollment is gone.
    Rejected,
    Failed(SharedString),
}

pub struct EnrollDeviceModal {
    app_state: Arc<AppState>,
    phase: Phase,
    grant_id: Option<String>,
    code: Option<String>,
    qr_image: Option<Arc<Image>>,
    expires_at: Option<Instant>,
    copied: bool,
    _poll_task: Option<Task<()>>,
    _tick_task: Task<()>,
}

impl EnrollDeviceModal {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        let mut this = Self {
            app_state,
            phase: Phase::Opening,
            grant_id: None,
            code: None,
            qr_image: None,
            expires_at: None,
            copied: false,
            _poll_task: None,
            _tick_task: animation::spawn_pulse_ticker(cx),
        };
        this.start(cx);
        this
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        self.phase = Phase::Opening;
        self.grant_id = None;
        self.code = None;
        self.qr_image = None;
        self.expires_at = None;
        self._poll_task = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                open_enrollment_invite(&app_state).await
            })
            .await;

            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(invite)) => {
                        // A v3 code is a grant id and a URL, so it always fits
                        // one QR — v2 carried a whole keypair and had to be
                        // split into a carousel of them.
                        this.qr_image = crate::qr::render_qr_image(&invite.code, 6).map(Arc::new);
                        this.expires_at =
                            Some(Instant::now() + Duration::from_secs(invite.expires_in));
                        this.grant_id = Some(invite.grant_id);
                        this.code = Some(invite.code);
                        this.phase = Phase::Waiting;
                        this.spawn_poll(cx);
                    }
                    Ok(Err(e)) => this.phase = Phase::Failed(e.into()),
                    Err(e) => this.phase = Phase::Failed(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Poll until a device claims the grant, then stop.
    ///
    /// Stopping matters: from the moment a claim exists the candidate list is
    /// fixed, and re-fetching it could only redraw the list while the user is
    /// reading it.
    fn spawn_poll(&mut self, cx: &mut Context<Self>) {
        let Some(grant_id) = self.grant_id.clone() else { return };
        let app_state = self.app_state.clone();

        self._poll_task = Some(cx.spawn(async move |this, cx| loop {
            cx.background_spawn(async { std::thread::sleep(POLL_INTERVAL) }).await;

            let app_state = app_state.clone();
            let grant_id_inner = grant_id.clone();
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                poll_enrollment_claim(&app_state, &grant_id_inner).await
            })
            .await;

            // A failed poll is not a failed enrollment — the grant is alive
            // until it expires, and the countdown is what tells the user when
            // to give up.
            let Ok(Ok(Some(claim))) = result else { continue };

            this.update(cx, |this, cx| {
                this.phase = Phase::Claimed(claim);
                cx.notify();
            })
            .ok();
            break;
        }));
    }

    fn pick(&mut self, choice: String, cx: &mut Context<Self>) {
        let Some(grant_id) = self.grant_id.clone() else { return };
        let device_label = match &self.phase {
            Phase::Claimed(claim) => claim
                .device_name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "The new device".to_string()),
            _ => "The new device".to_string(),
        };
        self.phase = Phase::Confirming;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                confirm_enrollment(&app_state, &grant_id, &choice).await
            })
            .await;

            this.update(cx, |this, cx| {
                match result {
                    Ok(Ok(_)) => {
                        this.phase = Phase::Enrolled(device_label.into());
                        cx.emit(EnrollDeviceModalEvent::Enrolled);
                    }
                    // A wrong pick is not an error to retry: the core has
                    // already discarded the enrollment.
                    Ok(Err(_)) => this.phase = Phase::Rejected,
                    Err(e) => this.phase = Phase::Failed(format!("Task failed: {e}").into()),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Dismiss the dialog without killing the enrollment.
    ///
    /// The joining device is about to be walked through its own screens and
    /// this one is in the way. When it is reopened, `open_enrollment_invite`
    /// resumes the same grant and the poll picks up the claim — otherwise the
    /// user would come back to a dead code and a joining device stuck on a
    /// fingerprint to pick.
    fn close(&mut self, cx: &mut Context<Self>) {
        self._poll_task = None;
        cx.emit(EnrollDeviceModalEvent::Close);
    }

    /// A deliberate abort, unlike `close` above.
    fn cancel(&mut self, cx: &mut Context<Self>) {
        cancel_enrollment(&self.app_state);
        self.close(cx);
    }

    fn copy_code(&mut self, cx: &mut Context<Self>) {
        if let Some(code) = self.code.clone() {
            crate::clipboard::copy(cx, "Enrollment code", &code);
            self.copied = true;
            cx.notify();
        }
    }

    fn seconds_left(&self) -> Option<u64> {
        self.expires_at
            .map(|at| at.saturating_duration_since(Instant::now()).as_secs())
    }
}

impl Render for EnrollDeviceModal {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);

        div()
            .id("enroll-v3-backdrop")
            .absolute()
            .inset_0()
            .bg(gpui::Hsla { a: 0.6, h: 0., s: 0., l: 0. })
            .flex()
            .items_center()
            .justify_center()
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| this.close(cx)))
            .child(
                div()
                    .id("enroll-v3-body")
                    .w(px(440.))
                    .p_8()
                    .rounded_2xl()
                    .bg(palette.surface_container)
                    .border_1()
                    .border_color(gpui::Hsla { a: 0.2, ..palette.outline_variant })
                    .flex()
                    .flex_col()
                    .gap_4()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(icon("add_to_queue", px(24.), palette.primary))
                            .child(
                                div()
                                    .font_family(fonts::HEADLINE)
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .text_xl()
                                    .text_color(palette.on_surface)
                                    .child("Enroll a new device"),
                            ),
                    )
                    .map(|el| match &self.phase {
                        Phase::Opening => el.child(
                            div()
                                .flex()
                                .items_center()
                                .justify_center()
                                .py_16()
                                .child(
                                    icon("progress_activity", px(32.), palette.primary)
                                        .opacity(animation::pulse_alpha(1.0)),
                                ),
                        ),
                        Phase::Waiting => self.render_waiting(el, &palette, window, cx),
                        Phase::Claimed(claim) => {
                            self.render_choices(el, &palette, claim.clone(), window, cx)
                        }
                        Phase::Confirming => el.child(
                            div()
                                .py_16()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_color(palette.on_surface_variant)
                                .child("Enrolling…"),
                        ),
                        Phase::Enrolled(name) => self.render_done(el, &palette, name.clone(), window, cx),
                        Phase::Rejected => self.render_rejected(el, &palette, window, cx),
                        Phase::Failed(error) => {
                            self.render_failed(el, &palette, error.clone(), window, cx)
                        }
                    }),
            )
    }
}

impl EnrollDeviceModal {
    fn render_waiting(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let secs = self.seconds_left();
        let expired = secs == Some(0);
        let copied = self.copied;

        el.child(
            div()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child("On the new device, choose \"Join existing account\" and scan this code. You will then be asked to confirm a short code shown on both screens."),
        )
        .when_some(self.qr_image.clone(), |el, image| {
            el.child(
                div()
                    .p_3()
                    .rounded_xl()
                    .bg(gpui::white())
                    .flex()
                    .justify_center()
                    .child(img(ImageSource::Image(image)).w(px(280.)).h(px(280.))),
            )
        })
        .when_some(self.code.clone(), |el, code| {
            el.child(
                div()
                    .p_3()
                    .rounded_xl()
                    .bg(palette.surface_bright)
                    .font_family(fonts::MONO)
                    .text_xs()
                    .text_color(palette.on_surface)
                    .child(code),
            )
        })
        .child(
            div()
                .text_xs()
                .text_color(palette.on_surface_variant)
                .child("This code cannot unlock your vault on its own — it only lets one device ask to join, once. You still have to confirm which device that was. You can close this window and come back later; it will pick up where it left off until the code expires."),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_2()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child(
                    icon("sync", px(16.), palette.on_surface_variant)
                        .opacity(animation::pulse_alpha(1.0)),
                )
                .child(match (expired, secs) {
                    (true, _) => "This code has expired.".to_string(),
                    (false, Some(s)) => {
                        format!("Waiting for a device to scan · expires in {}:{:02}", s / 60, s % 60)
                    }
                    (false, None) => "Waiting for a device to scan".to_string(),
                }),
        )
        .child(
            div().flex().gap_3().w_full()
                .map(|el| if expired {
                    el.child(modal_button(
                        palette,
                        "enroll-v3-new-code",
                        "New code",
                        ButtonKind::Primary,
                        window,
                        cx,
                        |this, cx| this.start(cx),
                    ))
                } else {
                    el.child(modal_button(
                        palette,
                        "enroll-v3-copy",
                        if copied { "Copied!" } else { "Copy code" },
                        ButtonKind::Primary,
                        window,
                        cx,
                        |this, cx| this.copy_code(cx),
                    ))
                })
                .child(modal_button(
                    palette,
                    "enroll-v3-cancel",
                    "Close",
                    ButtonKind::Neutral,
                    window,
                    cx,
                    |this, cx| this.close(cx),
                )),
        )
    }

    fn render_choices(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        claim: ClaimedDevice,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let label = claim
            .device_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "The new device".to_string());
        let type_suffix = claim
            .device_type
            .clone()
            .filter(|t| !t.trim().is_empty())
            .map(|t| format!(" ({t})"))
            .unwrap_or_default();

        let el = el.child(
            div()
                .text_sm()
                .text_color(palette.on_surface_variant)
                .child(format!(
                    "{label}{type_suffix} is asking to join. It is showing a code on its screen. Pick the same code below to give it your vault."
                )),
        );

        if claim.decoys_unavailable {
            // No OS randomness, so no decoys. A guessable decoy set would look
            // like a check without being one, so the core returned the single
            // true value — this falls back to a plain comparison and says so.
            let only = claim.fingerprint_choices.first().cloned().unwrap_or_default();
            el.child(
                div()
                    .p_4()
                    .rounded_xl()
                    .bg(gpui::Hsla { a: 0.1, ..palette.primary })
                    .text_xs()
                    .text_color(palette.on_surface_variant)
                    .child("This device could not generate the usual set of alternatives, so compare the two codes yourself instead of picking from a list."),
            )
            .child(
                div()
                    .py_4()
                    .rounded_xl()
                    .bg(palette.surface_bright)
                    .flex()
                    .justify_center()
                    .font_family(fonts::MONO)
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_xl()
                    .text_color(palette.on_surface)
                    .child(only.clone()),
            )
            .child(modal_button(
                palette,
                "enroll-v3-match",
                "The codes match — enroll it",
                ButtonKind::Primary,
                window,
                cx,
                move |this, cx| this.pick(only.clone(), cx),
            ))
            .child(modal_button(
                palette,
                "enroll-v3-nomatch",
                "They do not match — cancel",
                ButtonKind::Neutral,
                window,
                cx,
                |this, cx| this.cancel(cx),
            ))
        } else {
            el.child(
                div()
                    .text_xs()
                    .text_color(palette.on_surface_variant)
                    .child(format!(
                        "Only one of these is real. If none of them matches what {label} shows, cancel — do not guess."
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .children(claim.fingerprint_choices.iter().enumerate().map(
                        |(index, choice)| {
                            let choice = choice.clone();
                            fingerprint_choice_button(palette, index, choice, window, cx)
                        },
                    )),
            )
            .child(modal_button(
                palette,
                "enroll-v3-none-match",
                "None of these match — cancel",
                ButtonKind::Neutral,
                window,
                cx,
                |this, cx| this.cancel(cx),
            ))
        }
    }

    fn render_done(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        name: SharedString,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        el.child(
            div()
                .p_4()
                .rounded_xl()
                .bg(gpui::Hsla { a: 0.1, ..palette.primary })
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(icon("check_circle", px(18.), palette.primary))
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_sm()
                                .text_color(palette.primary)
                                .child("Device enrolled"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child(format!(
                            "{name} now has access to your vault. It is downloading the vault now."
                        )),
                ),
        )
        .child(modal_button(
            palette,
            "enroll-v3-done",
            "Done",
            ButtonKind::Primary,
            window,
            cx,
            |this, cx| this.close(cx),
        ))
    }

    fn render_rejected(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        el.child(
            div()
                .p_4()
                .rounded_xl()
                .bg(gpui::Hsla { a: 0.1, ..palette.error })
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(icon("gpp_maybe", px(18.), palette.error))
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::BOLD)
                                .text_sm()
                                .text_color(palette.error)
                                .child("Enrollment cancelled"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(palette.on_surface_variant)
                        .child("That was not the code the other device is showing, so nothing was enrolled. If you picked in a hurry, start again and compare the two screens carefully. If you are certain you picked the code your device displayed, stop: something else answered this enrollment, and it should not be retried on this network."),
                ),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .w_full()
                .child(modal_button(
                    palette,
                    "enroll-v3-restart",
                    "Start again",
                    ButtonKind::Neutral,
                    window,
                    cx,
                    |this, cx| this.start(cx),
                ))
                .child(modal_button(
                    palette,
                    "enroll-v3-close",
                    "Close",
                    ButtonKind::Primary,
                    window,
                    cx,
                    |this, cx| this.close(cx),
                )),
        )
    }

    fn render_failed(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        error: SharedString,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        el.child(div().text_sm().text_color(palette.error).child(error))
            .child(
                div()
                    .flex()
                    .gap_3()
                    .w_full()
                    .child(modal_button(
                        palette,
                        "enroll-v3-retry",
                        "Try again",
                        ButtonKind::Neutral,
                        window,
                        cx,
                        |this, cx| this.start(cx),
                    ))
                    .child(modal_button(
                        palette,
                        "enroll-v3-fail-close",
                        "Close",
                        ButtonKind::Primary,
                        window,
                        cx,
                        |this, cx| this.close(cx),
                    )),
            )
    }
}

/// One candidate. Styled identically to every other candidate on purpose: a
/// decoy that looked different would let the user pick correctly without
/// reading their other device's screen, which is the whole point.
fn fingerprint_choice_button(
    palette: &Palette,
    index: usize,
    choice: String,
    window: &mut Window,
    cx: &mut Context<EnrollDeviceModal>,
) -> impl IntoElement {
    let id = SharedString::from(format!("enroll-v3-choice-{index}"));
    let hover_t = animation::hover_transition(id.clone(), window, cx);
    let t = *hover_t.evaluate(window, cx);
    let bg = animation::lerp_hsla(palette.surface_bright, palette.surface_container_highest, t);
    let border = animation::lerp_hsla(
        gpui::Hsla { a: 0.2, ..palette.outline_variant },
        palette.primary,
        t,
    );

    div()
        .id(id)
        .w_full()
        .py_4()
        .px_4()
        .rounded_xl()
        .bg(bg)
        .border_1()
        .border_color(border)
        .flex()
        .items_center()
        .justify_center()
        .font_family(fonts::MONO)
        .font_weight(gpui::FontWeight::BOLD)
        .text_lg()
        .text_color(palette.on_surface)
        .cursor_pointer()
        .child(choice.clone())
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |this, _, _, cx| this.pick(choice.clone(), cx)),
        )
}

#[derive(Clone, Copy)]
enum ButtonKind {
    Primary,
    Neutral,
}

fn modal_button(
    palette: &Palette,
    id: &'static str,
    label: impl Into<SharedString>,
    kind: ButtonKind,
    window: &mut Window,
    cx: &mut Context<EnrollDeviceModal>,
    on_click: impl Fn(&mut EnrollDeviceModal, &mut Context<EnrollDeviceModal>) + 'static,
) -> impl IntoElement {
    let hover_t = animation::hover_transition(id, window, cx);
    let t = *hover_t.evaluate(window, cx);
    let (bg, fg) = match kind {
        ButtonKind::Primary => (
            animation::lerp_hsla(palette.primary, gpui::Hsla { a: 0.9, ..palette.primary }, t),
            palette.on_primary,
        ),
        ButtonKind::Neutral => (
            animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t),
            palette.on_surface,
        ),
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
        .text_color(fg)
        .font_weight(gpui::FontWeight::MEDIUM)
        .cursor_pointer()
        .child(label.into())
        .on_hover(move |is_hovered, _, cx| {
            hover_t.update(cx, |v, cx| {
                *v = *is_hovered as u8 as f32;
                cx.notify();
            });
        })
        .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| on_click(this, cx)))
}
