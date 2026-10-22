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
    show_code: bool,
    _poll_task: Option<Task<()>>,
    _tick_task: Task<()>,
}

impl EnrollDeviceModal {
    pub fn new(app_state: Arc<AppState>, cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify())
            .detach();
        let mut this = Self {
            app_state,
            phase: Phase::Opening,
            grant_id: None,
            code: None,
            qr_image: None,
            expires_at: None,
            copied: false,
            show_code: false,
            _poll_task: None,
            _tick_task: animation::spawn_pulse_ticker(cx),
        };
        this.start(cx);
        this
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        self.phase = Phase::Opening;
        self.show_code = false;
        self.grant_id = None;
        self.code = None;
        self.qr_image = None;
        self.expires_at = None;
        self._poll_task = None;
        cx.notify();

        let app_state = self.app_state.clone();
        cx.spawn(async move |this, cx| {
            let result =
                gpui_tokio::Tokio::spawn(
                    cx,
                    async move { open_enrollment_invite(&app_state).await },
                )
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
        let Some(grant_id) = self.grant_id.clone() else {
            return;
        };
        let app_state = self.app_state.clone();

        self._poll_task = Some(cx.spawn(async move |this, cx| loop {
            cx.background_spawn(async { std::thread::sleep(POLL_INTERVAL) })
                .await;

            let app_state = app_state.clone();
            let grant_id_inner = grant_id.clone();
            let result = gpui_tokio::Tokio::spawn(cx, async move {
                poll_enrollment_claim(&app_state, &grant_id_inner).await
            })
            .await;

            // A failed poll is not a failed enrollment — the grant is alive
            // until it expires, and the countdown is what tells the user when
            // to give up.
            let Ok(Ok(Some(claim))) = result else {
                continue;
            };

            this.update(cx, |this, cx| {
                this.phase = Phase::Claimed(claim);
                cx.notify();
            })
            .ok();
            break;
        }));
    }

    fn pick(&mut self, choice: String, cx: &mut Context<Self>) {
        let Some(grant_id) = self.grant_id.clone() else {
            return;
        };
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
        let palette = crate::modal::palette(cx);
        let close = crate::modal::close_button("enroll-v3-close", &palette).on_mouse_down(
            MouseButton::Left,
            cx.listener(|this, _, _, cx| this.close(cx)),
        );
        let header = crate::modal::header("Enroll a device", close, &palette);
        let content = div().id("enroll-phase-content").flex().flex_col().gap_4();
        let content = match &self.phase {
            Phase::Opening => content.child(div().py_8().flex().justify_center().child(icon(
                "progress_activity",
                px(32.),
                palette.primary,
            ))),
            Phase::Waiting => self.render_waiting(content, &palette, window, cx),
            Phase::Claimed(claim) => {
                self.render_choices(content, &palette, claim.clone(), window, cx)
            }
            Phase::Confirming => content.child(
                div()
                    .py_8()
                    .text_color(palette.on_surface_variant)
                    .child("Enrolling…"),
            ),
            Phase::Enrolled(name) => self.render_done(content, &palette, name.clone(), window, cx),
            Phase::Rejected => self.render_rejected(content, &palette, window, cx),
            Phase::Failed(error) => {
                self.render_failed(content, &palette, error.clone(), window, cx)
            }
        };
        let mut footer = div().flex().gap_3();
        footer = footer.child(modal_button(
            &palette,
            "enroll-v3-dismiss",
            if matches!(self.phase, Phase::Enrolled(_)) {
                "Done"
            } else {
                "Close"
            },
            ButtonKind::Neutral,
            window,
            cx,
            |this, cx| this.close(cx),
        ));
        footer = match self.phase {
            Phase::Waiting if self.seconds_left() == Some(0) => footer.child(modal_button(
                &palette,
                "enroll-v3-new-code",
                "New code",
                ButtonKind::Primary,
                window,
                cx,
                |this, cx| this.start(cx),
            )),
            Phase::Waiting => footer.child(modal_button(
                &palette,
                "enroll-v3-copy",
                if self.copied { "Copied!" } else { "Copy code" },
                ButtonKind::Primary,
                window,
                cx,
                |this, cx| this.copy_code(cx),
            )),
            Phase::Claimed(_) => footer.child(modal_button(
                &palette,
                "enroll-v3-cancel",
                "Cancel enrollment",
                ButtonKind::Neutral,
                window,
                cx,
                |this, cx| this.cancel(cx),
            )),
            Phase::Rejected | Phase::Failed(_) => footer.child(modal_button(
                &palette,
                "enroll-v3-retry",
                "Try again",
                ButtonKind::Primary,
                window,
                cx,
                |this, cx| this.start(cx),
            )),
            _ => footer,
        };
        let overlay = crate::modal::backdrop("enroll-v3-backdrop")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| this.close(cx)),
            )
            .child(
                crate::modal::frame(
                    "enroll-v3-body",
                    520.,
                    720.,
                    header,
                    crate::modal::scroll_body("enroll-v3-scroll", content),
                    footer,
                    &palette,
                )
                .map(|el| crate::keyboard::trap_tab(el, "enroll-v3-trap", window, cx))
                .on_key_down(cx.listener(
                    |this, event: &gpui::KeyDownEvent, _, cx| {
                        if event.keystroke.key == "escape" {
                            cx.stop_propagation();
                            this.close(cx);
                        }
                    },
                ))
                .map(|card| crate::modal::animate(card, palette.instrument, false)),
            );
        crate::modal::present(window, overlay)
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

        let qr_edge = (f32::from(window.viewport_size().height) - 300.).clamp(144., 280.);
        el.when(palette.instrument, |el| el.child(
            div().py(px(8.))
                .child(crate::instrument::mono("01 / CONNECT A DEVICE", palette.on_surface_variant))
                .child(div().text_size(px(30.)).font_family(fonts::HEADLINE).mt(px(12.)).child("Your vault. Another device."))
                .child(div().mt(px(8.)).text_size(px(13.)).text_color(palette.on_surface_variant).child("Scan to join, then verify the matching codes."))))
        .when_some(self.qr_image.clone(), |el, image| {
            el.child(
                div()
                    .w_full().max_w(px(qr_edge + 24.)).self_center()
                    .debug_selector(|| "enroll-v3-qr".into())
                    .p_3()
                    .rounded_xl()
                    .bg(gpui::white())
                    .flex()
                    .justify_center()
                    .child(img(ImageSource::Image(image)).w_full().max_w(px(qr_edge)).aspect_square().object_fit(gpui::ObjectFit::Contain)),
            )
        })
        .child(div().text_sm().text_color(palette.on_surface_variant)
            .child("On your other device, choose Join existing account and scan this code. Then compare the short codes on both screens."))
        .child(div().id("enroll-v3-show-code").text_sm().text_color(palette.primary).cursor_pointer()
            .child(if self.show_code { "Hide manual enrollment code" } else { "Can’t scan? Show enrollment code" })
            .on_mouse_down(MouseButton::Left, cx.listener(|this, _, _, cx| { this.show_code = !this.show_code; cx.notify(); })))
        .when(self.show_code, |el| el.when_some(self.code.clone(), |el, code| el.child(
            div().id("enroll-v3-manual-code").p_3().rounded_lg().bg(palette.surface_bright)
                .font_family(fonts::MONO).text_xs().text_color(palette.on_surface)
                .overflow_x_scroll().whitespace_nowrap().child(code))))
        .child(
            div()
                .text_xs()
                .text_color(palette.on_surface_variant)
                .child("Only approve a device when the short codes match. You can close this dialog and resume until the invitation expires."),
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
                        format!("Waiting for scan · {}:{:02} left", s / 60, s % 60)
                    }
                    (false, None) => "Waiting for a device to scan".to_string(),
                }),
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
            let only = claim
                .fingerprint_choices
                .first()
                .cloned()
                .unwrap_or_default();
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
        }
    }

    fn render_done(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        name: SharedString,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        el.child(
            div()
                .p_4()
                .rounded_xl()
                .bg(gpui::Hsla {
                    a: 0.1,
                    ..palette.primary
                })
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
    }

    fn render_rejected(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        _window: &mut Window,
        _cx: &mut Context<Self>,
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
    }

    fn render_failed(
        &self,
        el: gpui::Stateful<gpui::Div>,
        palette: &Palette,
        error: SharedString,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        el.child(div().text_sm().text_color(palette.error).child(error))
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
        gpui::Hsla {
            a: 0.2,
            ..palette.outline_variant
        },
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
            animation::lerp_hsla(
                palette.primary,
                gpui::Hsla {
                    a: 0.9,
                    ..palette.primary
                },
                t,
            ),
            palette.on_primary,
        ),
        ButtonKind::Neutral => (
            animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, t),
            palette.on_surface,
        ),
    };

    div()
        .id(id)
        .debug_selector(move || id.to_owned())
        .flex_1()
        .min_w_0()
        .min_h(px(44.))
        .py_3()
        .rounded_xl()
        .when(palette.instrument, |el| el.rounded_full().border_1().border_color(palette.outline_variant).text_size(px(13.)))
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
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(move |this, _, _, cx| on_click(this, cx)),
        )
}

#[cfg(test)]
mod modal_tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{point, size, Entity, Modifiers, ScrollDelta, ScrollWheelEvent, TestAppContext};
    use std::{cell::Cell, rc::Rc};

    struct Host {
        child: Entity<EnrollDeviceModal>,
        _subscription: gpui::Subscription,
    }
    impl Render for Host {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            div().relative().size_full().child(self.child.clone())
        }
    }

    #[gpui::test]
    fn enrollment_stages_fit_and_close_after_scrolling(cx: &mut TestAppContext) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let directory = tempfile::tempdir().unwrap();
        for instrument in [false, true] {
        for stage in 0..7 {
            for (width, height) in [(945., 508.), (360., 480.)] {
                let state = ui::state(&directory);
                let closes = Rc::new(Cell::new(0));
                let (host, cx) = cx.add_window_view(|_, cx| {
                    ui::fonts(cx);
                    cx.set_global(crate::instrument::ActiveInterface(if instrument {
                        crate::instrument::InterfaceMode::Instrument
                    } else { crate::instrument::InterfaceMode::Classic }));
                    let child = cx.new(|_| {
                        let code = "VELA-ENROLL:v3:synthetic-layout-verification";
                        EnrollDeviceModal {
                            app_state: state,
                            phase: match stage {
                                0 => Phase::Opening,
                                1 => Phase::Waiting,
                                2 => Phase::Claimed(ClaimedDevice {
                                    device_name: Some(
                                        "A device with a long name for testing".into(),
                                    ),
                                    device_type: Some("desktop".into()),
                                    fingerprint_choices: vec![
                                        "123-456".into(),
                                        "234-567".into(),
                                        "345-678".into(),
                                    ],
                                    decoys_unavailable: false,
                                }),
                                3 => Phase::Confirming,
                                4 => Phase::Enrolled("Example device".into()),
                                5 => Phase::Rejected,
                                _ => Phase::Failed("Synthetic network error".into()),
                            },
                            grant_id: Some("synthetic".into()),
                            code: Some(code.into()),
                            qr_image: crate::qr::render_qr_image(code, 6).map(Arc::new),
                            expires_at: Some(Instant::now() + Duration::from_secs(300)),
                            copied: false,
                            show_code: true,
                            _poll_task: None,
                            _tick_task: Task::ready(()),
                        }
                    });
                    let _subscription = cx.subscribe(&child, {
                        let closes = closes.clone();
                        move |_: &mut Host, _, event, _| {
                            if matches!(event, EnrollDeviceModalEvent::Close) {
                                closes.set(closes.get() + 1);
                            }
                        }
                    });
                    Host {
                        child,
                        _subscription,
                    }
                });
                cx.simulate_resize(size(px(width), px(height)));
                cx.run_until_parked();
                let close = ui::bounds(cx, "enroll-v3-close");
                let footer = ui::bounds(cx, "enroll-v3-body-footer");
                let body = ui::bounds(cx, "enroll-v3-scroll");
                assert!(close.top() >= px(56.) && footer.bottom() <= px(height));
                if stage == 1 {
                    let qr = ui::bounds(cx, "enroll-v3-qr");
                    assert!(
                        qr.size.height <= body.size.height - px(24.),
                        "QR is taller than visible enrollment content"
                    );
                }
                cx.simulate_event(ScrollWheelEvent {
                    position: body.center(),
                    delta: ScrollDelta::Pixels(point(px(0.), px(-3000.))),
                    ..Default::default()
                });
                cx.run_until_parked();
                assert_eq!(ui::bounds(cx, "enroll-v3-close"), close);
                assert_eq!(ui::bounds(cx, "enroll-v3-body-footer"), footer);
                cx.simulate_click(close.center(), Modifiers::default());
                cx.run_until_parked();
                assert_eq!(
                    closes.get(),
                    1,
                    "enrollment stage {stage} cannot close at {width}×{height}"
                );
                drop(host);
            }
        }
        }
    }
}
