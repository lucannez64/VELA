//! Port of `desktopVELA/src/components/Sidebar.tsx` — the persistent left
//! nav shown once the vault is unlocked (never during Welcome/Setup/
//! BiometricGate). Matches the original's `w-16 lg:w-64` responsive
//! collapse: below `COLLAPSE_BELOW_WIDTH` the sidebar shrinks to an
//! icon-only rail (labels and the "VELA VAULT" branding block hidden,
//! matching the original's `hidden lg:block`/`hidden lg:inline` classes),
//! read from `window.viewport_size()` each render since gpui has no CSS
//! media-query equivalent to do this declaratively.

use gpui::{div, prelude::*, px, Context, EventEmitter, IntoElement, MouseButton, Render, Window};

use crate::animation;
use crate::fonts;
use crate::icon::icon;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NavView {
    Vault,
    Devices,
    Sharing,
    Audit,
    BreachMonitor,
    Settings,
}

impl NavView {
    const ALL: [NavView; 6] = [
        NavView::Vault,
        NavView::Devices,
        NavView::Sharing,
        NavView::Audit,
        NavView::BreachMonitor,
        NavView::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            NavView::Vault => "Vault",
            NavView::Devices => "Devices",
            NavView::Sharing => "Sharing",
            NavView::Audit => "Audit Log",
            NavView::BreachMonitor => "Breach Monitor",
            NavView::Settings => "Settings",
        }
    }

    fn icon_name(self) -> &'static str {
        match self {
            NavView::Vault => "shield",
            NavView::Devices => "devices",
            NavView::Sharing => "share_reviews",
            NavView::Audit => "history",
            NavView::BreachMonitor => "security",
            NavView::Settings => "settings",
        }
    }
}

/// Below this viewport width the sidebar collapses to icon-only, matching
/// the original's `lg:` breakpoint (1024px) minus a little slack for gpui
/// windows that don't reserve as much OS-chrome width as a browser tab.
const COLLAPSE_BELOW_WIDTH: f32 = 900.;

pub enum SidebarEvent {
    Navigate(NavView),
    AddItem,
    Lock,
}
impl EventEmitter<SidebarEvent> for Sidebar {}

pub struct Sidebar {
    active: NavView,
}

impl Sidebar {
    pub fn new(cx: &mut Context<Self>) -> Self {
        cx.observe_global::<crate::theme::ActiveTheme>(|_, cx| cx.notify()).detach();
        Self { active: NavView::Vault }
    }

    pub fn set_active(&mut self, view: NavView, cx: &mut Context<Self>) {
        self.active = view;
        cx.notify();
    }
}

impl Render for Sidebar {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::current_palette(cx);
        let active = self.active;
        let collapsed = window.viewport_size().width < px(COLLAPSE_BELOW_WIDTH);

        let mut root = div()
            .w(if collapsed { px(72.) } else { px(240.) })
            .h_full()
            .flex()
            .flex_col()
            .bg(palette.surface_container_low)
            .border_r_1()
            .border_color(gpui::Hsla { a: 0.05, ..palette.outline_variant });

        let mut top = div().flex().flex_col().py_6().gap_1();
        if !collapsed {
            top = top.child(
                div()
                    .px_6()
                    .mb_6()
                    .child(
                        fonts::tracked_text("VELA VAULT", px(12.), 0.1)
                            .font_family(fonts::HEADLINE)
                            .font_weight(gpui::FontWeight::BLACK)
                            .text_xs()
                            .text_color(palette.primary),
                    )
                    .child(
                        fonts::tracked_text("Zero-Knowledge Active", px(10.), -0.05)
                            .text_color(palette.outline)
                            .text_size(px(10.)),
                    ),
            );
        }
        top = top.children(NavView::ALL.iter().map(|&view| {
            let selected = view == active;
            let base_bg = if selected { palette.surface_container } else { palette.surface_container_low };
            let base_text = if selected { palette.primary } else { palette.on_surface_variant };
            let hover_t = (!selected)
                .then(|| animation::hover_transition(format!("nav-{}", view.label()), window, cx));
            let (bg, text_color) = if let Some(hover_t) = &hover_t {
                let t = *hover_t.evaluate(window, cx);
                let bg = animation::lerp_hsla(base_bg, palette.surface_container, t);
                let text_color = animation::lerp_hsla(base_text, palette.primary, t);
                (bg, text_color)
            } else {
                (base_bg, base_text)
            };
            let mut row = div()
                .id(view.label())
                .py_3()
                .flex()
                .items_center()
                .gap_3()
                .text_sm()
                .font_family(fonts::BODY)
                .cursor_pointer()
                .border_l_2()
                .border_color(if selected { palette.primary } else { gpui::transparent_black() })
                .bg(bg)
                .text_color(text_color)
                .child(icon(view.icon_name(), px(18.), text_color));
            row = if collapsed {
                row.justify_center().px_0()
            } else {
                row.justify_start().px_6()
            };
            if !collapsed {
                row = row.child(view.label());
            }
            if let Some(hover_t) = hover_t {
                row = row.on_hover(move |is_hovered, _, cx| {
                    hover_t.update(cx, |v, cx| {
                        *v = *is_hovered as u8 as f32;
                        cx.notify();
                    });
                });
            }
            row.on_mouse_down(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                this.set_active(view, cx);
                cx.emit(SidebarEvent::Navigate(view));
            }))
        }));
        root = root.child(top).child(div().flex_1());

        let add_item_hover_t = animation::hover_transition("sidebar-add-item", window, cx);
        let add_item_t = *add_item_hover_t.evaluate(window, cx);
        let add_item_bg = animation::lerp_hsla(
            gpui::Hsla { a: 0.1, ..palette.primary },
            gpui::Hsla { a: 0.2, ..palette.primary },
            add_item_t,
        );
        let mut add_item = div()
            .id("sidebar-add-item")
            .py_3()
            .rounded_xl()
            .flex()
            .items_center()
            .justify_center()
            .gap_2()
            .bg(add_item_bg)
            .text_color(palette.primary)
            .font_family(fonts::LABEL)
            .text_sm()
            .cursor_pointer()
            .child(icon("add", px(18.), palette.primary));
        if !collapsed {
            add_item = add_item.child(fonts::tracked_text("Add Item", px(14.), 0.05));
        }
        add_item = add_item
            .on_hover(move |is_hovered, _, cx| {
                add_item_hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                cx.emit(SidebarEvent::AddItem);
            }));

        let lock_hover_t = animation::hover_transition("sidebar-lock", window, cx);
        let lock_t = *lock_hover_t.evaluate(window, cx);
        let lock_bg = animation::lerp_hsla(palette.surface_container_highest, palette.surface_bright, lock_t);
        let mut lock = div()
            .id("sidebar-lock")
            .py_3()
            .rounded_lg()
            .flex()
            .items_center()
            .justify_center()
            .gap_2()
            .bg(lock_bg)
            .text_color(palette.on_surface)
            .font_family(fonts::LABEL)
            .text_xs()
            .cursor_pointer()
            .child(icon("lock", px(18.), palette.on_surface));
        if !collapsed {
            lock = lock.child(fonts::tracked_text("LOCK SESSION", px(12.), 0.1));
        }
        lock = lock
            .on_hover(move |is_hovered, _, cx| {
                lock_hover_t.update(cx, |v, cx| {
                    *v = *is_hovered as u8 as f32;
                    cx.notify();
                });
            })
            .on_mouse_down(MouseButton::Left, cx.listener(|_this, _, _, cx| {
                cx.emit(SidebarEvent::Lock);
            }));

        root.child(
            div()
                .p(if collapsed { px(12.) } else { px(24.) })
                .flex()
                .flex_col()
                .gap_3()
                .child(add_item)
                .child(lock),
        )
    }
}
