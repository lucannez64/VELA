//! VELA controls shared by existing screens and richer-item/collection views.
//! Form geometry and action buttons come from AddItemModal; section headings
//! come from Settings; navigation styling comes from Sidebar.
use crate::{fonts, icon::icon, theme::Palette};
use gpui::{div, prelude::*, px, Div, Entity, IntoElement, SharedString, Stateful};
use gpui_elements::editable_text::{text_input, EditableTextElement, EditableTextState};

#[derive(Clone, Copy)]
pub enum ButtonKind {
    Primary,
    Secondary,
}

pub fn button(
    id: String,
    label: impl Into<SharedString>,
    kind: ButtonKind,
    p: &Palette,
) -> Stateful<Div> {
    let primary = matches!(kind, ButtonKind::Primary);
    let selector = id.clone();
    #[cfg(test)]
    let label_selector = format!("{id}-label");
    let button = div();
    #[cfg(test)]
    let button = button.on_children_prepainted(move |bounds, _, cx| {
        if let Some(bounds) = bounds.first() {
            cx.default_global::<ActionLabelBounds>()
                .0
                .insert(label_selector.clone(), *bounds);
        }
    });
    button
        .id(SharedString::from(id))
        .debug_selector(move || selector.clone())
        .flex()
        .items_center()
        .justify_center()
        .min_w_0()
        .max_w_full()
        .flex_shrink_0()
        .gap_2()
        .px_4()
        .py_3()
        .rounded_xl()
        .font_family(fonts::BODY)
        .text_base()
        .font_weight(if primary {
            gpui::FontWeight::BOLD
        } else {
            gpui::FontWeight::MEDIUM
        })
        .bg(if primary {
            p.primary
        } else if p.instrument {
            gpui::transparent_black()
        } else {
            p.surface_container_highest
        })
        .text_color(if primary { p.on_primary } else { p.on_surface })
        .hover(move |el| {
            el.bg(if p.instrument {
                if primary {
                    crate::instrument::alpha(p.primary, 0.9)
                } else {
                    crate::instrument::alpha(p.on_surface, 0.06)
                }
            } else if primary {
                gpui::Hsla {
                    a: 0.9,
                    ..p.primary
                }
            } else {
                p.surface_bright
            })
        })
        .cursor_pointer()
        .text_center()
        .whitespace_normal()
        .when(p.instrument, |el| el.rounded_full().py(px(10.)).text_size(px(13.)).font_weight(gpui::FontWeight::MEDIUM)
            .border_1().border_color(if primary { p.primary } else { p.outline_variant }))
        .child(label.into())
}

#[cfg(test)]
#[derive(Default)]
struct ActionLabelBounds(std::collections::HashMap<String, gpui::Bounds<gpui::Pixels>>);
#[cfg(test)]
impl gpui::Global for ActionLabelBounds {}
#[cfg(test)]
pub(crate) fn action_label_bounds(
    cx: &mut gpui::VisualTestContext,
    id: &str,
) -> gpui::Bounds<gpui::Pixels> {
    cx.update(|_, cx| cx.global::<ActionLabelBounds>().0[id])
}

pub fn secondary_button(id: String, label: impl Into<SharedString>, p: &Palette) -> Stateful<Div> {
    button(id, label, ButtonKind::Secondary, p)
}
pub fn primary_button(id: String, label: impl Into<SharedString>, p: &Palette) -> Stateful<Div> {
    button(id, label, ButtonKind::Primary, p)
}

pub fn form_label(label: &str, p: &Palette) -> Div {
    fonts::tracked_text(&label.to_uppercase(), px(12.), 0.1)
        .font_family(fonts::LABEL)
        .text_xs()
        .text_color(p.outline)
        .when(p.instrument, |el| el.font_family(fonts::MONO).text_size(px(10.)).text_color(p.on_surface_variant))
}
pub fn labeled_field(p: &Palette, label: &str, field: impl IntoElement) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .min_w_0()
        .child(form_label(label, p))
        .child(field)
}

pub fn text_field(
    id: impl Into<gpui::ElementId>,
    state: &Entity<EditableTextState>,
    p: &Palette,
) -> EditableTextElement {
    text_input(id)
        .state(state.downgrade())
        .caret_blink_interval_500ms()
        .font_family(fonts::LABEL)
        .text_base()
        .bg(p.surface_container_highest)
        .text_color(p.on_surface)
        .caret_color(p.on_surface)
        .rounded_lg()
        .p_3()
        .w_full()
        .min_h_auto()
        .whitespace_nowrap()
        .overflow_x_scroll()
        .when(p.instrument, |el| el.rounded(px(14.)).border_1().border_color(p.outline_variant).text_size(px(14.)).font_family(fonts::BODY))
}

/// A selector is a form field, so it shares input typography, shape and fill.
pub fn select_trigger(id: String, label: impl Into<SharedString>, p: &Palette) -> Stateful<Div> {
    let selector = id.clone();
    div()
        .id(SharedString::from(id))
        .debug_selector(move || selector.clone())
        .flex()
        .items_center()
        .gap_3()
        .p_3()
        .w_full()
        .min_w_0()
        .rounded_lg()
        .font_family(fonts::LABEL)
        .text_base()
        .text_color(p.on_surface)
        .bg(p.surface_container_highest)
        .cursor_pointer()
        .child(div().flex_1().min_w_0().text_ellipsis().child(label.into()))
        .child(icon("expand_more", px(18.), p.on_surface_variant))
}

pub fn choice_row(
    id: String,
    label: impl Into<SharedString>,
    selected: bool,
    multiple: bool,
    p: &Palette,
) -> Stateful<Div> {
    choice_row_with_state(id, label, Some(selected), multiple, p)
}
pub fn choice_row_with_state(
    id: String,
    label: impl Into<SharedString>,
    state: Option<bool>,
    multiple: bool,
    p: &Palette,
) -> Stateful<Div> {
    let selected = state == Some(true);
    let selector = id.clone();
    div()
        .id(SharedString::from(id))
        .debug_selector(move || selector.clone())
        .flex()
        .items_center()
        .gap_3()
        .px_3()
        .py_2()
        .min_h(px(40.))
        .w_full()
        .rounded_lg()
        .font_family(fonts::BODY)
        .text_sm()
        .text_color(p.on_surface)
        .bg(if selected {
            p.surface_container_high
        } else {
            gpui::transparent_black()
        })
        .hover(|el| el.bg(p.surface_container_highest))
        .cursor_pointer()
        .child(icon(
            if state.is_none() {
                "indeterminate_check_box"
            } else if multiple {
                if selected {
                    "check_box"
                } else {
                    "check_box_outline_blank"
                }
            } else if selected {
                "check_circle"
            } else {
                "radio_button_unchecked"
            },
            px(18.),
            if selected { p.primary } else { p.outline },
        ))
        .child(div().flex_1().min_w_0().child(label.into()))
}

pub fn section_heading(label: impl Into<SharedString>, p: &Palette) -> Div {
    div()
        .font_family(fonts::HEADLINE)
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_lg()
        .text_color(p.on_surface)
        .child(label.into())
}

pub fn switch_thumb(p: &Palette, checked: bool) -> Div {
    div()
        .w(px(40.))
        .h(px(24.))
        .rounded_full()
        .bg(if checked {
            p.primary
        } else {
            p.surface_container_highest
        })
        .flex()
        .items_center()
        .px(px(2.))
        .when(checked, |el| el.justify_end())
        .when(!checked, |el| el.justify_start())
        .child(
            div()
                .w(px(16.))
                .h(px(16.))
                .rounded_full()
                .bg(gpui::rgb(0xffffff)),
        )
}

pub fn navigation_row(
    id: impl Into<gpui::ElementId>,
    selected: bool,
    p: &Palette,
) -> Stateful<Div> {
    div()
        .id(id)
        .py_3()
        .flex()
        .items_center()
        .gap_3()
        .text_sm()
        .font_family(fonts::BODY)
        .cursor_pointer()
        .border_l_2()
        .border_color(if selected {
            p.primary
        } else {
            gpui::transparent_black()
        })
        .bg(if selected {
            p.surface_container
        } else {
            p.surface_container_low
        })
        .text_color(if selected {
            p.primary
        } else {
            p.on_surface_variant
        })
}

pub fn field_card(p: &Palette) -> Div {
    div()
        .p_4()
        .min_w_0()
        .flex_shrink_0()
        .rounded_xl()
        .bg(p.surface_container_low)
        .flex()
        .flex_col()
        .gap_2()
}

pub fn toggle_row(
    p: &Palette,
    id: impl Into<SharedString>,
    checked: bool,
    label: &str,
    subtitle: &str,
    on_toggle: impl Fn(&gpui::MouseDownEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> Stateful<Div> {
    let id = id.into();
    let selector = id.to_string();
    div()
        .id(id)
        .debug_selector(move || selector.clone())
        .flex()
        .items_start()
        .gap_3()
        .py_2()
        .cursor_pointer()
        .font_family(fonts::LABEL)
        .child(
            div()
                .flex()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .child(
                    div()
                        .text_sm()
                        .text_color(p.on_surface)
                        .child(label.to_string()),
                )
                .when(!subtitle.is_empty(), |el| {
                    el.child(
                        div()
                            .text_xs()
                            .text_color(p.on_surface_variant)
                            .child(subtitle.to_string()),
                    )
                }),
        )
        .child(switch_thumb(p, checked))
        .on_mouse_down(gpui::MouseButton::Left, on_toggle)
}

/// Same compact action used for reveal/copy on the existing detail cards.
pub fn icon_button(
    id: impl Into<SharedString>,
    glyph: &'static str,
    glyph_size: gpui::Pixels,
    color: gpui::Hsla,
) -> Stateful<Div> {
    let id = id.into();
    let selector = id.to_string();
    div()
        .id(id)
        .debug_selector(move || selector.clone())
        .p_2()
        .rounded_lg()
        .cursor_pointer()
        .flex()
        .items_center()
        .justify_center()
        .text_color(color)
        .child(icon(glyph, glyph_size, color))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modal_test_support as fixture;
    use gpui::{size, Context, Render, TestAppContext, Window};
    struct Actions;
    impl Render for Actions {
        fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
            let p = crate::theme::current_palette(cx);
            div()
                .size_full()
                .p_4()
                .flex()
                .flex_col()
                .gap_3()
                .child(secondary_button(
                    "test-add-field".into(),
                    "Add custom field",
                    &p,
                ))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(secondary_button("test-match".into(), "Match: Origin", &p))
                        .child(secondary_button("test-remove".into(), "Remove URL", &p)),
                )
                .child(secondary_button("test-add-site".into(), "Add site", &p))
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(secondary_button("test-cancel".into(), "Cancel", &p).flex_1())
                        .child(primary_button("test-create".into(), "Create Item", &p).flex_1()),
                )
        }
    }
    #[gpui::test]
    fn action_labels_keep_readable_width_in_columns_and_wrapping_rows(cx: &mut TestAppContext) {
        let (_, cx) = cx.add_window_view(|_, cx| {
            fixture::fonts(cx);
            Actions
        });
        for width in [264., 320., 360., 528., 640., 945.] {
            cx.simulate_resize(size(px(width), px(600.)));
            cx.run_until_parked();
            for (id, min_width) in [
                ("test-add-field-label", 100.),
                ("test-match-label", 80.),
                ("test-remove-label", 70.),
                ("test-add-site-label", 50.),
                ("test-cancel-label", 40.),
                ("test-create-label", 45.),
            ] {
                let bounds = action_label_bounds(cx, id);
                assert!(
                    bounds.size.width >= px(min_width),
                    "label collapsed at width {width}: {id}: {bounds:?}"
                );
                assert!(
                    bounds.left() >= px(0.) && bounds.right() <= px(width),
                    "label escaped at width {width}: {id}: {bounds:?}"
                );
            }
        }
    }
}
