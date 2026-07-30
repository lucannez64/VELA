//! Keyboard accessibility: moving focus between fields with Tab, and
//! submitting a form with Enter — the two things a mouse-free user needs from
//! every screen here, and neither of which gpui gives you for free.
//!
//! Both hang off plain `on_key_down` listeners rather than bound actions. The
//! text fields these have to cooperate with (`gpui_elements`' editable text)
//! bind `tab` and `enter` themselves under their own `EditableText` key
//! context, which sits *deeper* in the context stack than anything we could
//! attach from an enclosing view — so a competing binding of ours would lose
//! on depth no matter where we put it. The vendored fork instead has those two
//! handlers `cx.propagate()` when they have nothing to do (tab always; enter
//! on a single-line field), which lets the keystroke fall through to ordinary
//! key listeners. That's this module's entry point.
//!
//! Key listeners only fire along the dispatch path of the *focused* element,
//! which is what keeps [`submit_on_enter`] scoped: put it on a form's own
//! container and it reacts to Enter typed in that form's fields, not to Enter
//! anywhere in the window.

use gpui::{App, Context, ElementId, InteractiveElement, KeyDownEvent, Window};

/// Upper bound on the hops [`trap_tab`] will make looking for a tab stop back
/// inside its container. The order wraps, so one lap always suffices; this
/// only stops a container that holds no tab stops at all from spinning.
const MAX_TAB_HOPS: usize = 256;

/// `Some(going_backwards)` when this keystroke is a focus move.
fn tab_direction(event: &KeyDownEvent) -> Option<bool> {
    if event.keystroke.key != "tab" {
        return None;
    }
    let modifiers = event.keystroke.modifiers;
    // Shift-Tab is the only modified form we claim; Ctrl-Tab and friends are
    // left alone in case something above us wants them.
    if modifiers.control || modifiers.alt || modifiers.platform || modifiers.function {
        return None;
    }
    Some(modifiers.shift)
}

/// Moves focus to the next (Tab) or previous (Shift-Tab) tab stop.
///
/// Belongs on a window's root element: focus movement is window-wide, and
/// `Window::focus_next` wraps around on its own once it runs off either end.
/// Every `text_input` / `text_area` registers itself as a tab stop; other
/// elements join the order by being `track_focus`ed on a handle built with
/// `.tab_stop(true)`.
pub fn navigate_on_tab(event: &KeyDownEvent, window: &mut Window, cx: &mut App) {
    let Some(backwards) = tab_direction(event) else {
        return;
    };

    // Unconditional, and before the move: a key event that survives dispatch
    // with propagation intact falls through to the platform's "just type the
    // keystroke's character" path (see `handle_input` in gpui's Wayland/X11
    // window), which would insert a literal "\t" into the field being left —
    // including when `focus_next` finds nowhere to go and does nothing.
    cx.stop_propagation();
    if backwards {
        window.focus_prev(cx);
    } else {
        window.focus_next(cx);
    }
}

/// Confines Tab / Shift-Tab to `el`'s subtree, and parks focus there to begin
/// with. Apply to a modal's body: without it, tabbing off the last field walks
/// straight into the screen the modal is covering, which is both disorienting
/// and lets the keyboard reach controls the modal is meant to be blocking.
///
/// `key` just has to be stable across frames for this element — the focus
/// handle is stored against it.
///
/// Two halves, both needed:
///
///  - The handle is `track_focus`ed onto `el` and focused whenever nothing
///    inside it is, so a freshly opened modal already owns the focus. gpui's
///    tab order is window-wide with no notion of "current dialog", so a modal
///    that left focus unset would send the very first Tab into the background
///    screen, with nothing on the dispatch path to stop it.
///  - The listener then walks the window-wide order until it lands back
///    inside. Skipping rather than clamping is what makes it wrap: run off the
///    last field and the hops carry through the background screen's stops and
///    around to this modal's first one.
///
/// The handle is deliberately not itself a tab stop, so Tab passes over the
/// container and goes straight to the first real field within it.
pub fn trap_tab<E: InteractiveElement>(
    el: E,
    key: impl Into<ElementId>,
    window: &mut Window,
    cx: &mut App,
) -> E {
    let container = window
        .use_keyed_state(key, cx, |_, cx| cx.focus_handle().tab_stop(false))
        .read(cx)
        .clone();

    // False on the modal's first frame too — the container isn't in the
    // rendered dispatch tree yet — which is exactly when focus should be
    // claimed. Once it is, this stays true and focus is left alone, including
    // after the user clicks into a field.
    if !container.contains_focused(window, cx) {
        window.focus(&container, cx);
    }

    el.track_focus(&container).on_key_down({
        let container = container.clone();
        move |event: &KeyDownEvent, window: &mut Window, cx: &mut App| {
            let Some(backwards) = tab_direction(event) else {
                return;
            };
            // See `navigate_on_tab`: an un-stopped tab types a literal "\t".
            // This also keeps the window-root handler from moving focus a
            // second time.
            cx.stop_propagation();

            let previous = window.focused(cx);
            for _ in 0..MAX_TAB_HOPS {
                if backwards {
                    window.focus_prev(cx);
                } else {
                    window.focus_next(cx);
                }
                if container.contains_focused(window, cx) {
                    return;
                }
            }
            // Nothing tabbable in here at all — leave focus where it was
            // rather than stranded somewhere behind the modal.
            if let Some(previous) = previous {
                window.focus(&previous, cx);
            }
        }
    })
}

/// Builds an `on_key_down` listener that runs `submit` when Enter is pressed
/// with focus inside the element it's attached to — the "press Enter in the
/// password box to log in" behaviour every form on the web has.
///
/// Attach it to a form's container, never to a window root, so it can't fire
/// for unrelated fields. Enter inside a `text_area` never reaches here (that
/// field inserts a newline and consumes the key), so a form may safely mix the
/// two.
pub fn submit_on_enter<V: 'static>(
    cx: &Context<V>,
    submit: impl Fn(&mut V, &mut Window, &mut Context<V>) + 'static,
) -> impl Fn(&KeyDownEvent, &mut Window, &mut App) + 'static {
    // Deliberately not `cx.listener`: its return type borrows from `cx`, which
    // this function cannot hand back out. Downgrading the entity ourselves is
    // the same thing minus the borrow.
    let view = cx.entity().downgrade();
    move |event: &KeyDownEvent, window: &mut Window, cx: &mut App| {
        if event.keystroke.key != "enter" || event.keystroke.modifiers.modified() {
            return;
        }
        cx.stop_propagation();
        view.update(cx, |view, cx| submit(view, window, cx)).ok();
    }
}
