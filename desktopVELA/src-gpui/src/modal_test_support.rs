//! Synthetic native UI fixtures. No account is unlocked and no request is sent.
use gpui::{prelude::*, App, Bounds, Entity, Pixels, VisualTestContext, Window};
use std::sync::Arc;
use vela_desktop_core::{api::ApiClient, store::Store, AppState};

pub fn state(directory: &tempfile::TempDir) -> Arc<AppState> {
    let mut state = AppState::default();
    state.store = Arc::new(Store::new_at(directory.path().into()).unwrap());
    state.api = Arc::new(ApiClient::with_url("https://example.invalid".into()));
    Arc::new(state)
}

pub fn fonts(cx: &mut App) {
    for (_, bytes) in crate::fonts::FONT_FILES {
        cx.text_system()
            .add_fonts(vec![std::borrow::Cow::Borrowed(*bytes)])
            .unwrap();
    }
}

pub fn bounds(cx: &mut VisualTestContext, selector: &'static str) -> Bounds<Pixels> {
    cx.debug_bounds(selector)
        .unwrap_or_else(|| panic!("Missing visible element: {selector}"))
}

pub struct Host<V: gpui::Render> {
    pub child: Entity<V>,
}
impl<V: gpui::Render + 'static> gpui::Render for Host<V> {
    fn render(&mut self, _: &mut Window, _: &mut gpui::Context<Self>) -> impl gpui::IntoElement {
        gpui::div().relative().size_full().child(self.child.clone())
    }
}
