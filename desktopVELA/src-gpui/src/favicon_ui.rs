//! Shared favicon-loading UI helper, used by both `VaultBrowser`'s item rows
//! and `ItemDetail`'s header icon. Calls the real
//! `vela_desktop_core::favicon::fetch_favicon` (same DuckDuckGo-then-direct-
//! site-then-HTML-discovery chain, SSRF-guarded, the shipped app uses) via
//! `gpui_tokio::Tokio::spawn` — real network I/O must run on tokio's own
//! worker threads (entered into our tokio runtime), not gpui's
//! `background_executor()`, which is a separate thread pool that never
//! entered that runtime and panics the instant it tries real reactor I/O.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use gpui::{div, img, prelude::*, App, AsyncApp, Image, ImageFormat, ImageSource, Pixels};

use crate::icon::icon;
use crate::theme::Palette;

/// Per-URL favicon state, cached for the lifetime of whichever view owns
/// the `FaviconCache` (matches the original's module-level `faviconCache` —
/// ours is per-screen-instance rather than global, since gpui has no
/// equivalent of a plain JS module-level `Map`; the effect is the same:
/// fetch once per URL, reuse thereafter. The core `fetch_favicon` call
/// itself also has its own 24h-TTL cache, so even a fresh per-view instance
/// re-fetching a URL another view already warmed is effectively free).
#[derive(Clone)]
pub enum FaviconState {
    Loading,
    Loaded(Arc<Image>),
    Failed,
}

pub type FaviconCache = Rc<RefCell<HashMap<String, FaviconState>>>;

pub fn new_cache() -> FaviconCache {
    Rc::new(RefCell::new(HashMap::new()))
}

/// Decodes the `data:<mime>;base64,<payload>` string returned by
/// `fetch_favicon` into a gpui `Image`, ready for `ImageSource::Image`.
fn decode_favicon_data_url(data_url: &str) -> Option<Image> {
    let rest = data_url.strip_prefix("data:")?;
    let (mime, b64_payload) = rest.split_once(";base64,")?;
    let format = match mime {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/webp" => ImageFormat::Webp,
        "image/gif" => ImageFormat::Gif,
        "image/svg+xml" => ImageFormat::Svg,
        "image/x-icon" => ImageFormat::Ico,
        "image/bmp" => ImageFormat::Bmp,
        _ => return None,
    };
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64_payload).ok()?;
    Some(Image::from_bytes(format, bytes))
}

pub fn fallback_icon_box(palette: &Palette, icon_name: &'static str, size: Pixels) -> impl IntoElement {
    div()
        .flex_shrink_0()
        .w(size)
        .h(size)
        .rounded_xl()
        .bg(palette.surface_bright)
        .flex()
        .items_center()
        .justify_center()
        .child(icon(icon_name, size * 0.46, palette.primary))
}

/// Kicks off a favicon fetch for `url` if it isn't already cached/in-flight,
/// and returns the icon element to render right now (fallback type-icon
/// until/unless the fetch resolves). `on_loaded` is called once the fetch
/// settles (success or failure) so the caller can `cx.notify()` its own
/// entity — kept generic over the caller's entity type via a closure rather
/// than a `WeakEntity<T>` parameter, since `VaultBrowser` and `ItemDetail`
/// are different types.
pub fn favicon_or_fallback(
    palette: &Palette,
    url: &str,
    icon_name: &'static str,
    size: Pixels,
    favicon_cache: &FaviconCache,
    app: &mut App,
    on_loaded: impl FnOnce(&mut AsyncApp) + 'static,
) -> gpui::AnyElement {
    let cached = favicon_cache.borrow().get(url).cloned();
    match cached {
        Some(FaviconState::Loaded(image)) => div()
            .flex_shrink_0()
            .w(size)
            .h(size)
            .rounded_xl()
            .overflow_hidden()
            .child(img(ImageSource::Image(image)).w(size).h(size))
            .into_any_element(),
        Some(FaviconState::Loading) | Some(FaviconState::Failed) => {
            fallback_icon_box(palette, icon_name, size).into_any_element()
        }
        None => {
            favicon_cache.borrow_mut().insert(url.to_string(), FaviconState::Loading);
            let url = url.to_string();
            let cache = favicon_cache.clone();
            app.spawn(async move |cx| {
                let result =
                    gpui_tokio::Tokio::spawn(cx, vela_desktop_core::favicon::fetch_favicon(url.clone()))
                        .await;
                let state = match result {
                    Ok(Ok(Some(data_url))) => match decode_favicon_data_url(&data_url) {
                        Some(image) => FaviconState::Loaded(Arc::new(image)),
                        None => FaviconState::Failed,
                    },
                    _ => FaviconState::Failed,
                };
                cache.borrow_mut().insert(url, state);
                on_loaded(cx);
            })
            .detach();
            fallback_icon_box(palette, icon_name, size).into_any_element()
        }
    }
}
