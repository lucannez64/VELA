//! Renders a QR code (via the `qrcode` crate) to a PNG-encoded gpui `Image`,
//! for the device-enrollment flow. Deliberately builds the pixel buffer by
//! hand from `QrCode::to_colors()`/`.width()` rather than relying on any
//! optional `image`-crate integration feature of the `qrcode` crate itself —
//! keeps the two dependencies' versions decoupled. Mirrors the favicon
//! decode pipeline in `favicon_ui.rs` (raw bytes -> `Image::from_bytes`).

use gpui::{Image, ImageFormat};
use qrcode::{Color, QrCode};

/// Modules-worth of quiet-zone margin around the code, matching common QR
/// rendering conventions (most scanners expect at least a 2-module margin).
const MARGIN_MODULES: u32 = 2;

/// Renders `data` as a QR code, `scale` real pixels per module, returning a
/// ready-to-display gpui `Image`. Returns `None` if `data` doesn't fit in a
/// QR code at all (shouldn't happen for enrollment-code-sized payloads).
pub fn render_qr_image(data: &str, scale: u32) -> Option<Image> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();

    let img_modules = width as u32 + MARGIN_MODULES * 2;
    let img_size = img_modules * scale;

    let mut buffer = image::RgbaImage::from_pixel(img_size, img_size, image::Rgba([255, 255, 255, 255]));

    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == Color::Dark {
                let px0 = (x as u32 + MARGIN_MODULES) * scale;
                let py0 = (y as u32 + MARGIN_MODULES) * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        buffer.put_pixel(px0 + dx, py0 + dy, image::Rgba([0, 0, 0, 255]));
                    }
                }
            }
        }
    }

    let mut png_bytes = Vec::new();
    {
        use image::ImageEncoder;
        image::codecs::png::PngEncoder::new(&mut png_bytes)
            .write_image(buffer.as_raw(), img_size, img_size, image::ExtendedColorType::Rgba8)
            .ok()?;
    }

    Some(Image::from_bytes(ImageFormat::Png, png_bytes))
}
