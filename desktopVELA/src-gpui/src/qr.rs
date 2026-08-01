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

    let buffer = build_pixel_buffer(&colors, width, scale);
    let img_size = buffer.width();

    let mut png_bytes = Vec::new();
    {
        use image::ImageEncoder;
        image::codecs::png::PngEncoder::new(&mut png_bytes)
            .write_image(buffer.as_raw(), img_size, img_size, image::ExtendedColorType::Rgba8)
            .ok()?;
    }

    Some(Image::from_bytes(ImageFormat::Png, png_bytes))
}

/// The module grid → RGBA pixel buffer step, separated from the QR/PNG
/// plumbing so the scaling and quiet-zone math can be unit-tested.
fn build_pixel_buffer(colors: &[Color], width: usize, scale: u32) -> image::RgbaImage {
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

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHITE: image::Rgba<u8> = image::Rgba([255, 255, 255, 255]);
    const BLACK: image::Rgba<u8> = image::Rgba([0, 0, 0, 255]);

    #[test]
    fn pixel_buffer_honours_margin_and_scale() {
        // 2×2 module grid, dark on the main diagonal, scale 3.
        let colors = vec![Color::Dark, Color::Light, Color::Light, Color::Dark];
        let buffer = build_pixel_buffer(&colors, 2, 3);

        // (2 + 2*2) modules × 3px = 18px square.
        assert_eq!((buffer.width(), buffer.height()), (18, 18));

        // Quiet zone (margin) is white.
        assert_eq!(*buffer.get_pixel(0, 0), WHITE);
        assert_eq!(*buffer.get_pixel(5, 5), WHITE);

        // Module (0,0) dark → pixels (2*3..2*3+3)² black.
        assert_eq!(*buffer.get_pixel(6, 6), BLACK);
        assert_eq!(*buffer.get_pixel(8, 8), BLACK);
        // Module (1,0) light → stays white.
        assert_eq!(*buffer.get_pixel(9, 6), WHITE);
        // Module (1,1) dark → bottom-right module black.
        assert_eq!(*buffer.get_pixel(9, 9), BLACK);
        assert_eq!(*buffer.get_pixel(11, 11), BLACK);
    }

    #[test]
    fn render_qr_image_produces_png_of_expected_size() {
        let scale = 4;
        let image = render_qr_image("VELA-ENROLL:v2:test", scale).expect("payload fits");

        assert_eq!(image.format, ImageFormat::Png);
        assert!(image.bytes.starts_with(b"\x89PNG\r\n\x1a\n"));

        let decoded = image::load_from_memory(&image.bytes).unwrap().to_rgba8();
        // PNG dimensions = (QR width + 2×margin) × scale.
        let qr_width = QrCode::new(b"VELA-ENROLL:v2:test").unwrap().width() as u32;
        assert_eq!(decoded.width(), (qr_width + MARGIN_MODULES * 2) * scale);
        assert_eq!(decoded.height(), decoded.width());

        // A real code has both dark modules and a white quiet zone.
        let has_black = decoded.pixels().any(|p| *p == BLACK);
        assert!(has_black, "rendered code must contain dark modules");
        assert_eq!(*decoded.get_pixel(0, 0), WHITE, "quiet zone must be white");
    }

    #[test]
    fn render_qr_image_rejects_oversize_payload() {
        // QR byte mode tops out at 2953 bytes.
        let huge = "A".repeat(4000);
        assert!(render_qr_image(&huge, 1).is_none());
    }
}
