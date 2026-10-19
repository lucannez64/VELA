//! Shared desktop breakpoints, in logical pixels (so display scaling applies).
pub const SIDEBAR_BREAKPOINT: f32 = 1024.;

pub fn sidebar_width(viewport_width: f32) -> f32 {
    if viewport_width < SIDEBAR_BREAKPOINT {
        64.
    } else {
        256.
    }
}

/// Available content width, excluding navigation and page padding.
pub fn content_width(viewport_width: f32) -> f32 {
    (viewport_width - sidebar_width(viewport_width) - 32.).max(0.)
}

pub fn compact(viewport_width: f32) -> bool {
    content_width(viewport_width) < 640.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_fit_narrow_and_scaled_desktop_windows() {
        // Includes 1920px desktops at 125%, 150%, and 200% scale.
        for width in [
            360., 480., 640., 800., 960., 1023., 1024., 1280., 1536., 1920.,
        ] {
            assert!(sidebar_width(width) + content_width(width) + 32. <= width);
            if width <= 640. {
                assert!(compact(width));
            }
        }
        assert_eq!(sidebar_width(1023.), 64.);
        assert_eq!(sidebar_width(1024.), 256.);
        assert!(!compact(1280.));
    }
}
