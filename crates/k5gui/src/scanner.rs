// Reading a ticket from a QR code with the device's camera: the platform
// gives a [`Scanner`] (on Android, `k5android`'s camera; none on the
// desktop), which sends greyscale frames; the window shows them as a preview
// and looks for a ticket's QR code in them.

use slint::{Rgb8Pixel, SharedPixelBuffer};

/// A camera frame: its luminance plane, row after row, `stride` bytes apart.
pub struct Frame<'a> {
    pub luma: &'a [u8],
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    /// Clockwise rotation, in degrees (0, 90, 180 or 270), that shows it
    /// upright.
    pub rotation: u32,
}

/// What a scanner reports.
pub enum Scan<'a> {
    Frame(Frame<'a>),
    /// The camera could not be used (no permission, no camera...).
    Failed(String),
}

/// Called by a scanner, from its own thread.
pub type OnScan = Box<dyn FnMut(Scan<'_>) + Send>;

/// The camera of the device.
pub trait Scanner: Send {
    /// Starts sending frames to `on_scan`, from another thread, until
    /// [`Scanner::stop`]. Returns right away: failures are reported to
    /// `on_scan`.
    fn start(&mut self, on_scan: OnScan);

    /// Stops the camera, if started.
    fn stop(&mut self);
}

/// The preview of `frame`: greyscale, upright, at most `max` pixels on its
/// longer side.
pub fn preview(frame: &Frame<'_>, max: usize) -> SharedPixelBuffer<Rgb8Pixel> {
    let step = frame.width.max(frame.height).div_ceil(max.max(1)).max(1);
    let (w, h) = (frame.width / step, frame.height / step);
    let turned = matches!(frame.rotation, 90 | 270);
    let (out_w, out_h) = if turned { (h, w) } else { (w, h) };

    let mut buffer = SharedPixelBuffer::<Rgb8Pixel>::new(out_w as u32, out_h as u32);
    let pixels = buffer.make_mut_slice();
    for y in 0..out_h {
        for x in 0..out_w {
            // The source pixel shown at (x, y) once rotated clockwise.
            let (sx, sy) = match frame.rotation {
                90 => (y, h - 1 - x),
                180 => (w - 1 - x, h - 1 - y),
                270 => (w - 1 - y, x),
                _ => (x, y),
            };
            let luma = frame
                .luma
                .get(sy * step * frame.stride + sx * step)
                .copied()
                .unwrap_or(0);
            pixels[y * out_w + x] = Rgb8Pixel::new(luma, luma, luma);
        }
    }

    buffer
}

/// The ticket in `frame`, if it shows a ticket's QR code.
pub fn ticket(frame: &Frame<'_>) -> Option<String> {
    crate::qr::decode(frame.luma, frame.width, frame.height, frame.stride)
        .filter(|text| text.starts_with("k5ticket:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4x2 frame, stride 5, whose pixels are 0..7.
    fn frame(luma: &[u8], rotation: u32) -> Frame<'_> {
        Frame {
            luma,
            width: 4,
            height: 2,
            stride: 5,
            rotation,
        }
    }

    fn lumas(buffer: &SharedPixelBuffer<Rgb8Pixel>) -> (u32, u32, Vec<u8>) {
        (
            buffer.width(),
            buffer.height(),
            buffer.as_slice().iter().map(|pixel| pixel.r).collect(),
        )
    }

    #[test]
    fn test_preview() {
        // Rows: 0 1 2 3 | 4 5 6 7, with a padding byte (9) after each.
        let luma = [0, 1, 2, 3, 9, 4, 5, 6, 7, 9];
        assert_eq!(
            lumas(&preview(&frame(&luma, 0), 10)),
            (4, 2, vec![0, 1, 2, 3, 4, 5, 6, 7])
        );
        // Turned clockwise: the first column, bottom up, is the top row.
        assert_eq!(
            lumas(&preview(&frame(&luma, 90), 10)),
            (2, 4, vec![4, 0, 5, 1, 6, 2, 7, 3])
        );
        assert_eq!(
            lumas(&preview(&frame(&luma, 180), 10)),
            (4, 2, vec![7, 6, 5, 4, 3, 2, 1, 0])
        );
        assert_eq!(
            lumas(&preview(&frame(&luma, 270), 10)),
            (2, 4, vec![3, 7, 2, 6, 1, 5, 0, 4])
        );
        // Downscaled to fit.
        assert_eq!(lumas(&preview(&frame(&luma, 0), 2)), (2, 1, vec![0, 2]));
    }

    #[test]
    fn test_ticket() {
        let (pixels, side) = crate::qr::encode("k5ticket:abc", 4).unwrap();
        let frame = Frame {
            luma: &pixels,
            width: side,
            height: side,
            stride: side,
            rotation: 90,
        };
        assert_eq!(ticket(&frame).as_deref(), Some("k5ticket:abc"));

        // Other QR codes are ignored.
        let (pixels, side) = crate::qr::encode("https://example.com", 4).unwrap();
        let other = Frame {
            luma: &pixels,
            width: side,
            height: side,
            stride: side,
            rotation: 0,
        };
        assert_eq!(ticket(&other), None);
    }
}
