// Tickets as QR codes: shown on screen after making a ticket, and read from
// the camera frames on Android (see `scan` in k5android).

use anyhow::anyhow;
use qrcode::{Color, QrCode};

/// Modules of the quiet zone around a code, as the standard asks.
const QUIET_ZONE: usize = 4;

/// A QR code rasterized as luminance (0 black, 255 white), `scale` pixels
/// per module, with its quiet zone: `(pixels, side)`.
pub fn encode(text: &str, scale: usize) -> anyhow::Result<(Vec<u8>, usize)> {
    let code = QrCode::new(text.as_bytes()).map_err(|e| anyhow!("cannot make a QR code: {e}"))?;
    let modules = code.width();
    let colors = code.to_colors();
    let side = (modules + 2 * QUIET_ZONE) * scale;

    let mut pixels = vec![255; side * side];
    for (index, color) in colors.iter().enumerate() {
        if *color != Color::Dark {
            continue;
        }
        let (row, col) = (index / modules + QUIET_ZONE, index % modules + QUIET_ZONE);
        for y in row * scale..(row + 1) * scale {
            pixels[y * side + col * scale..y * side + (col + 1) * scale].fill(0);
        }
    }

    Ok((pixels, side))
}

/// The QR code of `text` as an image for the window.
pub fn pixel_buffer(
    text: &str,
    scale: usize,
) -> anyhow::Result<slint::SharedPixelBuffer<slint::Rgb8Pixel>> {
    let (pixels, side) = encode(text, scale)?;
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(side as u32, side as u32);
    for (pixel, luma) in buffer.make_mut_slice().iter_mut().zip(pixels) {
        *pixel = slint::Rgb8Pixel::new(luma, luma, luma);
    }

    Ok(buffer)
}

/// The text of the first QR code found in a greyscale image (`width` x
/// `height` luminance values, row after row, `stride` bytes apart), if any.
pub fn decode(luma: &[u8], width: usize, height: usize, stride: usize) -> Option<String> {
    if width == 0 || height == 0 || luma.len() < (height - 1) * stride + width {
        return None;
    }
    let mut image =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luma[y * stride + x]);

    image
        .detect_grids()
        .into_iter()
        .find_map(|grid| grid.decode().ok())
        .map(|(_, text)| text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ticket as long as a real one (endpoint id, relay and addresses).
    const TICKET: &str = "k5ticket:eyJpZCI6IjAyNjg4YzhmNTUwYWMwMGIxZWVjMmM5ZjQyMjFmZjc0ZTZlZWM3NDNlMDY1ZjhkNmNiYzMzMTViZTkzMGI3ODYiLCJhZGRycyI6W3siUmVsYXkiOiJodHRwczovL2V1YzEtMS5yZWxheS5uMC5pcm9oLmxpbmsuLyJ9LHsiSXAiOiI4My40Ni4yNTUuMTI0OjU3NjI4In0seyJJcCI6IjE5Mi4xNjguMS4xMjI6NTc2MjgifV19";

    #[test]
    fn test_round_trip() {
        let (pixels, side) = encode(TICKET, 3).unwrap();
        assert_eq!(pixels.len(), side * side);
        // Quiet zone: the border is white.
        assert!(pixels[..side * 3 * QUIET_ZONE]
            .iter()
            .all(|&luma| luma == 255));

        assert_eq!(decode(&pixels, side, side, side).as_deref(), Some(TICKET));
    }

    #[test]
    fn test_decode_in_a_camera_frame() {
        // The code somewhere in a larger, grey frame, with rows padded (a
        // camera plane's stride), and a bit of noise.
        let (code, side) = encode(TICKET, 4).unwrap();
        let (width, height, stride) = (side + 90, side + 60, side + 128);
        let mut frame = vec![128u8; stride * height];
        for y in 0..side {
            for x in 0..side {
                let noise = ((x * 7 + y * 13) % 17) as u8;
                let luma = code[y * side + x];
                frame[(y + 30) * stride + x + 45] = if luma == 0 { noise } else { 255 - noise };
            }
        }

        assert_eq!(
            decode(&frame, width, height, stride).as_deref(),
            Some(TICKET)
        );
        // No code: nothing.
        assert_eq!(
            decode(&vec![128; stride * height], width, height, stride),
            None
        );
        // A frame too short for its size: nothing, no panic.
        assert_eq!(decode(&frame[..100], width, height, stride), None);
    }
}
