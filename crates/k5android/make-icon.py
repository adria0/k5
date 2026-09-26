#!/usr/bin/env python3
# Generates the app icon in res/: "K5" in dots, like the window's header
# (ink dots on paper). An adaptive icon (paper background, dots in the
# foreground, Android 8+) and square PNGs for older launchers.
#
# Usage: python3 make-icon.py   (no dependencies)

import os
import struct
import zlib

PAPER = (0xD8, 0xD2, 0xC2)
INK = (0x1C, 0x1B, 0x18)

K = ["10001", "10010", "10100", "11000", "10100", "10010", "10001"]
FIVE = ["11111", "10000", "11110", "00001", "00001", "10001", "01110"]
# K, a column gap, 5: 11 x 7 dots.
GLYPHS = [k + "0" + five for k, five in zip(K, FIVE)]
COLS, ROWS = len(GLYPHS[0]), len(GLYPHS)

# Launcher icon sizes (px) by density: legacy 48dp, adaptive layers 108dp.
DENSITIES = {"mdpi": 1.0, "hdpi": 1.5, "xhdpi": 2.0, "xxhdpi": 3.0, "xxxhdpi": 4.0}

HERE = os.path.dirname(os.path.abspath(__file__))


def png(path, size, pixels):
    """Writes RGBA `pixels` (rows of (r, g, b, a)) as a PNG."""
    raw = b"".join(
        b"\x00" + b"".join(struct.pack("4B", *pixel) for pixel in row) for row in pixels
    )

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header))
        f.write(chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def render(size, content, background):
    """The dots, `content` (fraction of the side) wide, centered; on paper if
    `background`, else transparent. 4x4 supersampling for round dots."""
    cell = size * content / COLS
    x0 = (size - cell * COLS) / 2
    y0 = (size - cell * ROWS) / 2
    radius = cell * 0.42
    samples = 4

    rows = []
    for y in range(size):
        row = []
        for x in range(size):
            covered = 0
            for sy in range(samples):
                for sx in range(samples):
                    px = x + (sx + 0.5) / samples
                    py = y + (sy + 0.5) / samples
                    col = int((px - x0) // cell)
                    line = int((py - y0) // cell)
                    if 0 <= col < COLS and 0 <= line < ROWS and GLYPHS[line][col] == "1":
                        cx = x0 + (col + 0.5) * cell
                        cy = y0 + (line + 0.5) * cell
                        if (px - cx) ** 2 + (py - cy) ** 2 <= radius**2:
                            covered += 1
            alpha = covered / samples**2
            if background:
                row.append(
                    tuple(round(i * alpha + p * (1 - alpha)) for i, p in zip(INK, PAPER))
                    + (255,)
                )
            else:
                row.append(INK + (round(255 * alpha),))
        rows.append(row)
    return rows


for density, scale in DENSITIES.items():
    folder = os.path.join(HERE, "res", f"mipmap-{density}")
    os.makedirs(folder, exist_ok=True)
    # Legacy: the whole square, on paper.
    legacy = round(48 * scale)
    png(os.path.join(folder, "ic_launcher.png"), legacy, render(legacy, 0.72, True))
    # Adaptive foreground: 108dp, within the 66dp safe zone.
    layer = round(108 * scale)
    png(
        os.path.join(folder, "ic_launcher_foreground.png"),
        layer,
        render(layer, 0.5, False),
    )

anydpi = os.path.join(HERE, "res", "mipmap-anydpi-v26")
os.makedirs(anydpi, exist_ok=True)
with open(os.path.join(anydpi, "ic_launcher.xml"), "w") as f:
    f.write(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <background android:drawable="@color/ic_launcher_background" />\n'
        '    <foreground android:drawable="@mipmap/ic_launcher_foreground" />\n'
        "</adaptive-icon>\n"
    )
values = os.path.join(HERE, "res", "values")
os.makedirs(values, exist_ok=True)
with open(os.path.join(values, "colors.xml"), "w") as f:
    f.write(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        '    <color name="ic_launcher_background">#%02X%02X%02X</color>\n' % PAPER
        + "</resources>\n"
    )
print("icons written to", os.path.join(HERE, "res"))
