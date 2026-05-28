"""
Generate extension icons (icon-16.png, icon-48.png, icon-128.png).

Requires Pillow:
    pip install Pillow

Run from this directory:
    python generate_icons.py
"""

import os
import math
from PIL import Image, ImageDraw

SIZES = [16, 48, 128]
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# Brand colours
BG_COLOR    = (215,  58,  74, 255)   # #d73a4a — GitHub security red
FG_COLOR    = (255, 255, 255, 255)   # white
SHADOW      = ( 80,  10,  20, 120)   # subtle drop shadow


def draw_lock(draw: ImageDraw.ImageDraw, size: int):
    """Draw a padlock icon scaled to `size`."""
    s = size / 128  # all coordinates below are for a 128px canvas

    # ── Lock body ──────────────────────────────────────────────────────────────
    body_x1 = 28 * s
    body_y1 = 58 * s
    body_x2 = 100 * s
    body_y2 = 108 * s
    body_r  = max(1, int(10 * s))

    draw.rounded_rectangle([body_x1, body_y1, body_x2, body_y2],
                            radius=body_r, fill=FG_COLOR)

    # ── Shackle (U-shape arc) ──────────────────────────────────────────────────
    shackle_x1 = 38 * s
    shackle_y1 = 22 * s
    shackle_x2 = 90 * s
    shackle_y2 = 75 * s
    lw = max(1, int(12 * s))

    draw.arc([shackle_x1, shackle_y1, shackle_x2, shackle_y2],
             start=0, end=180, fill=FG_COLOR, width=lw)

    # ── Keyhole ────────────────────────────────────────────────────────────────
    kx  = 64 * s
    ky  = 78 * s
    kr  = max(1, int(8 * s))
    draw.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], fill=BG_COLOR)

    # Keyhole notch
    notch_w = max(1, int(5 * s))
    notch_h = max(1, int(12 * s))
    draw.rectangle([kx - notch_w // 2, ky, kx + notch_w // 2, ky + notch_h],
                   fill=BG_COLOR)


def create_icon(size: int) -> Image.Image:
    img  = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle
    pad = max(1, size // 12)
    draw.ellipse([pad, pad, size - pad, size - pad], fill=BG_COLOR)

    # Lock
    draw_lock(draw, size)

    return img


def main():
    for size in SIZES:
        img  = create_icon(size)
        path = os.path.join(OUT_DIR, f'icon-{size}.png')
        img.save(path, 'PNG')
        print(f'Created {path}')


if __name__ == '__main__':
    main()
