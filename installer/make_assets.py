#!/usr/bin/env python3
"""Generate the installer artwork in installer/assets/ (needs Pillow: pip install pillow).

  hostblock.ico  - app / installer icon (16-256 px)
  wizard.bmp     - 164x314 side panel on the Welcome and Finish pages
  header.bmp     - 150x57 image in the top-right corner of the other pages

The generated files are kept in the repository, so you only need to run this
if you want to change the artwork.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "assets"
GREEN_DARK, GREEN, GREEN_LIGHT = (16, 84, 40), (26, 127, 55), (46, 160, 80)
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def shield(size: int, fill=GREEN, check=(255, 255, 255), outline=None) -> Image.Image:
    """A shield with a check mark, drawn at 4x and scaled down for smooth edges."""
    s = size * 4
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    top, mid, bottom = s * 0.06, s * 0.55, s * 0.96
    left, right, cx = s * 0.12, s * 0.88, s / 2
    points = [(cx, top), (right, top + s * 0.12), (right, mid), (cx, bottom), (left, mid), (left, top + s * 0.12)]
    d.polygon(points, fill=fill)
    if outline:
        d.line(points + [points[0]], fill=outline, width=max(4, s // 40), joint="curve")
    w = max(4, int(s * 0.09))
    d.line([(s * 0.32, s * 0.50), (s * 0.45, s * 0.64), (s * 0.70, s * 0.36)], fill=check, width=w, joint="curve")
    return img.resize((size, size), Image.LANCZOS)


def vertical_gradient(w: int, h: int, top, bottom) -> Image.Image:
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        t = y / (h - 1)
        d.line([(0, y), (w, y)], fill=tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)))
    return img


def main() -> None:
    OUT.mkdir(exist_ok=True)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    big = shield(256)
    # BMP frames (not PNG) for compatibility with older Windows tools and NSIS.
    big.save(OUT / "hostblock.ico", sizes=[(n, n) for n in sizes], bitmap_format="bmp")

    panel = vertical_gradient(164, 314, GREEN_DARK, GREEN_LIGHT)
    mark = shield(96, fill=(255, 255, 255), check=GREEN)
    panel.paste(mark, ((164 - 96) // 2, 58), mark)
    d = ImageDraw.Draw(panel)
    title = ImageFont.truetype(FONT_BOLD, 21)
    small = ImageFont.truetype(FONT, 11)
    for text, font, y in (("HostBlock", title, 172), ("Ads & trackers,", small, 206), ("blocked.", small, 221)):
        width = d.textlength(text, font=font)
        d.text(((164 - width) / 2, y), text, font=font, fill=(255, 255, 255))
    panel.save(OUT / "wizard.bmp")

    header = Image.new("RGB", (150, 57), (255, 255, 255))
    mark = shield(44)
    header.paste(mark, (150 - 44 - 6, (57 - 44) // 2), mark)
    header.save(OUT / "header.bmp")
    print("Wrote", ", ".join(p.name for p in sorted(OUT.iterdir())))


if __name__ == "__main__":
    main()
