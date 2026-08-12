#!/usr/bin/env python3
"""Regenerate the brand assets in docs/assets/ from a single source of truth.

Run this only when the mark or the wordmark changes. The generated SVGs are
committed, so an ordinary checkout never needs it:

    uv run --no-project --with fonttools python scripts/generate_brand_assets.py

The wordmark's glyphs are converted to outlines, so the shipped SVGs carry no
font dependency and render identically everywhere. That conversion needs
JetBrains Mono (SIL Open Font License) installed; point FONT elsewhere if
yours lives at a different path.

Each asset ships with explicit fills rather than currentColor. These are loaded
through <img> and <link rel="icon">, where the SVG is an independent document
and currentColor resolves to black, which would vanish against a dark ground.
"""

from __future__ import annotations

from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

FONT = Path.home() / "Library/Fonts/JetBrainsMonoNerdFont-Medium.ttf"
OUT = Path("docs/assets")

# The D2 mark: a drop with a rule that runs past the silhouette and erases it
# where it crosses, echoing the wordmark's redaction bar. viewBox is 0 0 64 64.
DROP = "M32 6C32 6 51 26 51 39A19 19 0 1 1 13 39C13 26 32 6 32 6ZM2 34H62V42H2Z"
DROP_TOP, DROP_BOT, DROP_LEFT, DROP_W = 6, 58, 2, 60

# Wordmark metrics, in font units (1000 per em).
GAP = 140  # space between "one" and the bar
PAD_X = 95  # bar padding, left and right
BAR_TOP, BAR_BOT = 775, -130
STRIKE_H = 85

# word colour, bar colour, ghost colour
VARIANTS = {
    "light": ("#14141C", "#14141C", "#FFFFFF"),
    "dark": ("#EFEFF4", "#EFEFF4", "#08080B"),
}

font = TTFont(FONT)
glyphs = font.getGlyphSet()
cmap = font.getBestCmap()
ADVANCE = 600  # monospace
X_HEIGHT = font["OS/2"].sxHeight


def outline(word: str, x0: float) -> tuple[str, float]:
    """Glyph outlines for `word`, laid out from x0. Returns (paths, end x)."""
    parts, x = [], x0
    for ch in word:
        pen = SVGPathPen(glyphs)
        glyphs[cmap[ord(ch)]].draw(pen)
        if d := pen.getCommands():
            parts.append(f'<path transform="translate({x},0)" d="{d}"/>')
        x += ADVANCE
    return "".join(parts), x


ONE_D, ONE_END = outline("one", 0)
BAR_X = ONE_END + GAP
LEAKS_D, LEAKS_END = outline("leaks", BAR_X + PAD_X)
BAR_W = (LEAKS_END + PAD_X) - BAR_X
TYPE_W = LEAKS_END + PAD_X
HEIGHT = BAR_TOP - BAR_BOT


def wordmark(word_c: str, bar_c: str, ghost_c: str, dx: float = 0) -> str:
    """'one' plus the bar carrying a ghosted, struck-through 'leaks'."""
    strike_y = X_HEIGHT / 2 - STRIKE_H / 2
    return (
        f'<g transform="translate({dx},0)">'
        f'<g fill="{word_c}">{ONE_D}</g>'
        f'<rect x="{BAR_X}" y="{BAR_BOT}" width="{BAR_W}" height="{HEIGHT}" '
        f'rx="20" fill="{bar_c}"/>'
        f'<g fill="{ghost_c}" fill-opacity="0.46">{LEAKS_D}</g>'
        f'<rect x="{BAR_X + PAD_X}" y="{strike_y}" width="{BAR_W - 2 * PAD_X}" '
        f'height="{STRIKE_H}" rx="10" fill="{ghost_c}" fill-opacity="0.85"/>'
        f"</g>"
    )


def mark(word_c: str) -> tuple[str, float]:
    """The drop, scaled and centred on the bar's midline. Returns (path, width)."""
    drop_h = DROP_BOT - DROP_TOP  # 52 units of real extent
    scale = 0.86 * HEIGHT / drop_h
    baseline = (BAR_TOP + BAR_BOT) / 2 - (drop_h / 2) * scale
    tx, ty = -DROP_LEFT * scale, baseline + DROP_BOT * scale
    path = (
        f'<path fill="{word_c}" fill-rule="evenodd" '
        f'transform="translate({tx:.2f},{ty:.2f}) scale({scale:.4f},{-scale:.4f})" '
        f'd="{DROP}"/>'
    )
    return path, DROP_W * scale


def document(width: float, body: str, px_height: int = 44) -> str:
    ratio = width / HEIGHT * px_height
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {HEIGHT:.0f}" '
        f'width="{ratio:.0f}" height="{px_height}" role="img" aria-label="oneleaks">\n'
        f'  <g transform="translate(0,{BAR_TOP}) scale(1,-1)">{body}</g>\n'
        f"</svg>\n"
    )


def main() -> None:
    for name, (word_c, bar_c, ghost_c) in VARIANTS.items():
        (OUT / f"logotype-on-{name}.svg").write_text(
            document(TYPE_W, wordmark(word_c, bar_c, ghost_c))
        )
        drop, drop_w = mark(word_c)
        dx = drop_w + 210
        (OUT / f"lockup-on-{name}.svg").write_text(
            document(dx + TYPE_W, drop + wordmark(word_c, bar_c, ghost_c, dx))
        )
    print(f"wrote logotype and lockup, light and dark, to {OUT}/")


if __name__ == "__main__":
    main()
