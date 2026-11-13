"""Build the README demo GIF from the live view's own output.

The frames come from `cargo run --example gif_frames`, which drives the real
`Frame::render`. This script only draws them: it parses the fixed-column layout
back into coloured runs, paints a terminal window, and assembles the animation.

Keeping the text generation in Rust and the painting here means the GIF cannot
drift from what the program actually prints.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------- palette
BG = (11, 12, 14)
WINDOW = (20, 22, 25)
BORDER = (35, 39, 45)
TITLEBAR = (16, 18, 20)
TEXT = (230, 232, 235)
DIM = (139, 145, 153)
ACCENT = (240, 180, 41)
DANGER = (229, 72, 77)
GREEN = (70, 167, 88)
DOT_RED = (255, 95, 87)
DOT_AMBER = (254, 188, 46)
DOT_GREEN = (40, 200, 64)

FONT_PATH = r"C:\Windows\Fonts\consola.ttf"
FONT_BOLD_PATH = r"C:\Windows\Fonts\consolab.ttf"
# Draw everything at a scale factor rather than upscaling the finished bitmap:
# text stays sharp on a high-DPI display, which is most of them now.
SCALE = 1.6

FONT_SIZE = int(17 * SCALE)
PAD_X = int(30 * SCALE)
PAD_TOP = int(22 * SCALE)
PAD_BOTTOM = int(26 * SCALE)
TITLEBAR_H = int(40 * SCALE)
LINE_H = int(25 * SCALE)
RADIUS = int(12 * SCALE)


def load_fonts() -> tuple[ImageFont.FreeTypeFont, ImageFont.FreeTypeFont]:
    regular = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    try:
        bold = ImageFont.truetype(FONT_BOLD_PATH, FONT_SIZE)
    except OSError:
        bold = regular
    return regular, bold


# ---------------------------------------------------------------- parsing
RE_TITLE = re.compile(r"^(tattletale)(  live  )(\d\d:\d\d:\d\d)( +)([\u2581-\u2588]*)$")
RE_COUNTS = re.compile(
    r"^(\s*)(\d+)( (?:connection|connections))(  \|  )(\d+)( (?:app|apps))"
    r"(  \|  )(\d+)( flagged)(  \|  )(\d+%)( named)$"
)
RE_ROW = re.compile(
    r"^(  )(.+?)(\s+)(\d+)(\s+)(\d+)(\s+)(\d+)(\s+)([\u25cf\u25cb]+)(\s+)([\u2588]*)$"
)
RE_HEADER = re.compile(r"^\s+APP\s+CONNS\s+SITES\s+FLAGGED\s+CONF\s+LOAD$")
RE_PROMPT = re.compile(r"^\$ (.*)$")
RE_RECEIPT = re.compile(r"^\s+receipt written")

BAR = "\u2588"

# Consolas has U+2588 but not the lower eighth blocks, so a copylot sparkline
# renders as tofu. Substitute a density ramp: the same information, in glyphs
# every monospace font has.
SPARK_FALLBACK = {
    "\u2581": " ",
    "\u2582": ".",
    "\u2583": ":",
    "\u2584": "-",
    "\u2585": "=",
    "\u2586": "+",
    "\u2587": "*",
    "\u2588": "#",
}


def spark_to_ascii(text: str) -> str:
    return "".join(SPARK_FALLBACK.get(ch, ch) for ch in text)


def segments(line: str, regular) -> list[tuple[str, tuple[int, int, int], bool]]:
    """Split one output line into coloured runs, preserving spacing exactly.

    The layout is produced by the program, not invented here, so these patterns
    have to track `src/live.rs`. The rendering is a pure function of the text,
    which is why the GIF cannot show something the tool does not print.
    """
    out: list[tuple[str, tuple[int, int, int], bool]] = []

    if not line.strip():
        return out

    prompt = RE_PROMPT.match(line)
    if prompt:
        out.append(("$ ", GREEN, True))
        out.append((prompt.group(1), TEXT, False))
        return out

    title = RE_TITLE.match(line)
    if title:
        out.append((title.group(1), ACCENT, True))
        out.append((title.group(2), DIM, False))
        out.append((title.group(3), TEXT, False))
        out.append((title.group(4), DIM, False))
        out.append((spark_to_ascii(title.group(5)), GREEN, False))
        return out

    counts = RE_COUNTS.match(line)
    if counts:
        (
            indent,
            connections,
            connections_label,
            pipe1,
            apps,
            apps_label,
            pipe2,
            flagged,
            flagged_label,
            pipe3,
            coverage,
            named,
        ) = counts.groups()
        out.append((indent, DIM, False))
        out.append((connections, TEXT, False))
        out.append((connections_label, DIM, False))
        out.append((pipe1, DIM, False))
        out.append((apps, TEXT, False))
        out.append((apps_label, DIM, False))
        out.append((pipe2, DIM, False))
        out.append((flagged, DANGER if int(flagged) > 0 else TEXT, False))
        out.append((flagged_label, DIM, False))
        out.append((pipe3, DIM, False))
        out.append((coverage, DANGER if int(coverage.rstrip("%")) < 50 else TEXT, False))
        out.append((named, DIM, False))
        return out

    if RE_HEADER.match(line):
        out.append((line, DIM, False))
        return out

    row = RE_ROW.match(line)
    if row:
        indent, name, gap1, conns, gap2, sites, gap3, flagged, gap4, glyph, gap5, bar = (
            row.groups()
        )
        out.append((indent, DIM, False))
        # A truncated name is the one case where the text is not a real path.
        out.append((name, TEXT, False))
        out.append((gap1, DIM, False))
        out.append((conns, TEXT, False))
        out.append((gap2, DIM, False))
        out.append((sites, TEXT, False))
        out.append((gap3, DIM, False))
        out.append((flagged, DANGER if int(flagged) > 0 else DIM, False))
        out.append((gap4, DIM, False))
        if "\u25cf\u25cf" in glyph:
            colour = GREEN
        elif "\u25cf" in glyph:
            colour = ACCENT
        else:
            colour = DIM
        out.append((glyph, colour, False))
        out.append((gap5, DIM, False))
        out.append((bar, GREEN, False))
        return out

    if RE_RECEIPT.match(line):
        out.append((line, DIM, False))
        return out

    out.append((line, TEXT, False))
    return out

def text_width(font, text: str) -> int:
    return int(round(font.getlength(text)))


def build_frames(blocks: list[str]) -> list[tuple[list[str], int]]:
    """Turn raw frame blocks into (lines, hold_ms) pairs.

    The generator emits one block per table frame, then a block holding the
    "ctrl-c to stop" footer, then a block holding the closing command. Slicing
    `[:-2]` for the tables is load-bearing: `[:-3]` counts one too many and
    treats the final table as the footer.
    """
    tables = blocks[:-2]
    ctrl_c = blocks[-2].strip()
    closing = blocks[-1]

    frames: list[tuple[list[str], int]] = []
    for index, block in enumerate(tables):
        lines = block.strip("\n").split("\n")
        # Prepend the command that produced all of this.
        lines = ["$ tattle", ""] + lines
        if index == len(tables) - 1 and ctrl_c:
            lines += ["", ctrl_c]
        # Faster while the table fills, slower once it is complete.
        hold = 260 if index < len(tables) - 1 else 1400
        frames.append((lines, hold))

    closing_lines = closing.strip("\n").split("\n")

    # The closing frame keeps the full table and appends the payoff below it, so
    # the animation ends on "watch, then get a receipt" rather than on a blank
    # screen holding a single line.
    final = tables[-1].strip("\n").split("\n")
    final = ["$ tattle", ""] + final + [""] + closing_lines
    frames.append((final, 2600))

    return frames


def render(frames: list[tuple[list[str], int]], out_path: Path) -> None:
    regular, _bold = load_fonts()

    char_w = text_width(regular, "M")
    max_cols = max(len(ln) for lines, _ in frames for ln in lines)
    max_lines = max(len(lines) for lines, _ in frames)

    content_w = max_cols * char_w
    content_h = max_lines * LINE_H
    width = content_w + PAD_X * 2
    height = TITLEBAR_H + PAD_TOP + content_h + PAD_BOTTOM

    images: list[Image.Image] = []
    durations: list[int] = []

    for frame_index, (lines, hold) in enumerate(frames):
        img = Image.new("RGB", (width, height), BG)
        draw = ImageDraw.Draw(img)

        # Window body with a hairline border.
        draw.rounded_rectangle(
            [(0, 0), (width - 1, height - 1)], radius=RADIUS, fill=WINDOW, outline=BORDER, width=1
        )
        # Title bar: a slightly darker strip with three lights.
        draw.rounded_rectangle([(0, 0), (width - 1, TITLEBAR_H)], radius=RADIUS, fill=TITLEBAR)
        draw.rectangle([(0, TITLEBAR_H - RADIUS), (width - 1, TITLEBAR_H)], fill=TITLEBAR)
        draw.line([(0, TITLEBAR_H), (width - 1, TITLEBAR_H)], fill=BORDER)

        for i, colour in enumerate((DOT_RED, DOT_AMBER, DOT_GREEN)):
            cx = int(20 * SCALE) + i * int(20 * SCALE)
            r = int(6 * SCALE)
            draw.ellipse([(cx - r, TITLEBAR_H // 2 - r), (cx + r, TITLEBAR_H // 2 + r)], fill=colour)

        title = "tattle  -  live"
        tw = text_width(regular, title)
        draw.text(
            ((width - tw) // 2, TITLEBAR_H // 2 - FONT_SIZE // 2 - 1),
            title,
            font=regular,
            fill=DIM,
        )

        y = TITLEBAR_H + PAD_TOP
        for line_index, line in enumerate(lines):
            x = PAD_X
            for text, colour, bold in segments(line, regular):
                font = regular
                draw.text((x, y), text, font=font, fill=colour)
                x += text_width(font, text)

            # A cursor on the command line for the first two frames, so the GIF
            # reads as something being typed rather than a slide.
            if line_index == 0 and frame_index < 2:
                caret_x = PAD_X + text_width(regular, "$ tattle") + 2
                draw.rectangle(
                    [(caret_x, y + 2), (caret_x + char_w - 1, y + LINE_H - 4)], fill=TEXT
                )

            y += LINE_H

        images.append(img)
        durations.append(hold)

    images[0].save(
        out_path,
        save_all=True,
        append_images=images[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {out_path}  ({out_path.stat().st_size / 1024:.0f} KB, {len(images)} frames)")


def main() -> int:
    frames_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    raw = frames_path.read_text(encoding="utf-8")
    blocks = [b for b in raw.split("<<<FRAME>>>") if b.strip()]
    if len(blocks) < 5:
        print(f"expected several frames, got {len(blocks)}", file=sys.stderr)
        return 1

    render(build_frames(blocks), out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
