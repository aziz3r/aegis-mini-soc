#!/usr/bin/env python3
"""Compose the annotated demo reel from captured frames.

ffmpeg on macOS ships without `drawtext` (no libfreetype), so the captions are
burned in with Pillow and ffmpeg only assembles and encodes.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "docs" / "screenshots"
OUT = ROOT / "docs" / "media"

WIDTH = 800
BAR = 86
BG = (7, 11, 20)
ACCENT = (34, 211, 238)
TITLE = (241, 245, 249)
SUB = (148, 163, 184)
RULE = (31, 49, 83)

FONTS = Path("/System/Library/Fonts/Supplemental")


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    for candidate in (FONTS / name, Path("/System/Library/Fonts/Helvetica.ttc")):
        if candidate.exists():
            try:
                return ImageFont.truetype(str(candidate), size)
            except OSError:
                continue
    return ImageFont.load_default()


F_STEP = font("Arial Bold.ttf", 15)
F_TITLE = font("Arial Bold.ttf", 20)
F_SUB = font("Arial.ttf", 15)


def compose(shot: Path, step: str, title: str, subtitle: str, height: int) -> Image.Image:
    """One frame: the screenshot, letterboxed to a common size, plus a caption bar."""
    img = Image.open(shot).convert("RGB")
    if img.width != WIDTH:
        img = img.resize((WIDTH, round(img.height * WIDTH / img.width)), Image.LANCZOS)

    canvas = Image.new("RGB", (WIDTH, height + BAR), BG)
    canvas.paste(img, (0, max((height - img.height) // 2, 0)))

    draw = ImageDraw.Draw(canvas)
    top = height
    draw.line([(0, top), (WIDTH, top)], fill=RULE, width=1)
    draw.text((24, top + 16), step, font=F_STEP, fill=ACCENT)
    step_w = draw.textlength(step, font=F_STEP)
    draw.text((24 + step_w + 14, top + 13), title, font=F_TITLE, fill=TITLE)
    draw.text((24, top + 48), subtitle, font=F_SUB, fill=SUB)
    return canvas


def main() -> int:
    frames_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    OUT.mkdir(parents=True, exist_ok=True)
    build = OUT / "_frames"
    build.mkdir(exist_ok=True)
    for stale in build.glob("*.png"):
        stale.unlink()

    motion = sorted(frames_dir.glob("*.jpg")) if frames_dir and frames_dir.exists() else []

    # (source image, step, title, subtitle, seconds)
    scenes: list[tuple[Path, str, str, str, float]] = []

    def add(src: Path, step: str, title: str, sub: str, secs: float) -> None:
        if src.exists():
            scenes.append((src, step, title, sub, secs))

    # the captured login + live frames carry real motion; the rest are stills
    if len(motion) >= 9:
        for f in motion[0:3]:
            add(f, "01", "Sign in", "Three server-enforced roles: viewer, analyst, admin.", 0.9)
        add(motion[4], "02", "Overview",
            "Open incidents by severity, 24 h anomaly score, observed precision.", 3.2)
        for f in motion[5:9]:
            add(f, "03", "Live stream (WebSocket)",
                "Mean traffic score vs the per-host threshold, updating in real time.", 0.85)
    else:
        add(SHOTS / "01-connexion.jpg", "01", "Sign in",
            "Three server-enforced roles: viewer, analyst, admin.", 2.4)
        add(SHOTS / "02-vue-ensemble.jpg", "02", "Overview",
            "Open incidents by severity, 24 h anomaly score, observed precision.", 3.4)
        add(SHOTS / "03-flux-temps-reel.jpg", "03", "Live stream (WebSocket)",
            "Mean traffic score vs the per-host threshold, updating in real time.", 3.4)

    add(SHOTS / "04-incidents.jpg", "04", "Incident queue",
        "Sorted by priority, not by score: severity weighs asset criticality.", 3.4)
    add(SHOTS / "05-incident-explication.jpg", "05", "Why this alert",
        "Occlusion attribution: each feature replaced by its benign median, flow re-scored.", 4.0)
    add(SHOTS / "06-incident-alertes.jpg", "06", "Merged alerts + ground truth",
        "8,994 alerts collapsed into one incident. Lab ground truth confirms every one.", 3.6)
    add(SHOTS / "07-hotes.jpg", "07", "Per-host profiles",
        "Each host carries its own adaptive threshold and traffic baseline.", 3.0)
    add(SHOTS / "08-modele-metriques.jpg", "08", "Measured performance",
        "Loud vs stealth attacks. The C2 beacon at 48.6 % is published, not hidden.", 4.2)
    add(SHOTS / "09-sources-rejeu.jpg", "09", "Three traffic sources",
        "Synthetic lab, PCAP replay, live capture - all through the same engine.", 3.4)
    add(SHOTS / "10-reglages.jpg", "10", "Operating point",
        "Thresholds and asset inventory, editable live - no retraining needed.", 3.0)
    add(SHOTS / "11-journal-audit.jpg", "11", "Audit trail",
        "Every state change attributed. Without it, triage is not verifiable.", 3.0)

    if not scenes:
        print("aucune image source trouvée", file=sys.stderr)
        return 1

    height = max(
        round(Image.open(src).height * WIDTH / Image.open(src).width) for src, *_ in scenes
    )

    listing: list[str] = []
    last = ""
    for i, (src, step, title, sub, secs) in enumerate(scenes):
        frame = build / f"{i:03d}.png"
        compose(src, step, title, sub, height).save(frame)
        listing.append(f"file '{frame.name}'")
        listing.append(f"duration {secs}")
        last = frame.name
    # the concat demuxer ignores the final entry's duration, so the last image is
    # repeated to give the closing scene its full time on screen
    listing.append(f"file '{last}'")

    concat = build / "list.txt"
    concat.write_text("\n".join(listing) + "\n")

    gif, mp4 = OUT / "demo.gif", OUT / "demo.mp4"
    common = ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
              "-f", "concat", "-safe", "0", "-i", str(concat)]
    subprocess.run(common + [
        "-vf", "fps=10,scale=760:-2:flags=lanczos,split[a][b];[a]palettegen=max_colors=160[p];"
               "[b][p]paletteuse=dither=bayer:bayer_scale=3",
        "-loop", "0", str(gif)], check=True)
    subprocess.run(common + [
        "-vf", "fps=24,scale=1000:-2:flags=lanczos,format=yuv420p",
        "-c:v", "libx264", "-preset", "slow", "-crf", "24", "-movflags", "+faststart",
        str(mp4)], check=True)

    total = sum(s[4] for s in scenes)
    print(f"{len(scenes)} plans · {total:.0f}s")
    print(f"  {gif.relative_to(ROOT)}  {gif.stat().st_size / 1024 / 1024:.1f} Mio")
    print(f"  {mp4.relative_to(ROOT)}  {mp4.stat().st_size / 1024 / 1024:.1f} Mio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
