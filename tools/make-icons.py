#!/usr/bin/env python3
"""Draws the extension icon (an original design: an image frame with a check mark) at 16/32/48/128 px.
Run:  python3 tools/make-icons.py   (needs Pillow)"""
import os
from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "icons")
os.makedirs(OUT, exist_ok=True)
S = 1024  # draw large, then downsample for smooth edges

def draw():
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=230, fill=(24, 62, 120, 255))          # tile
    d.rounded_rectangle((170, 200, 854, 700), radius=70, fill=(244, 248, 255, 255))           # photo frame
    d.polygon([(170, 640), (370, 420), (520, 570), (640, 470), (854, 680), (854, 630), (854, 700), (170, 700)],
              fill=(120, 170, 225, 255))                                                      # hills
    d.ellipse((650, 270, 760, 380), fill=(255, 200, 70, 255))                                 # sun
    d.ellipse((560, 560, 960, 960), fill=(34, 160, 90, 255), outline=(255, 255, 255, 255), width=36)  # badge
    d.line([(655, 765), (730, 840), (870, 685)], fill=(255, 255, 255, 255), width=64, joint="curve")  # check
    return im

big = draw()
for n in (16, 32, 48, 128):
    big.resize((n, n), Image.LANCZOS).save(os.path.join(OUT, f"icon{n}.png"))
print("wrote icons to", os.path.abspath(OUT))
