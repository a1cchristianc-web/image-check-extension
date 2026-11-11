#!/usr/bin/env python3
"""Builds realistic (main image, embedded-thumbnail) test cases from public sample photos
(scikit-image / matplotlib) for tools/calibrate-thumbnail.mjs.

Usage: python3 tools/export-thumbnail-cases.py OUT_DIR
Developer tooling only; nothing here ships in the extension.

Each case is a pair: the image as it exists in the file, and the preview thumbnail that was
embedded when the photo was taken (a small, JPEG-compressed copy of the ORIGINAL).
  same        untouched photo                      -> must NOT be flagged
  rotated     thumbnail stored unrotated (EXIF)    -> must NOT be flagged
  regrade     colour/contrast/saturation changed   -> must NOT be flagged (benign edit)
  resaved     downscaled + recompressed            -> must NOT be flagged (benign edit)
  crop90/70/50  image cropped, thumbnail stale     -> should be flagged (more so for tighter crops)
  replaced    different photo, thumbnail stale     -> should be flagged
  retouch     ~8% of the area painted over         -> expected NOT flagged (a known limit)
"""
import io
import json
import os
import sys

import numpy as np
from PIL import Image, ImageEnhance

out = sys.argv[1]
os.makedirs(out, exist_ok=True)

import skimage.data as d

photos = {n: getattr(d, n)() for n in ["astronaut", "camera", "coffee", "chelsea", "rocket", "moon", "immunohistochemistry", "retina"]}
textures = {n: getattr(d, n)() for n in ["brick", "grass", "gravel", "page", "text"]}
try:
    from matplotlib import cbook
    import matplotlib.image as mpimg
    photos["grace_hopper"] = mpimg.imread(cbook.get_sample_data("grace_hopper.jpg", asfileobj=False))
except Exception as e:  # noqa: BLE001
    print("skip grace_hopper:", e)


def rgb(a):
    a = np.asarray(a)
    if a.dtype != np.uint8:
        a = (a * 255).clip(0, 255).astype(np.uint8)
    if a.ndim == 2:
        a = np.stack([a] * 3, axis=-1)
    return Image.fromarray(a[..., :3])


def jpeg_roundtrip(im, q):
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=q)
    return Image.open(io.BytesIO(buf.getvalue())).convert("RGB")


def thumb_of(im):  # what a camera embeds: ~160px wide JPEG
    t = im.copy()
    t.thumbnail((160, 160), Image.BILINEAR)
    return jpeg_roundtrip(t, 65)


def crop(im, f):
    w, h = im.size
    cw, ch = int(w * f), int(h * f)
    x, y = (w - cw) // 2, (h - ch) // 3
    return im.crop((x, y, x + cw, y + ch))


def retouch(im):
    a = np.array(im)
    h, w = a.shape[:2]
    ph, pw = int(h * 0.28), int(w * 0.28)  # 0.28*0.28 ~ 8% of the area
    y, x = int(h * 0.2), int(w * 0.55)
    a[y:y + ph, x:x + pw] = np.array(im)[h - ph - 10:h - 10, 10:10 + pw]  # paste another part over it
    return Image.fromarray(a)


def regrade(im):
    im = ImageEnhance.Brightness(im).enhance(1.25)
    im = ImageEnhance.Contrast(im).enhance(1.3)
    return ImageEnhance.Color(im).enhance(0.6)


def resaved(im):
    w, h = im.size
    return jpeg_roundtrip(im.resize((max(8, int(w * 0.6)), max(8, int(h * 0.6))), Image.BILINEAR), 55)


cases = []


def add(name, kind, group, main, thumb):
    for tag, im in (("main", main), ("thumb", thumb)):
        a = np.array(im.convert("RGBA"))
        a[..., 3] = 255
        a.tofile(os.path.join(out, f"{name}.{kind}.{tag}.rgba"))
    cases.append({"name": name, "kind": kind, "group": group,
                  "main": [f"{name}.{kind}.main.rgba", main.size[0], main.size[1]],
                  "thumb": [f"{name}.{kind}.thumb.rgba", thumb.size[0], thumb.size[1]]})


for group, src in (("photo", photos), ("texture", textures)):
    names = list(src)
    for i, n in enumerate(names):
        im = rgb(src[n])
        th = thumb_of(im)
        other = rgb(src[names[(i + 3) % len(names)]])
        add(n, "same", group, im, th)
        add(n, "rotated", group, im, th.rotate(90, expand=True))
        add(n, "regrade", group, regrade(im), th)
        add(n, "resaved", group, resaved(im), th)
        for f in (0.9, 0.7, 0.5):
            add(n, f"crop{int(f * 100)}", group, crop(im, f), th)
        add(n, "replaced", group, other, th)
        add(n, "retouch", group, retouch(im), th)

json.dump(cases, open(os.path.join(out, "cases.json"), "w"))
print(len(cases), "cases written to", out)
