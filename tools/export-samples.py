#!/usr/bin/env python3
"""Exports public sample photos (scikit-image / matplotlib) as raw RGBA for tools/calibrate-pixels.mjs.
Usage: python3 tools/export-samples.py OUT_DIR
Developer tooling only; nothing here ships in the extension."""
import json, os, sys
import numpy as np

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
import skimage.data as d
names = ["astronaut", "camera", "coffee", "chelsea", "rocket", "brick", "grass", "gravel", "moon",
         "page", "text", "immunohistochemistry", "retina"]
meta = {}
for n in names:
    a = getattr(d, n)()
    if a.ndim == 2:
        a = np.stack([a] * 3, axis=-1)
    a = a[..., :3].astype(np.uint8)
    rgba = np.concatenate([a, np.full(a.shape[:2] + (1,), 255, np.uint8)], axis=-1)
    rgba.tofile(os.path.join(out, n + ".rgba"))
    meta[n] = [int(a.shape[1]), int(a.shape[0])]
try:
    from matplotlib import cbook
    import matplotlib.image as mpimg
    a = (mpimg.imread(cbook.get_sample_data("grace_hopper.jpg", asfileobj=False)) * (255 if False else 1)).astype(np.uint8)
    rgba = np.concatenate([a[..., :3], np.full(a.shape[:2] + (1,), 255, np.uint8)], axis=-1)
    rgba.tofile(os.path.join(out, "grace_hopper.rgba"))
    meta["grace_hopper"] = [int(a.shape[1]), int(a.shape[0])]
except Exception as e:
    print("skip grace_hopper:", e)
with open(os.path.join(out, "meta.json"), "w") as f:
    json.dump(meta, f)
print("exported", len(meta), "images to", out)
