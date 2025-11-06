"""Utility methods to assist with testing of screenshot images"""

import io
import itertools
import zipfile
from typing import List

from PIL import Image, ImageChops, ImageSequence


def _make_img_zip(imgs: List[Image.Image]) -> bytes:
    # Make a ZIP file in CAPE JPEG screenshot format, with the images in the provided list (PIL `Image`s)
    # Returns the byte-stream of the ZIP file
    temp_zip = io.BytesIO()
    with zipfile.ZipFile(temp_zip, "w") as zf:
        for num, img in enumerate(imgs):
            bio = io.BytesIO()
            img.save(bio, "JPEG", quality=90)
            zf.writestr(f"shots/{num:04}.jpg", bio.getvalue())
    temp_zip.seek(0)
    return temp_zip.read()


def _compare_img_seqs(orig_img_list: List[Image.Image], webp_data: bytes):
    """
    Use Pillow to compare source JPG sequence with the WEBP animation output by the plugin

    Params: a list of binary source JPG data and the binary content of the WEBP file to compare with them
    Returns True if matching, False if different
    Typical usage: _compare_img_seqs(test_imgs, res['data'][<hash_of_output_webpfile>])
    Because we use lossy WEBP, it will pass as long as the maximum single-pixel absolute difference
     is <24 (of 256) on any channel (R,G,B). (ie the images should be more or less visually indistinguishable)
    """
    imseq = Image.open(io.BytesIO(webp_data))
    for origframe, newframe in itertools.zip_longest(orig_img_list, ImageSequence.Iterator(imseq)):
        if origframe is None or newframe is None:
            # One of the sequences is longer than the other
            print("DEBUG: Image sequence length mismatch")
            return False
        if origframe.getbbox() != newframe.getbbox():
            print(f"DEBUG: bounding box mismatch: orig {origframe.getbbox()}, new {newframe.getbbox()}")
            return False
        if origframe.getbands() != newframe.getbands():
            print(f"DEBUG: image channels mismatch: orig {origframe.getbands()}, new {newframe.getbands()}")
            return False
        diff = ImageChops.difference(origframe, newframe)
        if max([t[1] for t in diff.getextrema()]) > 24:
            # The images differed too greatly
            print(f"DEBUG: images differ, max extrema are {diff.getextrema()} (should be <=24)")
            return False
    return True
