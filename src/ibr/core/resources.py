"""Data files (fingerprint DB, syscall tables): embedded in the single-file build, else
read from ibr/data/ next to the package."""
import base64
import gzip
import os

# filled by the single-file bootstrap: name -> base64 of the gzip-compressed file
BUNDLED = {}


def load(name):
    """Raw bytes of a data file."""
    if name in BUNDLED:
        return gzip.decompress(base64.b64decode(BUNDLED[name]))
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", name)
    with open(path, "rb") as f:
        return f.read()
