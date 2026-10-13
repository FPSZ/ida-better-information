"""Detect the runtime of the program loaded in the database."""
from ..core.detect import detect
from ..core.fingerprint import _present_in_buffer, _scan_window
from ..core.i18n import T


def _present_hook(prog):
    """Scan the loaded executable segments for anchors (database-local).
       Falls back to per-function windows if the image can't be read in bulk."""
    def hook(index):
        buf = prog.image_bytes()
        if buf:
            return _present_in_buffer(buf, index)
        present = set()
        for w in prog.function_heads(32):
            if w:
                _scan_window(w, index, present)
        return present
    return hook


def run_detection(prog):
    """(result, None) or (None, error text)."""
    arch = prog.arch()
    data = prog.input_bytes()
    try:
        if data is not None:
            # IDA can load an ELF yet create no segments (e.g. tampered EI_CLASS):
            # then scan the file on disk instead of an empty database
            if not prog.has_code():
                r = detect(data=data, arch_hint=arch)
                r.setdefault("notes", []).append(T(
                    "IDA loaded no code from this file; the file on disk was scanned instead.",
                    "IDA 没有从该文件加载出代码,已改为扫描磁盘上的原文件。"))
                return r, None
            return detect(data=data, arch_hint=arch, present_hook=_present_hook(prog)), None
        # file is gone: reconstruct enough from the database
        img = prog.header_bytes() + prog.image_bytes()
        return detect(data=img, arch_hint=arch, present_hook=_present_hook(prog)), None
    except Exception as e:
        return None, "detect error: %s" % e
