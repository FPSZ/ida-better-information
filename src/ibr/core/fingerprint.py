"""Byte-anchor fingerprint database: decode, index and score libc builds.

fingerprint.bin holds 29 builds each for x86_64 / i386 / aarch64: glibc 2.19-2.44 + musl.
Rebuild with tools/build-db.py -> tools/build-fingerprint.py (see tools/ for provenance)."""
from . import resources


_FP_CACHE = None       # {arch: {"table":[bytes...], "vers":{key:[idx...]}}}
_ARCH_CACHE = {}       # {arch: (prefix_index, {key:set(idx)})}


def _rd_uvarint(b, p):
    shift = val = 0
    while True:
        x = b[p]; p += 1
        val |= (x & 0x7F) << shift
        if not (x & 0x80):
            return val, p
        shift += 7


def _rd_str(b, p):
    n = b[p]; p += 1
    return b[p:p + n].decode(), p + n


def _decode_fp(blob):
    """Decode the compact IBIFP2 blob into {arch: {"table":[...], "vers":{...}}}."""
    if blob[:6] != b"IBIFP2":
        raise ValueError("bad fingerprint blob")
    p = 6
    narch = blob[p]; p += 1
    out = {}
    for _ in range(narch):
        arch, p = _rd_str(blob, p)
        ntab, p = _rd_uvarint(blob, p)
        table = []
        for _ in range(ntab):
            ln = blob[p]; p += 1
            table.append(blob[p:p + ln]); p += ln
        nver, p = _rd_uvarint(blob, p)
        vers = {}
        for _ in range(nver):
            key, p = _rd_str(blob, p)
            nidx, p = _rd_uvarint(blob, p)
            idx = []; prev = 0
            for _ in range(nidx):
                d, p = _rd_uvarint(blob, p)
                prev += d; idx.append(prev)
            vers[key] = idx
        out[arch] = {"table": table, "vers": vers}
    return out


def _load_fp():
    global _FP_CACHE
    if _FP_CACHE is None:
        try:
            _FP_CACHE = _decode_fp(resources.load("fingerprint.bin"))
        except Exception:
            _FP_CACHE = {}
    return _FP_CACHE


# Each anchor (10..24 bytes) is indexed by its *rarest* 8-byte window rather than its
# prefix. Anchors start in function prologues, so prefixes collide massively (x86_64:
# 12k anchors -> 4.5k distinct 8-byte prefixes, largest bucket 1124 anchors, all hit
# at every function entry). Keying on the window least shared with other anchors
# gives ~11.6k distinct keys, largest bucket 7, and ~300x less verification work.
_Q = 8


def _arch_db(arch):
    """Return (index, {key:set(idx)}) for an arch, or (None, None).
       index maps an 8-byte key to [(anchor_id, anchor_bytes, key_offset_in_anchor)]."""
    if arch in _ARCH_CACHE:
        return _ARCH_CACHE[arch]
    fp = _load_fp().get(arch)
    if not fp:
        _ARCH_CACHE[arch] = (None, None)
        return None, None
    table = fp["table"]
    freq = {}
    for a in table:
        for j in range(len(a) - _Q + 1):
            w = a[j:j + _Q]
            freq[w] = freq.get(w, 0) + 1
    index = {}
    for i, a in enumerate(table):
        j = min(range(len(a) - _Q + 1), key=lambda j: (freq[a[j:j + _Q]], -j))
        index.setdefault(a[j:j + _Q], []).append((i, a, j))
    vers = {k: set(v) for k, v in fp["vers"].items()}
    _ARCH_CACHE[arch] = (index, vers)
    return index, vers


def _lib_label(key):
    if key.startswith("musl"):
        return "musl " + key.split("_", 1)[-1]
    return "glibc " + key


# ======================================================================
#  Scanning — find which anchors are present in a byte buffer
# ======================================================================
def _scan_window(window, index, present):
    """Record ids of anchors occurring anywhere in window."""
    get = index.get
    for p in range(len(window) - _Q + 1):
        bucket = get(window[p:p + _Q])
        if bucket:
            for i, a, j in bucket:
                s = p - j
                if i not in present and s >= 0 and window[s:s + len(a)] == a:
                    present.add(i)


def _present_in_buffer(buf, index):
    present = set()
    if buf and index is not None:
        _scan_window(buf, index, present)
    return present


def _score(present, vers, top):
    scored = []
    for ver, ids in vers.items():
        if not ids:
            continue
        hit = len(present & ids)
        scored.append((ver, hit / len(ids), hit, len(ids)))
    scored.sort(key=lambda t: t[1], reverse=True)
    return scored[:top], scored
