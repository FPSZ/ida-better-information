#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the per-architecture byte-pattern database (FLAIR .pat) for glibc / musl.

For every (family, arch, version) it:
  1. picks a package from the Ubuntu pools (archive / ports / old-releases):
       glibc x86_64  libc6-dev_<v>_amd64.deb         -> usr/lib/x86_64-linux-gnu/libc.a
       glibc i386    libc6-dev-i386_<v>_amd64.deb    -> usr/lib32/libc.a
       glibc aarch64 libc6-dev_<v>_arm64.deb         -> usr/lib/aarch64-linux-gnu/libc.a
       musl  *       musl-dev_<v>_<arch>.deb         -> usr/lib/musl/lib/libc.a
     (newest Ubuntu revision for the DB; with --corpus the OLDEST one, so the
      regression corpus is linked against a different build than the DB)
  2. extracts libc.a (+ crt objects) with pure Python (ar + tar.{xz,zst,gz})
  3. runs FLAIR `pelf` -> <out>/<arch>/<key>.pat     (key = "2.35" or "musl_1.2.5")

usage:
  python tools/build-db.py --pelf <flair>/pelf.exe [--arch x86_64,i386,aarch64]
                           [--family glibc,musl] [--out db] [--cache _cache]
  python tools/build-db.py --corpus --cache _cache      # only fetch + extract (oldest rev)

Then: python tools/build-fingerprint.py _db tools/fingerprint.json
"""
import argparse, io, os, re, subprocess, sys, tarfile, time, urllib.request

GLIBC_VERSIONS = ["2.19", "2.21", "2.23", "2.24", "2.26", "2.27", "2.28", "2.29", "2.30",
                  "2.31", "2.32", "2.33", "2.34", "2.35", "2.36", "2.37", "2.38", "2.39",
                  "2.40", "2.41", "2.42", "2.43", "2.44"]
MUSL_VERSIONS = ["1.1.24", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6"]

ARCHIVE = "http://archive.ubuntu.com/ubuntu/pool"
PORTS = "http://ports.ubuntu.com/ubuntu-ports/pool"
OLD = "http://old-releases.ubuntu.com/ubuntu/pool"

# arch -> (deb arch, glibc package, libc.a dir inside the deb, pools to search)
ARCHES = {
    "x86_64":  ("amd64", "libc6-dev",      "usr/lib/x86_64-linux-gnu", (ARCHIVE, OLD)),
    "i386":    ("amd64", "libc6-dev-i386", "usr/lib32",                (ARCHIVE, OLD)),
    "aarch64": ("arm64", "libc6-dev",      "usr/lib/aarch64-linux-gnu", (PORTS, OLD)),
}
MUSL_DEB_ARCH = {"x86_64": "amd64", "i386": "i386", "aarch64": "arm64"}
KEEP = ("libc.a", "libc_nonshared.a", "crt1.o", "crti.o", "crtn.o", "rcrt1.o", "Scrt1.o")

# Ubuntu stopped building musl for i386 after 1.1.19 -> fall back to Alpine (x86) there.
ALPINE = "https://dl-cdn.alpinelinux.org/alpine"
ALPINE_REL = {"1.1.24": "v3.12", "1.2.2": "v3.14", "1.2.3": "v3.17", "1.2.4": "v3.19",
              "1.2.5": "v3.21", "1.2.6": "edge"}
ALPINE_ARCH = {"x86_64": "x86_64", "i386": "x86", "aarch64": "aarch64"}


def log(*a):
    print(*a, flush=True)


def fetch(url, dst=None, tries=3):
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                data = r.read()
            if dst:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst + ".part", "wb") as f:
                    f.write(data)
                os.replace(dst + ".part", dst)
            return data
        except Exception as e:          # flaky mirrors: retry
            last = e
            time.sleep(2 + 3 * i)
    raise last


_listing_cache = {}

def listing(cache, url):
    """Pool directory listing -> set of .deb names (cached on disk for a day)."""
    if url in _listing_cache:
        return _listing_cache[url]
    fn = os.path.join(cache, "listings", re.sub(r"[^A-Za-z0-9]+", "_", url) + ".html")
    if not (os.path.exists(fn) and time.time() - os.path.getmtime(fn) < 86400):
        fetch(url, fn)
    html = open(fn, "r", encoding="utf-8", errors="replace").read()
    names = set(re.findall(r'href="([^"]+\.(?:deb|apk))"', html))
    _listing_cache[url] = names
    return names


def _rev_key(rev):
    """Debian revision -> sortable tuple ('0ubuntu3.15' > '0ubuntu3.2' > '0ubuntu3')."""
    return [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[A-Za-z]+", rev)]


def pick_deb(cache, family, arch, ver, oldest=False):
    """Return (url, debname) of the newest (or oldest) Ubuntu build of <ver>."""
    debarch, pkg, _, pools = ARCHES[arch]
    if family == "musl":
        pkg, debarch, sub = "musl-dev", MUSL_DEB_ARCH[arch], "universe/m/musl"
        pools = (PORTS, OLD) if arch == "aarch64" else (ARCHIVE, OLD)
    else:
        sub = "main/g/glibc"
    rx = re.compile(r"^%s_%s(?:-([^_]+))?_%s\.deb$" % (re.escape(pkg), re.escape(ver), debarch))
    cands = []
    for pool in pools:
        base = "%s/%s/" % (pool, sub)
        try:
            names = listing(cache, base)
        except Exception as e:
            log("   listing failed: %s (%s)" % (base, e))
            continue
        for n in names:
            m = rx.match(n)
            if m:
                cands.append((_rev_key(m.group(1) or ""), base + n, n))
        if cands and pool != OLD:
            break                       # prefer the live pool; fall back to old-releases
    if not cands and family == "musl" and ver in ALPINE_REL:
        base = "%s/%s/main/%s/" % (ALPINE, ALPINE_REL[ver], ALPINE_ARCH[arch])
        arx = re.compile(r"^musl-dev-%s(?:_git\d+)?-r(\d+)\.apk$" % re.escape(ver))
        try:
            for n in listing(cache, base):
                m = arx.match(n)
                if m:
                    cands.append(([int(m.group(1))], base + n, n))
        except Exception as e:
            log("   listing failed: %s (%s)" % (base, e))
    if not cands:
        return None, None
    cands.sort()
    _, url, name = cands[0] if oldest else cands[-1]
    return url, name


def ar_members(blob):
    if not blob.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    off = 8
    while off + 60 <= len(blob):
        hdr = blob[off:off + 60]
        name = hdr[:16].decode().strip().rstrip("/")
        size = int(hdr[48:58].decode().strip())
        yield name, blob[off + 60: off + 60 + size]
        off += 60 + size + (size & 1)


def extract(deb_path, libdir, outdir):
    """Pull libc.a + crt objects out of a .deb / .apk into outdir. Returns list of files."""
    blob = open(deb_path, "rb").read()
    if deb_path.endswith(".apk"):               # Alpine: concatenated gzip'd tar segments
        import gzip
        data, libdir, mode = gzip.decompress(blob), "usr/lib", "r:"
    else:
        data = next((d for n, d in ar_members(blob) if n.startswith("data.tar")), None)
        mode = "r:*"
    if data is None:
        raise ValueError("no data.tar in " + deb_path)
    os.makedirs(outdir, exist_ok=True)
    got = []
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode, ignore_zeros=True) as tf:
        for m in tf:
            p = m.name.lstrip("./")
            if not m.isfile() or os.path.dirname(p) != libdir.strip("/"):
                continue
            if os.path.basename(p) in KEEP:
                dst = os.path.join(outdir, os.path.basename(p))
                with open(dst, "wb") as f:
                    f.write(tf.extractfile(m).read())
                got.append(dst)
    return got


def libdir_for(family, arch):
    if family == "musl":                        # Debian/Ubuntu musl-dev layout (.apk handled in extract)
        return "usr/lib/%s-linux-musl" % arch
    return ARCHES[arch][2]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arch", default="x86_64,i386,aarch64")
    ap.add_argument("--family", default="glibc,musl")
    ap.add_argument("--versions", default="", help="comma list to restrict versions")
    ap.add_argument("--pelf", default=os.environ.get("FLAIR_PELF", ""))
    ap.add_argument("--out", default="_db")
    ap.add_argument("--cache", default="_cache")
    ap.add_argument("--corpus", action="store_true", help="fetch the OLDEST revision, extract only (no pelf)")
    args = ap.parse_args()

    only = set(v for v in args.versions.split(",") if v)
    ok, fail = [], []
    for family in args.family.split(","):
        vers = GLIBC_VERSIONS if family == "glibc" else MUSL_VERSIONS
        for arch in args.arch.split(","):
            for ver in vers:
                if only and ver not in only:
                    continue
                key = ver if family == "glibc" else "musl_" + ver
                tag = "%s/%s" % (arch, key)
                pat = os.path.join(args.out, arch, key + ".pat")
                if not args.corpus and os.path.exists(pat) and os.path.getsize(pat) > 0:
                    log("skip %-18s (exists)" % tag); ok.append(tag); continue
                url, name = pick_deb(args.cache, family, arch, ver, oldest=args.corpus)
                if not url:
                    log("MISS %-18s no package in the Ubuntu pools" % tag); fail.append(tag); continue
                deb = os.path.join(args.cache, "debs", name)
                try:
                    if not os.path.exists(deb):
                        log("get  %-18s %s" % (tag, name))
                        fetch(url, deb)
                    xdir = os.path.join(args.cache, "x", os.path.splitext(name)[0])
                    files = extract(deb, libdir_for(family, arch), xdir)
                    liba = os.path.join(xdir, "libc.a")
                    if not os.path.exists(liba):
                        raise RuntimeError("libc.a not found in package")
                    if args.corpus:
                        log("ok   %-18s %s (%d files)" % (tag, xdir, len(files))); ok.append(tag); continue
                    os.makedirs(os.path.dirname(pat), exist_ok=True)
                    r = subprocess.run([args.pelf, liba, pat], capture_output=True, text=True)
                    if r.returncode != 0 or not os.path.exists(pat) or os.path.getsize(pat) == 0:
                        raise RuntimeError("pelf failed: " + (r.stdout + r.stderr)[-400:])
                    n = sum(1 for _ in open(pat, errors="ignore"))
                    log("ok   %-18s %d patterns  (%s)" % (tag, n, name)); ok.append(tag)
                except Exception as e:
                    log("FAIL %-18s %s" % (tag, e)); fail.append(tag)
    log("done: %d ok, %d failed %s" % (len(ok), len(fail), " ".join(fail)))
    sys.exit(1 if fail and not ok else 0)


if __name__ == "__main__":
    main()
