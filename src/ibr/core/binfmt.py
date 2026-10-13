"""ELF/PE header parsing, tamper detection, packer and language markers."""
import re
import struct


EM_TO_ARCH = {3: "i386", 62: "x86_64", 183: "aarch64", 40: "arm",
              8: "mips", 10: "mips", 21: "ppc", 22: "ppc64", 243: "riscv"}
_ARCH_BITS = {"x86_64": 64, "aarch64": 64, "ppc64": 64, "i386": 32, "arm": 32, "ppc": 32}


def _elf_layout(data):
    """Return (is64, endian, tamper_note). The kernel loads x86/ARM ELFs without
       trusting EI_CLASS/EI_DATA, so CTF binaries rewrite those ident bytes to break
       file(1), readelf and disassemblers. If the declared layout yields no known
       machine but the other byte order does, trust the header fields instead."""
    if len(data) < 0x40:
        return len(data) > 4 and data[4] == 2, ">" if len(data) > 5 and data[5] == 2 else "<", None
    is64 = data[4] == 2
    en = "<" if data[5] == 1 else ">"
    declared = 64 if is64 else 32
    ok = lambda e: (EM_TO_ARCH.get(struct.unpack_from(e + "H", data, 18)[0]),
                    struct.unpack_from(e + "H", data, 16)[0] in (1, 2, 3, 4))

    def fits(bits, e):
        # e_ehsize/e_phentsize are fixed per class (64/56 or 52/32) and sit at different
        # offsets, so they tell the real class even when e_type/e_machine read fine
        off, eh, ph = (0x34, 64, 56) if bits == 64 else (0x28, 52, 32)
        a, b = struct.unpack_from(e + "HH", data, off)
        return a == eh and b in (ph, 0)

    def note(bits, e, arch):
        return ("ELF ident bytes tampered: EI_CLASS/EI_DATA claim %d-bit %s-endian, "
                "header decodes as %d-bit %s-endian %s (to load it in IDA, set file "
                "byte 4 to %d and byte 5 to %d)"
                % (declared, "little" if en == "<" else "big",
                   bits, "little" if e == "<" else "big", arch,
                   2 if bits == 64 else 1, 1 if e == "<" else 2))

    arch, typ_ok = ok(en)
    if arch and typ_ok:
        if fits(declared, en) or not fits(96 - declared, en):
            return is64, en, None
        return 96 - declared == 64, en, note(96 - declared, en, arch)     # only EI_CLASS rewritten
    for e in ("<", ">"):
        arch, typ_ok = ok(e)
        if arch and typ_ok:
            bits = 64 if fits(64, e) else 32 if fits(32, e) else _ARCH_BITS.get(arch, declared)
            return bits == 64, e, note(bits, e, arch)
    return is64, en, None


def _parse_elf_headers(data):
    """Return dict with arch, class, interp, needed count, exec byte ranges."""
    r = {"arch": None, "bits": None, "etype": None, "interp": None,
         "needed": 0, "exec_ranges": [], "machine": None, "tampered": None}
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return r
    is64, en, r["tampered"] = _elf_layout(data)
    r["bits"] = 64 if is64 else 32
    r["etype"] = struct.unpack_from(en + "H", data, 16)[0]
    machine = struct.unpack_from(en + "H", data, 18)[0]
    r["machine"] = machine
    r["arch"] = EM_TO_ARCH.get(machine)
    try:
        if is64:
            phoff = struct.unpack_from(en + "Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 54)
        else:
            phoff = struct.unpack_from(en + "I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 42)
        if phentsize < (56 if is64 else 32):
            phnum = 0                    # a forged entry size would re-read one entry 65535 times
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + phentsize > len(data):
                break
            p_type = struct.unpack_from(en + "I", data, off)[0]
            if is64:
                p_flags = struct.unpack_from(en + "I", data, off + 4)[0]
                p_offset = struct.unpack_from(en + "Q", data, off + 8)[0]
                p_filesz = struct.unpack_from(en + "Q", data, off + 32)[0]
                dent = 16
            else:
                p_offset = struct.unpack_from(en + "I", data, off + 4)[0]
                p_filesz = struct.unpack_from(en + "I", data, off + 16)[0]
                p_flags = struct.unpack_from(en + "I", data, off + 24)[0]
                dent = 8
            if p_type == 3:                                   # PT_INTERP
                s = data[p_offset:p_offset + p_filesz].split(b"\x00", 1)[0]
                r["interp"] = s.decode("latin1", "replace")
            elif p_type == 2:                                 # PT_DYNAMIC
                for j in range(0, p_filesz, dent):
                    o = p_offset + j
                    if o + dent > len(data):
                        break
                    tag = struct.unpack_from(en + ("q" if is64 else "i"), data, o)[0]
                    if tag == 0:
                        break
                    if tag == 1:                              # DT_NEEDED
                        r["needed"] += 1
            elif p_type == 1 and (p_flags & 1):               # PT_LOAD + X
                if (p_offset, p_filesz) not in r["exec_ranges"]:
                    r["exec_ranges"].append((p_offset, p_filesz))
    except Exception:
        pass
    return r


def _comment_toolchain(data):
    """Extract the .comment producer string (GCC/clang/rustc) if present."""
    m = re.search(rb"GCC: \(([^)]*)\) ([0-9][^\x00\n]*)", data)
    if m:
        return "gcc %s (%s)" % (m.group(2).decode("latin1", "replace"),
                                m.group(1).decode("latin1", "replace"))
    m = re.search(rb"(?:Ubuntu |Debian )?clang version ([0-9][^\x00\n]{0,40})", data)
    if m:
        return "clang " + m.group(1).decode("latin1", "replace")
    return None


# map an Ubuntu gcc toolchain string to the glibc it ships (coarse cross-check)
_UBUNTU_GLIBC = [
    ("16.04", "2.23"), ("18.04", "2.27"), ("20.04", "2.31"), ("22.04", "2.35"),
    ("23.04", "2.37"), ("23.10", "2.38"), ("24.04", "2.39"), ("24.10", "2.40"),
    ("25.04", "2.41"), ("25.10", "2.42"),
]
# gcc major -> plausible glibc floor, used only when no Ubuntu tag is embedded
_GCC_GLIBC = {"9": "2.31", "10": "2.31", "11": "2.35", "12": "2.35",
              "13": "2.37", "14": "2.39", "15": "2.41"}


def _glibc_hint_from_comment(cmt):
    if not cmt:
        return None
    for tag, ver in _UBUNTU_GLIBC:
        if tag in cmt:
            return ver
    m = re.search(r"gcc (\d+)\.", cmt)
    if m:
        return _GCC_GLIBC.get(m.group(1))
    return None


# ======================================================================
#  Packer / language detection
# ======================================================================
def detect_packer(data):
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:] or b"$Info: This file is packed with the UPX" in data:
        return "UPX (run `upx -d` first; fingerprints are meaningless while packed)"
    if b"PyInstaller" in data or b"pyi-" in data or b"_MEIPASS" in data:
        return "PyInstaller (extract with pyinstxtractor, then decompile the .pyc)"
    if b"Nuitka" in data or b"__nuitka" in data:
        return "Nuitka-compiled Python"
    if b"py2exe" in data:
        return "py2exe"
    return None


def detect_rust(data):
    m = re.search(rb"/rustc/([0-9a-f]{8,40})/", data)
    m2 = re.search(rb"rustc-(\d+\.\d+\.\d+)", data) or re.search(rb"rustc version (\d+\.\d+\.\d+)", data)
    if m or m2 or b"__rust_alloc" in data or b"RUST_BACKTRACE" in data:
        ver = m2.group(1).decode() if m2 else "unknown"
        commit = (" (rustc %s)" % m.group(1).decode()[:12]) if m else ""
        return {"lang": "rust", "version": ver, "note": "Rust program" + commit}
    return None


def detect_go(data):
    # require the buildinfo blob, not merely a "go1.x" substring
    has_buildinf = (b"\xff Go buildinf:" in data) or (b"\xfa Go buildinf:" in data)
    if not has_buildinf and b"runtime.buildVersion" not in data and b"Go build ID:" not in data:
        return None
    m = re.search(rb"go1\.\d{1,2}(?:\.\d{1,3})?", data)
    ver = m.group(0).decode() if m else "unknown"
    return {"lang": "go", "version": ver}


# ---------- Windows PE ----------
def _decode_rich(data, pe_off):
    try:
        head = data[:pe_off]
        ri = head.rfind(b"Rich")
        if ri < 0:
            return None
        key = struct.unpack("<I", head[ri + 4:ri + 8])[0]
        di = head.rfind(struct.pack("<I", 0x536E6144 ^ key), 0, ri)   # "DanS" ^ key
        if di < 0:
            return None
        comps = []
        off = di + 16
        while off + 8 <= ri:
            v = struct.unpack("<I", head[off:off + 4])[0] ^ key
            c = struct.unpack("<I", head[off + 4:off + 8])[0] ^ key
            prodid, build = v >> 16, v & 0xFFFF
            if prodid or build:
                comps.append((prodid, build, c))
            off += 8
        return comps
    except Exception:
        return None


def detect_pe(data):
    r = {"os": "windows", "arch": None, "linker": None, "rich": None, "notes": []}
    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            r["notes"].append("MZ but PE header looks off"); return r
        machine = struct.unpack("<H", data[e_lfanew + 4:e_lfanew + 6])[0]
        r["arch"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
        opt = e_lfanew + 24
        r["linker"] = "%d.%d" % (data[opt + 2], data[opt + 3])
        if b"_CorExeMain" in data or b"mscoree.dll" in data or b"#~\x00" in data:
            r["notes"].append(".NET / managed PE (decompile with ILSpy / dnSpy).")
        if b"__gnu_exception_handler" in data or b"libgcc" in data or b"mingw" in data.lower():
            r["notes"].append("MinGW-compiled (GCC on Windows).")
        comps = _decode_rich(data, e_lfanew)
        if comps:
            top = max(comps, key=lambda t: t[1])
            r["rich"] = comps
            r["notes"].append("Rich header: highest build=%d (bigger = newer MSVC; cross-ref the MSVC table)." % top[1])
        else:
            r["notes"].append("no Rich header (non-MSVC toolchain, or stripped).")
        r["notes"].append("Windows library funcs: IDA's bundled MSVC/UCRT FLIRT usually names them.")
    except Exception as e:
        r["notes"].append("PE parse error: %s" % e)
    return r
