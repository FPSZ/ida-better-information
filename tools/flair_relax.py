# -*- coding: utf-8 -*-
"""Make FLAIR patterns match code as it looks *after* static linking.

pelf builds patterns from the object files in libc.a and wildcards the bytes a
relocation fills in. Two things make those patterns miss in a linked executable:

1. TLS relaxation (relax_line). libc.a reaches its thread-local variables (errno,
   h_errno, tcache, the locale pointers, ...) through the initial-exec model, e.g.
   on x86-64

       mov rcx, [rip + __libc_errno@gottpoff]      48 8B 0D <rel32>

   and the static linker rewrites that into the local-exec form

       mov rcx, -0x40                              48 C7 C1 <imm32>

   pelf wildcards only the 4 relocated bytes, so the rewritten opcode bytes stay
   literal. Most syscall wrappers (read, mmap, ptrace, alarm...) are affected.

2. Incomplete immediates on AArch64 (relax_relocs). pelf wildcards only part of a
   relocated instruction: ADRP keeps its top byte (which holds immlo, bits 29-30)
   and LDR/STR/ADD keep the byte with the high bits of imm12, although the linker
   fills those bits in too:

       pattern  ......90   binary  600400F0   adrp x0, #0x48f000
       pattern  ....40F9   binary  002446F9   ldr  x0, [x0, #0xc48]

   Such a pattern only matches when those bits happen to be 0. Every instruction
   word pelf left partly wildcarded is therefore wildcarded completely; this also
   covers the TLS (adrp/ldr -> movz/movk) and GOT -> direct rewrites.

On stripped static glibc 2.39 test binaries (scored against the unstripped twin)
this raises correctly named functions from 804 to 858 on x86-64 and from 293 to
495 on AArch64; i386 patterns are unaffected.
"""
import io, re, struct

STT_TLS = 6

# bytes around a relocation offset R that relaxation may rewrite, per arch
#   x86-64: REX + opcode + ModRM before the rel32   -> [R-3, R)
#   i386  : opcode + ModRM before the disp32        -> [R-2, R)
#   AArch64: the whole instruction holding the reloc -> [R, R+4)
_SPAN = {"x86_64": (-3, 0), "i386": (-2, 0), "aarch64": (0, 4)}


def _ar_members(blob):
    if not blob.startswith(b"!<arch>\n"):
        return
    off = 8
    while off + 60 <= len(blob):
        size = int(blob[off + 48:off + 58].decode().strip() or 0)
        yield blob[off + 60:off + 60 + size]
        off += 60 + size + (size & 1)


def _elf_tls_names(obj, out):
    if obj[:4] != b"\x7fELF":
        return
    is64, en = obj[4] == 2, "<" if obj[5] == 1 else ">"
    try:
        if is64:
            shoff = struct.unpack_from(en + "Q", obj, 0x28)[0]
            shentsize, shnum = struct.unpack_from(en + "HH", obj, 0x3A)
        else:
            shoff = struct.unpack_from(en + "I", obj, 0x20)[0]
            shentsize, shnum = struct.unpack_from(en + "HH", obj, 0x2E)
        secs = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if is64:
                _, typ, _, _, off, size, link, _, _, entsz = struct.unpack_from(en + "IIQQQQIIQQ", obj, o)
            else:
                _, typ, _, _, off, size, link, _, _, entsz = struct.unpack_from(en + "IIIIIIIIII", obj, o)
            secs.append((typ, off, size, link, entsz))
        for typ, off, size, link, entsz in secs:
            if typ != 2 or not entsz:                     # SHT_SYMTAB
                continue
            stoff = secs[link][1]
            for j in range(off, off + size, entsz):
                if is64:
                    name, info = struct.unpack_from(en + "IB", obj, j)
                else:
                    name = struct.unpack_from(en + "I", obj, j)[0]
                    info = obj[j + 12]
                if info & 0xF == STT_TLS and name:
                    end = obj.index(b"\x00", stoff + name)
                    out.add(obj[stoff + name:end].decode("latin1"))
    except Exception:
        pass


def tls_names(libc_a_paths):
    """Union of STT_TLS symbol names (defined or referenced) in the given archives."""
    out = set()
    for p in libc_a_paths:
        try:
            blob = open(p, "rb").read()
        except OSError:
            continue
        for obj in _ar_members(blob):
            _elf_tls_names(obj, out)
    return out


_REF = re.compile(r"\^([0-9A-F]{4,8}) (\S+)")


def _parse(line):
    """-> (fields, head bytes, crclen, tail field index or None, tail bytes or None)"""
    f = line.split(" ")
    head = [f[0][i:i + 2] for i in range(0, len(f[0]), 2)]
    crclen, total = int(f[1], 16), int(f[3], 16)
    tail_i = len(f) - 1 if re.fullmatch(r"[0-9A-F.]+", f[-1]) and not f[-1].startswith((":", "^")) \
        and len(f[-1]) == 2 * max(0, total - 32 - crclen) and len(f) > 5 else None
    tail = [f[tail_i][i:i + 2] for i in range(0, len(f[tail_i]), 2)] if tail_i else None
    return f, head, crclen, tail_i, tail


def _wildcard(line, positions, crc_hit="drop"):
    """Wildcard the given module offsets. A position inside the CRC-covered range either
    drops the CRC (crc_hit="drop": its bytes are not in the .pat, so it cannot be
    recomputed) or is skipped (crc_hit="skip")."""
    f, head, crclen, tail_i, tail = _parse(line)
    changed = drop_crc = False
    for p in positions:
        if 0 <= p < len(head):
            changed |= head[p] != ".."
            head[p] = ".."
        elif 32 <= p < 32 + crclen:
            drop_crc |= crc_hit == "drop"
        elif tail is not None and 0 <= p - 32 - crclen < len(tail):
            changed |= tail[p - 32 - crclen] != ".."
            tail[p - 32 - crclen] = ".."
    if not (changed or drop_crc):
        return line, False
    f[0] = "".join(head)
    if drop_crc:
        f[1], f[2] = "00", "0000"
        if tail_i:
            f.pop(tail_i)          # the tail was positioned after the old CRC range
    elif tail_i:
        f[tail_i] = "".join(tail)
    return " ".join(f), True


def _is_pattern(line):
    return bool(line) and not line.startswith("---") and len(line.split(" ")) >= 5


def relax_line(line, tls, arch):
    """TLS IE->LE relaxation. Return (new_line, changed) for one .pat line."""
    if not _is_pattern(line):
        return line, False
    span = _SPAN.get(arch)
    hits = [int(m.group(1), 16) for m in _REF.finditer(line) if m.group(2) in tls]
    if not span or not hits:
        return line, False
    return _wildcard(line, [p for r in hits for p in range(r + span[0], r + span[1])])


# x86-64 instructions whose RIP-relative GOT operand the linker may relax (R_X86_64_
# [REX_]GOTPCRELX): mov -> lea / mov $imm, call|jmp * -> addr32 call|jmp+nop, and
# test/ALU reg,[GOT] -> op $imm,reg. Keyed by opcode; ModRM must be RIP-relative.
_X64_GOTX = {0x8B, 0xFF, 0x85, 0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B}


def relax_relocs(line, arch):
    """Relocated instructions whose encoding pelf only partly wildcards.
      AArch64: any instruction word pelf left partly wildcarded carries a relocation
               (see the module docstring), so the whole 32-bit word is wildcarded.
      x86-64 : a 4-byte wildcard after a RIP-relative ModRM with a GOTPCRELX-
               relaxable opcode gets its opcode (+ REX) bytes wildcarded too
               (mov -> lea / mov $imm, call|jmp * -> direct). No glibc 2.39 test
               function depended on it; it guards other archives."""
    if not _is_pattern(line) or arch not in ("aarch64", "x86_64"):
        return line, False
    f, head, crclen, tail_i, tail = _parse(line)
    segs = [(0, head)] + ([(32 + crclen, tail)] if tail else [])
    pos = set()
    if arch == "aarch64":
        for base, seq in segs:
            for i, b in enumerate(seq):
                if b == "..":
                    w = (base + i) & ~3
                    pos.update(range(w, w + 4))
        return _wildcard(line, pos, crc_hit="skip")
    for base, seq in segs:
        for i in range(2, len(seq) - 3):
            if seq[i:i + 4] != [".."] * 4 or ".." in (seq[i - 2], seq[i - 1]):
                continue
            op, modrm = int(seq[i - 2], 16), int(seq[i - 1], 16)
            if op in _X64_GOTX and modrm & 0xC7 == 0x05:
                pos.update((base + i - 2, base + i - 1))
                if i >= 3 and seq[i - 3] != ".." and 0x40 <= int(seq[i - 3], 16) <= 0x4F:
                    pos.add(base + i - 3)
    return _wildcard(line, pos, crc_hit="skip")


def relax_pat(src, dst, tls, arch):
    n = changed = 0
    with open(src, "r", errors="ignore") as fi, open(dst, "w", newline="\n") as fo:
        for line in fi:
            new, c = relax_line(line.rstrip("\n"), tls, arch)
            fo.write(new + "\n")
            n += 1
            changed += c
    return n, changed
