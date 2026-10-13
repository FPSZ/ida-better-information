"""Header parsing and detection on synthetic and (when present) real binaries."""
import os
import struct

import pytest

from ibr.core.binfmt import _elf_layout
from ibr.core.detect import detect
from ibr.core.fingerprint import _load_fp


def elf64(machine=62):
    h = bytearray(0x40)
    h[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", h, 16, 2, machine)          # ET_EXEC, e_machine
    struct.pack_into("<HHH", h, 0x34, 64, 56, 0)        # e_ehsize, e_phentsize, e_phnum
    return bytes(h)


def test_consistent_header():
    assert _elf_layout(elf64()) == (True, "<", None)


def test_ei_class_alone_tampered():
    h = bytearray(elf64()); h[4] = 1
    is64, en, note = _elf_layout(bytes(h))
    assert (is64, en) == (True, "<")
    assert "claim 32-bit little-endian" in note and "64-bit little-endian x86_64" in note


def test_ei_data_tampered():
    h = bytearray(elf64()); h[5] = 2
    is64, en, note = _elf_layout(bytes(h))
    assert (is64, en) == (True, "<") and "set file byte 4 to 2 and byte 5 to 1" in note


def test_short_and_foreign_inputs():
    assert _elf_layout(b"\x7fELF\x02")[2] is None
    assert detect(data=b"hello")["notes"] == ["not an ELF/PE file"]


def test_fingerprint_db_loads():
    assert {"x86_64", "i386", "aarch64"} <= set(_load_fp())


SAMPLE = r"D:\CTF\tool\glibc-detect\devtools\samples\t_x86s"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample binaries not present")
def test_static_glibc_sample():
    r = detect(path=SAMPLE)
    assert r["kind"] == "static" and r["best"].startswith("glibc") and r["confidence"] in ("high", "medium")
