#!/usr/bin/env python3
"""Exercise Windows kptools against a generated Android boot v2 fixture.

This is a host-side format/I/O integration test. It is not a substitute for
running against the device's stock boot.img or validating AVB signatures.
"""
import gzip
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

PAGE = 2048
HEADER_SIZE = 1680


def make_fdt():
    # Minimal FDT header + structure block with FDT_BEGIN_NODE and FDT_END.
    fdt = bytearray(80)
    struct.pack_into(">10I", fdt, 0,
                     0xD00DFEED, 80, 56, 72, 40, 17, 16, 0, 0, 16)
    struct.pack_into(">I", fdt, 56, 1)
    fdt[60] = 0
    struct.pack_into(">I", fdt, 64, 2)
    struct.pack_into(">I", fdt, 68, 9)
    return bytes(fdt)


def make_boot(path):
    # ARM64 Image-like payload followed by a valid minimal FDT blob.
    raw = bytearray(4096)
    struct.pack_into("<I", raw, 0, 0x14000008)  # in-range B instruction
    struct.pack_into("<Q", raw, 8, 0x80000)     # text_offset
    struct.pack_into("<Q", raw, 16, len(raw))   # image_size
    struct.pack_into("<I", raw, 56, 0x644D5241) # ARM\x64 magic
    raw.extend(make_fdt())
    kernel = gzip.compress(bytes(raw), compresslevel=9, mtime=0)

    hdr = bytearray(HEADER_SIZE)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<10I", hdr, 8,
                     len(kernel), 0x80080000, 0, 0, 0, 0,
                     0x80000100, PAGE, 2, 0)
    hdr[48:64] = b"Y73S-WIN-TEST\0".ljust(16, b"\0")
    struct.pack_into("<I", hdr, 1632, 0)  # recovery_dtbo_size
    struct.pack_into("<Q", hdr, 1636, 0)  # recovery_dtbo_offset
    # Header v2 DTB fields are zero; fixture DTB is appended to kernel.
    struct.pack_into("<I", hdr, 1644, 0)
    struct.pack_into("<Q", hdr, 1648, 0)
    with open(path, "wb") as f:
        f.write(hdr)
        f.write(bytes(PAGE - len(hdr)))
        f.write(kernel)
        f.write(bytes((-len(kernel)) % PAGE))


def run(exe, args, cwd):
    p = subprocess.run([str(exe), *args], cwd=cwd,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {args}\n{p.stdout}")
    return p.stdout


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_kptools_bootimg_roundtrip.py <kptools.exe>")
    exe = Path(sys.argv[1]).resolve()
    if not exe.is_file():
        raise SystemExit(f"kptools executable not found: {exe}")

    with tempfile.TemporaryDirectory(prefix="kptools-y73s-win-") as td:
        root = Path(td)
        source = root / "fixture-boot.img"
        make_boot(source)

        first = root / "first"
        first.mkdir()
        log = run(exe, ["unpack", str(source)], first)
        extracted = first / "kernel"
        if not extracted.is_file() or extracted.stat().st_size < 4096:
            raise AssertionError("unpack did not produce the decompressed kernel")
        raw1 = extracted.read_bytes()
        if b"\xd0\x0d\xfe\xed" not in raw1:
            raise AssertionError("appended FDT was not present after unpack")

        log += run(exe, ["repack", str(source)], first)
        repacked = first / "new-boot.img"
        if not repacked.is_file() or repacked.stat().st_size <= PAGE:
            raise AssertionError("repack did not produce a valid-sized boot image")

        second = root / "second"
        second.mkdir()
        run(exe, ["unpack", str(repacked)], second)
        raw2 = (second / "kernel").read_bytes()
        if raw1 != raw2:
            raise AssertionError("decompressed kernel changed across Windows unpack/repack")
        print("[PASS] Windows kptools unpack/repack/unpack round-trip")
        print(f"[PASS] decompressed kernel SHA256: {hashlib.sha256(raw2).hexdigest()}")
        print(f"[PASS] fixture image size: {source.stat().st_size}; repacked: {repacked.stat().st_size}")


if __name__ == "__main__":
    main()
