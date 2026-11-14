#!/usr/bin/env python3
"""Windows kptools Android boot v2 round-trip test.

Usage:
  python test_kptools_bootimg_roundtrip.py <kptools.exe>
  python test_kptools_bootimg_roundtrip.py <kptools.exe> --boot-image boot.img

Supplied-image mode checks decompressed kernel, appended DTB, and ramdisk.
This is offline I/O validation only, not AVB validation or a flash test.
"""
import argparse, gzip, hashlib, shutil, struct, subprocess, tempfile, zlib
from pathlib import Path

PAGE = 2048
HEADER_SIZE = 1660

def make_fdt():
    fdt = bytearray(80)
    struct.pack_into(">10I", fdt, 0, 0xD00DFEED, 80, 56, 72, 40, 17, 16, 0, 0, 16)
    struct.pack_into(">I", fdt, 56, 1)
    fdt[60] = 0
    struct.pack_into(">I", fdt, 64, 2)
    struct.pack_into(">I", fdt, 68, 9)
    return bytes(fdt)

def make_boot(path):
    raw = bytearray(4096)
    struct.pack_into("<I", raw, 0, 0x14000008)
    struct.pack_into("<Q", raw, 8, 0x80000)
    struct.pack_into("<Q", raw, 16, len(raw))
    struct.pack_into("<I", raw, 56, 0x644D5241)
    kernel_blob = gzip.compress(bytes(raw), compresslevel=9, mtime=0) + make_fdt()
    hdr = bytearray(HEADER_SIZE)
    hdr[:8] = b"ANDROID!"
    struct.pack_into("<10I", hdr, 8, len(kernel_blob), 0x80080000, 0, 0, 0, 0,
                     0x80000100, PAGE, 2, 0)
    hdr[48:64] = b"Y73S-WIN-TEST\\0".ljust(16, b"\\0")
    struct.pack_into("<I", hdr, 1632, 0)
    struct.pack_into("<Q", hdr, 1636, 0)
    struct.pack_into("<I", hdr, 1644, HEADER_SIZE)
    struct.pack_into("<I", hdr, 1648, 80)
    struct.pack_into("<Q", hdr, 1652, 0x83000000)
    with open(path, "wb") as f:
        f.write(hdr)
        f.write(bytes(PAGE-len(hdr)))
        f.write(kernel_blob)
        f.write(bytes((-len(kernel_blob)) % PAGE))

def run(exe, args, cwd):
    p = subprocess.run([str(exe), *args], cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {args}\\n{p.stdout}")
    return p.stdout

def boot_components(path):
    data = Path(path).read_bytes()
    if data[:8] != b"ANDROID!":
        raise AssertionError(f"{path}: missing ANDROID! magic")
    ksz = struct.unpack_from("<I", data, 8)[0]
    rsz = struct.unpack_from("<I", data, 16)[0]
    ssz = struct.unpack_from("<I", data, 24)[0]
    page = struct.unpack_from("<I", data, 36)[0]
    version = struct.unpack_from("<I", data, 40)[0]
    if version != 2 or page != PAGE:
        raise AssertionError(f"unexpected header: v{version}, page={page}")
    align = lambda n: (n + page - 1) // page * page
    ko = page
    ro = align(ko + ksz)
    so = align(ro + rsz)
    if so + ssz > len(data):
        raise AssertionError("boot component bounds exceed image")
    blob = data[ko:ko+ksz]
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    kernel = dec.decompress(blob) + dec.flush()
    return {"kernel": kernel, "dtb": dec.unused_data,
            "ramdisk": data[ro:ro+rsz], "second_size": ssz}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kptools")
    ap.add_argument("--boot-image")
    a = ap.parse_args()
    exe = Path(a.kptools).resolve()
    if not exe.is_file():
        raise SystemExit(f"kptools executable not found: {exe}")
    with tempfile.TemporaryDirectory(prefix="kptools-y73s-win-") as td:
        root = Path(td)
        source = root / "source-boot.img"
        if a.boot_image:
            shutil.copy2(Path(a.boot_image).resolve(), source)
        else:
            make_boot(source)
        before = boot_components(source)
        first = root / "first"
        first.mkdir()
        run(exe, ["unpack", str(source)], first)
        raw1 = (first / "kernel").read_bytes()
        if raw1 != before["kernel"]:
            raise AssertionError("first unpack differs from source kernel")
        run(exe, ["repack", str(source)], first)
        repacked = first / "new-boot.img"
        if not repacked.is_file():
            raise AssertionError("repack did not produce new-boot.img")
        after = boot_components(repacked)
        for key in ("kernel", "dtb", "ramdisk", "second_size"):
            if before[key] != after[key]:
                raise AssertionError(f"{key} changed across round-trip")
        second = root / "second"
        second.mkdir()
        run(exe, ["unpack", str(repacked)], second)
        raw2 = (second / "kernel").read_bytes()
        if raw1 != raw2:
            raise AssertionError("unpack/repack/unpack kernel mismatch")
        print("[PASS] Windows kptools unpack/repack/unpack")
        print(f"[PASS] kernel SHA256: {hashlib.sha256(raw2).hexdigest()}")
        print(f"[PASS] appended DTB bytes: {len(after['dtb'])}")
        print(f"[PASS] ramdisk bytes: {len(after['ramdisk'])}")
        print(f"[PASS] second-stage bytes: {after['second_size']}")
        if a.boot_image:
            print("[NOTE] AVB metadata/signature was not validated or regenerated.")

if __name__ == "__main__":
    main()
