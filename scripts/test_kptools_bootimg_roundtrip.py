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

def boot_id_digest(path):
    """Recompute the Android boot header ID over the serialized components."""
    data = Path(path).read_bytes()
    ksz = struct.unpack_from("<I", data, 8)[0]
    rsz = struct.unpack_from("<I", data, 16)[0]
    ssz = struct.unpack_from("<I", data, 24)[0]
    page = struct.unpack_from("<I", data, 36)[0]
    raw_version = struct.unpack_from("<I", data, 40)[0]
    recovery_dtbo_size = struct.unpack_from("<I", data, 1632)[0]
    dtb_size = struct.unpack_from("<I", data, 1648)[0]
    version = raw_version
    extracted_size = 0
    if version > 10:
        version = 0
        extracted_size = raw_version

    def align(n):
        return (n + page - 1) // page * page

    kernel_off = page
    ramdisk_off = align(kernel_off + ksz)
    fmt_size = struct.unpack_from("<I", data, 12)[0] if version >= 3 else rsz
    id_field = data[576:608]
    words = struct.unpack("<8I", id_field)
    use_sha256 = not any(words[:6]) or bool(words[6] or words[7])
    algorithm = "sha256" if use_sha256 else "sha1"
    h = hashlib.sha256() if use_sha256 else hashlib.sha1()

    def add_component(offset, size):
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise AssertionError("boot ID component exceeds image bounds")
        h.update(data[offset:offset + size])
        h.update(struct.pack("<I", size))

    add_component(kernel_off, ksz)
    add_component(ramdisk_off, fmt_size)
    checksum_aligned = align(fmt_size)
    cursor = ramdisk_off + checksum_aligned
    add_component(cursor, ssz)
    cursor += align(ssz)
    if extracted_size:
        add_component(cursor, page)
        h.update(struct.pack("<I", extracted_size))
        cursor += align(extracted_size)
    if version in (1, 2):
        add_component(cursor, recovery_dtbo_size)
        cursor += align(recovery_dtbo_size)
    if version == 2:
        add_component(cursor, dtb_size)
    digest = h.digest()
    return digest, id_field[:len(digest)], algorithm


def set_boot_id(path, algorithm):
    data = bytearray(Path(path).read_bytes())
    data[576:608] = (b"\x00" * 32) if algorithm == "sha256" else (b"\x01" + b"\x00" * 31)
    Path(path).write_bytes(data)
    digest, _, detected = boot_id_digest(path)
    if detected != algorithm:
        raise AssertionError(f"failed to select {algorithm} boot ID mode")
    data = bytearray(Path(path).read_bytes())
    data[576:608] = digest.ljust(32, b"\x00")
    Path(path).write_bytes(data)


def make_boot(path, id_algorithm="sha256"):
    raw = bytearray(4096)
    struct.pack_into("<I", raw, 0, 0x14000008)
    struct.pack_into("<Q", raw, 8, 0x80000)
    struct.pack_into("<Q", raw, 16, len(raw))
    struct.pack_into("<I", raw, 56, 0x644D5241)
    fdt = make_fdt()
    kernel_blob = gzip.compress(bytes(raw), compresslevel=9, mtime=0) + fdt

    # Android DT table header/entry area followed by the same FDT in the v2 tail.
    dtb_table = bytearray(64)
    struct.pack_into(">8I", dtb_table, 0, 0xD7B7AB1E, 64 + len(fdt),
                     64, 32, 1, 64, PAGE, 0)
    dtb_table.extend(fdt)

    hdr = bytearray(HEADER_SIZE)
    hdr[:8] = b"ANDROID!"
    struct.pack_into("<10I", hdr, 8, len(kernel_blob), 0x80080000, 0, 0, 0, 0,
                     0x80000100, PAGE, 2, 0)
    hdr[48:64] = b"Y73S-WIN-TEST\0".ljust(16, b"\0")
    struct.pack_into("<I", hdr, 1632, 0)
    struct.pack_into("<Q", hdr, 1636, 0)
    struct.pack_into("<I", hdr, 1644, HEADER_SIZE)
    struct.pack_into("<I", hdr, 1648, len(dtb_table))
    struct.pack_into("<Q", hdr, 1652, 0x83000000)

    with open(path, "wb") as f:
        f.write(hdr)
        f.write(bytes(PAGE - len(hdr)))
        f.write(kernel_blob)
        f.write(bytes((-len(kernel_blob)) % PAGE))
        f.write(dtb_table)
        f.write(bytes([0xA5]) * 64)  # nonzero opaque tail after the DTB table
        f.write(bytes(64))  # reserved footer-sized area used by the repacker
        used = PAGE + ((len(kernel_blob) + PAGE - 1) // PAGE * PAGE) + len(dtb_table) + 128
        f.write(bytes((-used) % PAGE))
    set_boot_id(path, id_algorithm)


def run(exe, args, cwd):
    p = subprocess.run([str(exe), *args], cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {args}\n{p.stdout}")
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
    recovery_dtbo_size = struct.unpack_from("<I", data, 1632)[0]
    dtb_size = struct.unpack_from("<I", data, 1648)[0]
    if version != 2 or page != PAGE:
        raise AssertionError(f"unexpected header: v{version}, page={page}")

    def align(n):
        return (n + page - 1) // page * page

    kernel_off = page
    ramdisk_off = align(kernel_off + ksz)
    second_off = align(ramdisk_off + rsz)
    dtb_off = second_off + align(ssz) + align(recovery_dtbo_size)
    if dtb_off + dtb_size > len(data):
        raise AssertionError("boot component bounds exceed image")

    blob = data[kernel_off:kernel_off + ksz]
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    kernel = dec.decompress(blob) + dec.flush()
    return {
        "kernel": kernel,
        "dtb": dec.unused_data,
        "tail_dtb": data[dtb_off:dtb_off + dtb_size],
        "ramdisk": data[ramdisk_off:ramdisk_off + rsz],
        "second_size": ssz,
        "header_size": struct.unpack_from("<I", data, 1644)[0],
        "recovery_dtbo_offset": struct.unpack_from("<Q", data, 1636)[0],
        "dtb_addr": struct.unpack_from("<Q", data, 1652)[0],
    }


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
        if a.boot_image:
            cases = [("supplied", Path(a.boot_image).resolve())]
        else:
            cases = []
            for algorithm in ("sha1", "sha256"):
                source = root / f"source-boot-{algorithm}.img"
                make_boot(source, algorithm)
                cases.append((algorithm, source))

        for label, source in cases:
            before = boot_components(source)
            first = root / f"first-{label}"
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
            for key in ("kernel", "dtb", "tail_dtb", "ramdisk", "second_size", "header_size", "recovery_dtbo_offset", "dtb_addr"):
                if before[key] != after[key]:
                    raise AssertionError(f"{key} changed across round-trip")
            digest, stored, algorithm = boot_id_digest(repacked)
            if digest != stored:
                raise AssertionError(f"repacked Android boot header ID mismatch ({algorithm})")
            second = root / f"second-{label}"
            second.mkdir()
            run(exe, ["unpack", str(repacked)], second)
            raw2 = (second / "kernel").read_bytes()
            if raw1 != raw2:
                raise AssertionError("unpack/repack/unpack kernel mismatch")
            print(f"[PASS] {label}: unpack/repack/unpack")
            print(f"[PASS] {label}: Android boot header ID ({algorithm})")
            print(f"[PASS] {label}: kernel SHA256 {hashlib.sha256(raw2).hexdigest()}")
            print(f"[PASS] {label}: appended kernel DTB bytes {len(after['dtb'])}")
            print(f"[PASS] {label}: boot-v2 tail DTB table bytes {len(after['tail_dtb'])}")
            print(f"[PASS] {label}: ramdisk bytes {len(after['ramdisk'])}")
            print(f"[PASS] {label}: second-stage bytes {after['second_size']}")
            if a.boot_image:
                print("[NOTE] AVB metadata/signature was not validated or regenerated.")

if __name__ == "__main__":
    main()
