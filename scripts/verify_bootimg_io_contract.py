#!/usr/bin/env python3
"""Fail-closed source checks for boot image input and decompression bounds."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def body(source, signature):
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:pos]
    raise AssertionError(f"unterminated function {signature}")


def need(pattern, source, message):
    if not re.search(pattern, source, re.S):
        raise AssertionError(message)


def main():
    src = (ROOT / "tools/bootimg.c").read_text(encoding="utf-8")
    repack = body(src, "int repack_bootimg_mem(")
    need(r"fread\(&hdr,\s*sizeof\(hdr\),\s*1,\s*f_orig\)\s*!=\s*1", repack,
         "repack must reject truncated boot headers")
    need(r"hdr\.kernel_size\s*>\s*\(uint64_t\)total_size\s*-\s*page_size", repack,
         "repack must bound original kernel data")
    need(r"fread\(old_k_full,\s*1,\s*hdr\.kernel_size,\s*f_orig\)\s*!=\s*hdr\.kernel_size", repack,
         "repack must reject short kernel reads")
    for method in ("compress_gzip", "compress_lz4", "compress_lz4_le"):
        if method not in repack:
            raise AssertionError(f"missing compression path {method}")
    need(r"compress_gzip\([\s\S]*?\)\s*!=\s*0", repack,
         "GZIP compression failure must abort repack")
    need(r"compress_lz4\([\s\S]*?\)\s*!=\s*0", repack,
         "LZ4 compression failure must abort repack")
    need(r"compress_lz4_le\([\s\S]*?\)\s*!=\s*0", repack,
         "legacy LZ4 compression failure must abort repack")
    need(r"rest_buf_tmp\s*=\s*calloc[\s\S]*?fread\(rest_buf_tmp[\s\S]*?\)\s*!=\s*rest_data_size\s*-\s*sizeof\(avb\)",
         repack, "repack must check tail allocation and read")

    patch = body(src, "int patch_bootimg(")
    need(r"fread\(&hdr,\s*sizeof\(hdr\),\s*1,\s*fp\)\s*!=\s*1", patch,
         "patch must reject truncated boot headers")
    need(r"hdr\.kernel_size\s*>\s*\(uint64_t\)boot_size\s*-\s*kernel_offset", patch,
         "patch must bound compressed kernel range")
    need(r"fread\(compressed,\s*1,\s*hdr\.kernel_size,\s*fp\)\s*!=\s*hdr\.kernel_size", patch,
         "patch must reject short compressed-kernel reads")

    raw = body(src, "int repack_bootimg(")
    need(r"raw_k_size\s*>\s*0xffffffffULL", raw,
         "repack must reject input kernels larger than its uint32 size contract")
    need(r"fread\(raw_k_buf,\s*1,\s*\(size_t\)raw_k_size,\s*f_new_k\)\s*!=\s*\(size_t\)raw_k_size", raw,
         "repack must check new-kernel read length")

    gzip = body(src, "static int decompress_gzip_to_mem(")
    need(r"in_size\s*>\s*0xffffffffULL", gzip,
         "gzip input must fit zlib's uInt contract")
    need(r"have\s*>\s*0xffffffffULL\s*-\s*out_off", gzip,
         "gzip output accumulation must be overflow checked")
    need(r"new_cap\s*=\s*0xffffffffULL", gzip,
         "gzip growth must be capped to the uint32 output contract")

    print("[PASS] boot image header and kernel file ranges are validated")
    print("[PASS] short reads and compression failures abort repack")
    print("[PASS] gzip input/output sizes are bounded")

    need(r"rest_data_offset64\s*=\s*\(uint64_t\)page_size\s*\+\s*old_k_aligned64", repack,
         "boot tail offset must be calculated in 64-bit arithmetic")
    need(r"new_k_total_aligned64\s*=\s*align_ceil", repack,
         "new kernel page alignment must use checked 64-bit arithmetic")
    need(r"new_image_extent\s*=\s*\(uint64_t\)page_size\s*\+\s*new_k_total_aligned64", repack,
         "new boot image extent must be calculated without signed overflow")
    need(r"tail_pos\s*>\s*rest_data_size", repack,
         "checksum tail offsets must be checked against available tail bytes")
    need(r"hdr\.second_size\s*>\s*\(uint64_t\)rest_data_size\s*-\s*tail_pos", repack,
         "second-stage checksum data must be bounded")
    need(r"old_image_size\s*>\s*~0ULL\s*-\s*shift", repack,
         "AVB footer movement must avoid signed overflow")
    need(r"if\s*\(has_avb\)\s*\{\s*if\s*\(fwrite\(&avb", repack,
         "a footer may only be written when an AVB footer was actually read")
    need(r"fwrite\(&hdr,\s*sizeof\(hdr\),\s*1,\s*f_out\)\s*!=\s*1", repack,
         "repack must check output header writes")
    need(r"fwrite\(final_k_buf,\s*1,\s*final_k_size,\s*f_out\)\s*!=\s*final_k_size", repack,
         "repack must check kernel output writes")
    print("[PASS] boot tail, AVB offset and output write bounds")
    print("[NOTE] Source checks do not replace malformed-image fuzzing or AVB verification")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
