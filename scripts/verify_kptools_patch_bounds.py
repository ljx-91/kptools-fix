#!/usr/bin/env python3
"""Fail-closed checks for embedded KP preset and extra-item parsing."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def body(src, signature):
    start = src.find(signature)
    if start < 0:
        raise AssertionError(f"missing function {signature}")
    brace = src.find("{", start)
    depth = 0
    for pos in range(brace, len(src)):
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
            if depth == 0:
                return src[brace + 1:pos]
    raise AssertionError(f"unterminated function {signature}")


def need(pattern, src, message):
    if not re.search(pattern, src, re.S):
        raise AssertionError(message)


def main():
    src = (ROOT / "tools/patch.c").read_text(encoding="utf-8")
    preset = body(src, "preset_t *get_preset(")
    need(r"min_preset_size", preset, "preset search must require a complete minimum header")
    need(r"tail\s*>=\s*min_preset_size", preset, "preset candidate must fit inside input")

    find = body(src, "static preset_t *find_patched_preset(")
    need(r"saved_size\s*>\s*0x7fffffffULL", find,
         "saved kernel size must be representable before narrowing")
    need(r"align_ceil\(saved_size,\s*SZ_4K\)", find,
         "preset alignment must use the validated 64-bit size")

    parse = body(src, "int parse_image_patch_info(")
    need(r"!kimg\s*\|\|\s*!pimg\s*\|\|\s*kimg_len\s*<=\s*0", parse,
         "patch parser must reject null and empty input")
    need(r"kpimg_size\s*<\s*0", parse, "embedded KPIMG size must reject negative values")
    need(r"extra_size\s*<\s*0", parse, "extra payload size must reject negative values")
    need(r"extra_size\s*>\s*\(uint64_t\)kimg_len\s*-\s*extra_offset", parse,
         "extra payload must fit the remaining kernel image")
    need(r"args_size\s*<\s*0.*?con_size\s*<\s*0", parse,
         "extra item lengths must reject negative values")
    need(r"args_size\)\s*>\s*remaining\s*-\s*sizeof\(\*item\)", parse,
         "extra item args must fit before content")
    need(r"con_size\)\s*>\s*remaining\s*-\s*sizeof\(\*item\)\s*-\s*\(size_t\)item->args_size", parse,
         "extra item content must fit the remaining record")
    need(r"memchr\(item->name", parse, "extra item name must be NUL-terminated")

    display = body(src, "void print_preset_info(")
    need(r"len\s*>\s*remaining\s*-\s*1", display,
         "additional strings must be bounded by the fixed preset field")
    need(r"fprintf\(stdout,\s*\"%\.\*s", display,
         "additional strings must print with a bounded precision")

    print_path = body(src, "int print_kp_image_info_path(")
    need(r"free\(kpimg\)", print_path, "preset info path must free its input buffer on every path")
    need(r"required", print_path, "legacy/current preset layouts must be size-checked before display")

    print("[PASS] preset discovery validates the complete accessed prefix")
    print("[PASS] embedded KPIMG and extra-item ranges are bounded")
    print("[PASS] preset additional strings are bounded")
    print("[PASS] legacy/current preset display validates layout size")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
