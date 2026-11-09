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
    kallsym_src = (ROOT / "tools/kallsym.c").read_text(encoding="utf-8")
    offsets = body(kallsym_src, "static int find_approx_offsets(")
    need(r"elem_size\s*!=\s*4.*?elem_size\s*!=\s*8", offsets,
         "relative kallsyms scan must accept only supported entry widths")
    need(r"cand\s*<\s*0\s*\|\|\s*cand\s*>\s*imglen\s*-\s*elem_size", offsets,
         "relative kallsyms backward scan must validate its starting range")
    need(r"while\s*\(cand\s*>=\s*0", offsets,
         "relative kallsyms backward scans must stop before image underflow")
    need(r"cand\s*<=\s*imglen\s*-\s*elem_size", offsets,
         "relative kallsyms forward scan must read only complete entries")
    if "for (;; cand -= elem_size)" in offsets:
        raise AssertionError("unbounded kallsyms_offsets backward scan reintroduced")

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
    need(r"\(uint64_t\)extra_size\s*>\s*\(uint64_t\)kimg_len\s*-\s*extra_offset", parse,
         "extra payload must fit the remaining kernel image")
    need(r"args_size\s*<\s*0.*?con_size\s*<\s*0", parse,
         "extra item lengths must reject negative values")
    need(r"\(size_t\)item->args_size\s*>\s*remaining\s*-\s*sizeof\(\*item\)", parse,
         "extra item args must fit before content")
    need(r"\(size_t\)item->con_size\s*>\s*remaining\s*-\s*sizeof\(\*item\)\s*-\s*\(size_t\)item->args_size", parse,
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

    append = body(src, "static int extra_append(")
    need(r"\*offset\s*>\s*capacity", append,
         "extra append must validate the current output offset")
    need(r"len\s*>\s*capacity\s*-\s*\*offset", append,
         "extra append must bound each write")
    update = body(src, "int patch_update_img_buf(")
    need(r"extra_config_num\s*<\s*0.*?extra_config_num\s*>\s*EXTRA_ITEM_MAX_NUM", update,
         "patching must bound the number of extra items")
    need(r"out_all_len64\s*>\s*0x7fffffffULL", update,
         "patch output size arithmetic must be checked before narrowing")
    need(r"current_offset\s*!=\s*\(size_t\)out_all_len", update,
         "extra serialization must exactly fill its computed output extent")
    need(r"strnlen\(config->set_args,\s*args_len\)", update,
         "argument serialization must stay within the recorded args buffer")

    common = (ROOT / "tools/common.c").read_text(encoding="utf-8")
    read_file = body(common, "void read_file_align(")
    need(r"file_size\s*<\s*0.*?file_size\s*>\s*0x7fffffffL", read_file,
         "host file reader must reject invalid and oversized input")
    need(r"aligned\s*>\s*0x7fffffffULL", read_file,
         "host file alignment must reject integer overflow")
    branch = body(common, "int can_b_imm(")
    need(r"from\s*&\s*3.*?to\s*&\s*3", branch,
         "ARM64 branch helper must reject unaligned endpoints")
    need(r"0x07fffffcULL", branch, "ARM64 positive branch range must exclude +128 MiB")
    need(r"0x08000000ULL", branch, "ARM64 negative branch range must include -128 MiB")

    image = (ROOT / "tools/image.c").read_text(encoding="utf-8")
    get_image = body(image, "int32_t get_kernel_info(")
    need(r"imglen\s*<\s*\(int32_t\)sizeof\(arm64_hdr_t\)", get_image,
         "ARM64 Image parser must validate its fixed header length")

    hex_patch = body(src, "int hex_patch(")
    need(r"patternlen\s*>\s*32.*?replacelen\s*>\s*32", hex_patch,
         "hex patcher must bound both stack buffers")
    need(r"patternlen\s*!=\s*replacelen", hex_patch,
         "hex patcher must not overwrite beyond the matched pattern")
    need(r"static int hex_nibble\(", src, "hex patcher must reject invalid hex digits")

    parse = body(src, "int parse_image_patch_info(")
    need(r"memchr\(item_pos\s*\+\s*sizeof\(\*item\)", parse,
         "embedded argument strings must be NUL-terminated within args_size")
    print("[PASS] patch output arithmetic, extra serialization and host file bounds")
    print("[PASS] ARM64 branch range and hex patch input validation")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
