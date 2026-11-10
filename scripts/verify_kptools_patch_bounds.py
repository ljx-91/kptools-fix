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


def verify_token_table_cursor_semantics():
    # Model the 49-NUL prefix used by the token-table backward scan.
    image = bytearray(b"X" * 64)
    image[4:53] = bytes(49)
    marker = 53
    pos = marker
    count = 0
    while pos > 0 and count < 49:
        pos -= 1
        if not image[pos]:
            count += 1
    if count != 49:
        raise AssertionError("synthetic token-table prefix was not fully scanned")
    while_offset = pos + 1

    # The legacy for-loop decremented once after examining its final NUL.
    old_pos = marker
    old_count = 0
    while old_pos > 0 and old_count < 49:
        if not image[old_pos]:
            old_count += 1
        old_pos -= 1
    legacy_offset = old_pos + 2
    aligned_offset = (while_offset + 3) & ~3
    if while_offset != legacy_offset or while_offset != 5 or aligned_offset != 8:
        raise AssertionError(
            f"token-table cursor semantics diverged: while={while_offset}, "
            f"legacy={legacy_offset}, aligned={aligned_offset}, expected=5/8"
        )


def main():
    verify_token_table_cursor_semantics()
    src = (ROOT / "tools/patch.c").read_text(encoding="utf-8")
    kallsym_src = (ROOT / "tools/kallsym.c").read_text(encoding="utf-8")
    symbol_src = (ROOT / "tools/symbol.c").read_text(encoding="utf-8")
    kallsym_header = (ROOT / "tools/kallsym.h").read_text(encoding="utf-8")
    offsets = body(kallsym_src, "static int find_approx_offsets(")
    need(r"elem_size\s*!=\s*4", offsets,
         "relative kallsyms scan must accept only supported entry widths")
    need(r"cand\s*<\s*0\s*\|\|\s*cand\s*>\s*imglen\s*-\s*elem_size", offsets,
         "relative kallsyms backward scan must validate its starting range")
    need(r"while\s*\(cand\s*>=\s*0", offsets,
         "relative kallsyms backward scans must stop before image underflow")
    need(r"cand\s*<=\s*imglen\s*-\s*elem_size", offsets,
         "relative kallsyms forward scan must read only complete entries")
    need(r"info->arch\s*==\s*ARM64\s*\?\s*\(uint32_t\)raw_offset", offsets,
         "ARM64 relative kallsyms values must retain their unsigned 32-bit encoding")
    if "for (;; cand -= elem_size)" in offsets:
        raise AssertionError("unbounded kallsyms_offsets backward scan reintroduced")

    addresses = body(kallsym_src, "static int find_approx_addresses(")
    need(r"imglen\s*<\s*KSYM_MIN_NEQ_SYMS\s*\*\s*info->asm_PTR_size", addresses,
         "absolute kallsyms scan must validate the minimum image size")
    need(r"cand\s*<=\s*imglen\s*-\s*elem_size", addresses,
         "absolute kallsyms tail scan must read only complete entries")

    token_table = body(kallsym_src, "static int find_token_table(")
    need(r"!info\s*\|\|\s*!img\s*\|\|\s*imglen\s*<=", token_table,
         "token-table parser must reject null and undersized images")
    need(r"imgend\s*-\s*num_end\s*<\s*2", token_table,
         "numeric token probe must leave two bytes inside the image")
    need(r"imgend\s*-\s*letter\s*<", token_table,
         "alphabetic token probe must fit completely inside the image")
    need(r"memcmp\(letter,\s*letters_syms", token_table,
         "alphabetic token validation must not use an unchecked memmem span")
    need(r"offset\s*=\s*\(int32_t\)\(pos\s*\+\s*1\s*-\s*img\)",
         token_table, "token-table start must account for the backward scan cursor still pointing at its final NUL")
    need(r"preceding_terminators\s*!=\s*'0'\s*\+\s*1", token_table,
         "token-table backward scan must reject a missing prefix")
    need(r"offset\s*=\s*align_ceil\(offset,\s*4\)", token_table,
         "token-table start must preserve the required four-byte alignment")
    need(r"offset\s*<\s*0\s*\|\|\s*offset\s*>=\s*imglen", token_table,
         "aligned token-table start must remain inside the image")
    need(r"memchr\(token_pos,\s*'\\0',\s*imgend\s*-\s*token_pos\)", token_table,
         "all 256 token strings must terminate inside the image")

    need(r"char\s*\*\s*kallsyms_token_table_image", kallsym_header,
         "token strings must retain the image that owns their pointers")
    need(r"info->kallsyms_token_table_image\s*=\s*img", token_table,
         "token-table parser must record its pointer backing image")
    token_bounds = body(kallsym_src, "static int get_token_string(")
    need(r"info->kallsyms_token_table_image", token_bounds,
         "token pointer bounds must use the original backing image")
    need(r"token_addr\s*-\s*image_base\s*>=\s*\(uintptr_t\)info->image_size",
         token_bounds, "token pointer range must be bounded against its backing image")
    decoder = body(kallsym_src, "static int decompress_symbol_name(")
    need(r"get_token_string\(info,\s*tokidx", decoder,
         "symbol decompressor must use backing-image token validation")
    name_probe = body(kallsym_src, "static int is_symbol_name_pos(")
    need(r"get_token_string\(info,\s*tokidx", name_probe,
         "symbol-name probe must use backing-image token validation")

    token_index = body(kallsym_src, "static int find_token_index(")
    need(r"token_offset\s*>\s*UINT16_MAX", token_index,
         "token-index generation must reject token offsets wider than 16 bits")
    need(r"memchr\(img\s*\+\s*offset,\s*'\\0',\s*imglen\s*-\s*offset\)", token_index,
         "token-index generation must bound each string terminator")
    need(r"offset\s*<\s*start\s*\|\|\s*offset\s*>=\s*imglen", token_index,
         "token-index generation must validate each cursor before dereferencing")

    dispatcher = body(kallsym_src, "static int32_t find_approx_addresses_or_offset(")
    need(r"!info\s*\|\|\s*!img\s*\|\|\s*imglen\s*<=\s*0", dispatcher,
         "Kallsyms scan dispatcher must reject invalid image inputs")

    need(r"ret\s*=\s*find_approx_offsets\(info,\s*img,\s*imglen\);\s*if\s*\(!ret\)\s*return\s+0;.*?ret\s*=\s*find_approx_addresses\(info,\s*img,\s*imglen\)",
         dispatcher, "unsupported relative-offset layouts must fall back to the absolute-address scan")
    map_area = body(symbol_src, "void select_map_area(")
    need(r"!kallsym\s*\|\|\s*!image_buf\s*\|\|\s*imglen\s*<=\s*0\s*\|\|\s*!map_start\s*\|\|\s*!max_size",
         map_area, "map-area selection must reject invalid image and output pointers")
    need(r"addr\s*<=\s*0\s*\|\|\s*addr\s*>=\s*imglen\s*\|\|\s*\(addr\s*&\s*3\)",
         map_area, "map-area anchor must be positive, in range, and instruction aligned")
    need(r"hole_size\s*<=\s*0\s*\|\|\s*\(int64_t\)hole_size\s*\*\s*2\s*>\s*imglen",
         map_area, "map-hole size must not overflow the image or doubled sync range")
    need(r"aligned_start\s*\+\s*hole_size\s*>\s*imglen",
         map_area, "non-GKI map hole must remain inside the kernel image")
    need(r"\(int64_t\)addr\s*\+\s*\(int64_t\)hole_size\s*\*\s*2\s*>\s*imglen",
         map_area, "GKI PAC scan must bound both instruction windows before reading")
    need(r"if\s*\(!second_pos\)\s*\{\s*tools_loge_exit",
         map_area, "unpaired PAC must fail closed if no matching second-window instruction exists")
    num_syms = body(kallsym_src, "static int find_num_syms(")
    need(r"approx_end\s*<\s*0\s*\|\|\s*approx_end\s*>\s*imglen\s*-\s*num_syms_elem_size",
         num_syms, "symbol-count scan must validate its image range")
    need(r"cand\s*>=\s*lower\s*&&\s*cand\s*<=\s*imglen\s*-\s*num_syms_elem_size",
         num_syms, "symbol-count scan must read only complete in-image entries")
    need(r"nsyms\s*<=\s*0\s*\|\|\s*nsyms\s*>\s*KSYM_MAX_SYMS",
         num_syms, "symbol-count scan must reject invalid and excessive counts")

    rela = body(kallsym_src, "static int try_find_arm64_relo_table(")
    need(r"!info\s*\|\|\s*!img\s*\|\|\s*imglen\s*<\s*24", rela,
         "ARM64 RELA scanner must reject truncated image inputs")
    need(r"cand_start\s*<\s*0\s*\|\|\s*cand_end\s*<\s*cand_start",
         rela, "ARM64 RELA candidate range must be validated before backward scanning")
    need(r"while\s*\(cand_end\s*>=\s*cand_start\)", rela,
         "ARM64 RELA trailing-zero scan must stay inside the candidate range")
    need(r"if\s*\(ro\s*\|\|\s*ri\s*\|\|\s*ra\)", rela,
         "zero-addend RELA entries must not be mistaken for empty padding")
    need(r"memcpy\(img\s*\+\s*offset,\s*&relocated_value,\s*sizeof\(relocated_value\)\)", rela,
         "RELA target writes must avoid unaligned typed pointer stores")
    need(r"offset64\s*>=\s*\(uint64_t\)max_offset", rela,
         "ARM64 relocation target must be range-checked before narrowing")
    if rela.find("info->kernel_base = kernel_va") < rela.find("ARM64 relocation table is shorter"):
        raise AssertionError("kernel base must not be committed before RELA candidate validation")

    need(r"kernel_va\s*==\s*max_va", rela,
         "ARM64 RELA scanner must reject a candidate without a resolved kernel base")

    decoder = body(kallsym_src, "static int decompress_symbol_name(")
    need(r"info->image_size\s*<=\s*0", decoder,
         "symbol decompressor must require a validated image extent")
    need(r"info->kallsyms_markers_offset\s*>\s*info->image_size", decoder,
         "symbol decompressor must cap names at the markers boundary")
    need(r"pos\s*<\s*0\s*\|\|\s*pos\s*>=\s*limit", decoder,
         "symbol decompressor must validate the input cursor")
    need(r"len\s*>\s*limit\s*-\s*pos", decoder,
         "symbol decompressor must bound compressed name bytes")
    need(r"get_token_string\(info,\s*tokidx", decoder,
         "symbol decompressor must use the bounded token helper")
    need(r"memchr\(token,\s*'\\0',\s*remaining\)", token_bounds,
         "token helper must validate token string termination against its backing image")
    need(r"append_len\s*>\s*KSYM_SYMBOL_LEN\s*-\s*1\s*-\s*used", decoder,
         "symbol decompressor must bound expanded output")
    index_offset = body(kallsym_src, "int32_t get_symbol_index_offset(")
    need(r"index\s*<\s*0.*?index\s*>=\s*info->kallsyms_num_syms", index_offset,
         "symbol address lookup must validate symbol indexes")
    need(r"info->image_size\s*-\s*elem_size", index_offset,
         "symbol address lookup must validate image coverage")
    analyze = body(kallsym_src, "int analyze_kallsym_info(")
    need(r"if\s*\(!rc\)\s*memcpy\(img,\s*copied_img", analyze,
         "failed Kallsyms analysis must not publish a partially relocated image")
    need(r"info->image_size\s*=\s*imglen", analyze,
         "Kallsyms analysis must retain the validated image size")
    need(r"if\s*\(!copied_img\)", analyze,
         "Kallsyms analysis must reject allocation failure")
    for call in ("get_symbol_offset_and_size(", "get_symbol_offset(", "dump_all_symbols(", "on_each_symbol("):
        fn = body(kallsym_src, "int " + call)
        if "decompress_symbol_name(info, img, &pos" not in fn or "return -1;" not in fn:
            raise AssertionError(f"{call} must propagate bounded decoder failures")

    banner = body(kallsym_src, "int find_linux_banner(")
    need(r"!info\s*\|\|\s*!img\s*\|\|\s*imglen\s*<=\s*0", banner,
         "linux_banner parser must reject invalid image inputs")
    need(r"remaining\s*>\s*prefix_len\s*\+\s*1", banner,
         "linux_banner parser must bound version-prefix lookahead")
    need(r"info->banner_num\s*<\s*\(int32_t\)ARRAY_SIZE", banner,
         "linux_banner parser must cap stored banner offsets")
    need(r"if\s*\(!info->banner_num\)\s*\{[^}]*return\s+0;", banner,
         "missing linux_banner must leave the vector fallback path available")
    need(r"if\s*\(!info->banner_num\)", banner,
         "linux_banner parser must detect absence without aborting vector fallback")
    need(r"memchr\(uts_release_start,\s*' ',", banner,
         "linux release parser must find a bounded in-image delimiter")
    need(r"release_len\s*>=\s*sizeof\(release\)", banner,
         "linux release parser must bound its temporary version buffer")

    markers = body(kallsym_src, "static int find_markers_internal(")
    need(r"elem_size\s*!=\s*4.*?elem_size\s*!=\s*8", markers,
         "marker scanner must accept only supported entry widths")
    need(r"token_table_offset\s*>\s*imglen\s*-\s*elem_size", markers,
         "marker scanner must validate its initial read")
    need(r"marker_end64\s*>\s*imglen", markers,
         "marker table end arithmetic must remain inside the image")

    names_candidate = body(kallsym_src, "static int verify_names_candidate(")
    need(r"len\s*>\s*info->kallsyms_markers_offset\s*-\s*pos", names_candidate,
         "compressed names candidate must use subtraction-based bounds checks")
    need(r"info->kallsyms_markers_offset\s*\+\s*marker_offset", names_candidate,
         "names candidate must validate marker-table reads against image extent")
    names_search = body(kallsym_src, "static int find_names(")
    need(r"int64_t\s+guess_end", names_search,
         "names search window arithmetic must use a wide intermediate")
    need(r"marker_bytes\s*<=\s*0", names_search,
         "names search must validate marker-table extent")

    insn_window = body(kallsym_src, "static int arm64_verify_pid_vnr_window(")
    need(r"int64_t\s+insn_offset", insn_window,
         "ARM64 instruction-window scan must use wide offset arithmetic")
    need(r"insn_offset\s*>\s*\(int64_t\)imglen\s*-\s*4", insn_window,
         "ARM64 instruction-window scan must bound every 4-byte read")
    arm64_stub = body(kallsym_src, "static int arm64_verify_pid_vnr(kallsym_t *info, char *img, int32_t imglen,\n                                int32_t offset, int wide)\n{")
    need(r"int64_t\s+target", arm64_stub,
         "CFI branch target arithmetic must not overflow 32-bit offsets")
    need(r"target\s*\+\s*4\s*<=\s*imglen", arm64_stub,
         "CFI branch target must fit inside the image")

    strict_count = body(kallsym_src, "static int find_num_syms(")
    need(r"#ifndef KP_STRICT_KALLSYMS\s+#define KP_STRICT_KALLSYMS 1",
         kallsym_src, "Y73S kptools must default to strict kallsyms validation")
    need(r"#if KP_STRICT_KALLSYMS[\s\S]*?return -1;[\s\S]*?#else[\s\S]*?approx_num_syms - NSYMS_MAX_GAP",
         strict_count, "unverified symbol count must fail closed instead of using an approximate count")

    vectors = body(kallsym_src, "static int correct_addresses_or_offsets_by_vectors(")
    need(r"info->arch\s*!=\s*ARM64", vectors,
         "ARM64 vector heuristic must reject non-ARM64 architectures")
    need(r"int64_t\s+search_end", vectors,
         "vector search end arithmetic must use 64-bit intermediates")
    need(r"candidate\s*\+\s*3LL\s*\*\s*elem_size\s*>\s*table_end", vectors,
         "strict alias check must fit all three entries inside the table")
    need(r"uint64_t\s+first[\s\S]*?candidate\s*\+\s*elem_size[\s\S]*?candidate\s*\+\s*2LL\s*\*\s*elem_size",
         vectors, "strict ARM64 kallsyms validation must check the first three alias entries")
    need(r"vector_raw\s*<\s*base", vectors,
         "vector address subtraction must reject underflow")
    need(r"vector_next_delta\s*<\s*vector_delta", vectors,
         "vector span calculation must reject descending addresses")
    need(r"pid_delta\s*>\s*INT32_MAX", vectors,
         "pid_vnr address must fit the validated image-offset type")

    generic = body(kallsym_src, "static int correct_addresses_or_offsets(")
    need(r"correct_addresses_or_offsets_by_banner.*?else\s*\{.*?correct_addresses_or_offsets_by_vectors",
         generic, "missing linux_banner must fall back to strict ARM64 vector validation")
    need(r"end\s*>\s*imglen\s*\|\|\s*end\s*<\s*start", generic,
         "resolved kallsyms table coverage must be validated before subtraction")

    need(r"static int arm64_verify_pid_vnr\(kallsym_t \*info,\s*char \*img,\s*int32_t imglen,\s*int32_t offset,\s*int wide\);",
         kallsym_src, "ARM64 verifier must be forward-declared before banner fallback")
    banner_match = body(kallsym_src, "static int correct_addresses_or_offsets_by_banner(")
    need(r"table_end\s*>\s*imglen", banner_match,
         "banner-based address matching must validate candidate table bounds")
    need(r"max_base_pos\s*=\s*\(int64_t\)table_end\s*-\s*index_bytes\s*-\s*elem_size",
         banner_match, "banner matching must bound indexed address reads")
    need(r"target\s*>=\s*base\s*&&\s*target\s*-\s*base\s*<=\s*INT32_MAX",
         banner_match, "banner address difference must be validated before narrowing")

    ikconfig = body(kallsym_src, "int find_ikconfig_blob(")
    need(r"!img\s*\|\|\s*imglen\s*<=\s*0\s*\|\|\s*!start\s*\|\|\s*!size",
         ikconfig, "IKCONFIG parser must validate input and output pointers")
    need(r"imglen\s*-\s*kcfg_start", ikconfig,
         "IKCONFIG end-marker search must stay inside the image")

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
