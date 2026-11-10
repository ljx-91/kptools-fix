#!/usr/bin/env python3
"""Y73S 4.14.141 regression checks for kallsyms scan and hidden kernel_init."""
from bisect import bisect_right
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "kernel/base/symbol_lookup_scan.h"
START = ROOT / "kernel/base/start.c"
PATCH = ROOT / "kernel/patch/patch.c"
TOOLS_SYMBOL = ROOT / "tools/symbol.c"
PROFILE = ROOT / "scripts/verify_y73s_414_kallsyms_profile.py"

Y73S_ANCHOR = 0x0191E3E8
Y73S_TARGET = 0x01922680
Y73S_PREDECESSOR = 0x0192267C
Y73S_SUCCESSOR = 0x01922684
Y73S_OBSERVED_FIXED_STEPS = 4237
Y73S_SCAN_BUDGET = 8192

# Exact instructions extracted from the original Y73s boot.img kernel.Image.
REST_INIT = 0x018F1280
REST_INIT_SIZE = 0x44C
KERNEL_THREAD_CFI = 0x000DC0D8
KERNEL_INIT_CALL = 0x018F12A0
KERNEL_INIT_ADRP = 0xB0000260
KERNEL_INIT_ADD = 0x9126E000
KERNEL_INIT_BL = 0x979FAB8E
KERNEL_INIT_STUB = 0x0193E9B8
KERNEL_INIT_STUB_BRANCH = 0x17FECA67
KERNEL_INIT_BODY = 0x018F1354
KTHREADD_CALL = 0x018F130C
KTHREADD_ADRP = 0xB0000260
KTHREADD_ADD = 0x9127F000
KTHREADD_BL = 0x979FAB73
KTHREADD_STUB = 0x0193E9FC
KTHREADD_STUB_BRANCH = 0x179F914F
KTHREADD_BODY = 0x00122F38


def function_body(source, signature):
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


def need(pattern, source, message):
    if not re.search(pattern, source, re.S):
        raise AssertionError(message)


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def branch_target(pc, instruction):
    return pc + sign_extend(instruction & 0x03FFFFFF, 26) * 4


def adrp_page(pc, instruction):
    immlo = (instruction >> 29) & 0x3
    immhi = (instruction >> 5) & 0x7FFFF
    imm21 = sign_extend((immhi << 2) | immlo, 21)
    return (pc & ~0xFFF) + (imm21 << 12)


def adrp_add_target(adrp_pc, adrp_instruction, add_instruction):
    page = adrp_page(adrp_pc, adrp_instruction)
    imm12 = (add_instruction >> 10) & 0xFFF
    shift = (add_instruction >> 22) & 1
    return page + (imm12 << (12 if shift else 0))


def scan_model(symbols, anchor, target, extra, budget):
    addr = anchor
    kernel_end = symbols[-1] + 4
    for step in range(budget):
        if addr < anchor or addr >= kernel_end:
            return None
        index = bisect_right(symbols, addr) - 1
        if index < 0 or index + 1 >= len(symbols):
            return None
        start = symbols[index]
        end = symbols[index + 1]
        if start == target:
            return step
        if end <= addr or end <= start:
            return None
        addr = end + extra
    return None


def verify_scan():
    source = SCAN.read_text(encoding="utf-8")
    start = START.read_text(encoding="utf-8")
    scan_fn = function_body(source, "static inline unsigned long kp_resolve_symbol_by_lookup_anchor(")
    start_fn = function_body(start, "static int start_init(")

    need(r"#define KP_SYMBOL_SCAN_MAX_STEPS\s+8192", source,
         "Y73S scan budget must cover the measured 4-byte symbol run")
    need(r"addr\s*=\s*func_end\s*;", scan_fn,
         "symbol scan must query the exact next symbol boundary")
    if re.search(r"addr\s*=\s*func_end\s*\+\s*4", scan_fn):
        raise AssertionError("symbol scan must not skip 4-byte adjacent symbols")
    need(r"kernel_end\s*=\s*kernel_va\s*\+\s*image_size", scan_fn,
         "scan end must be computed once")
    need(r"kernel_end\s*<\s*kernel_va", scan_fn,
         "scan must reject kernel range overflow")
    need(r"anchor_offset\s*>=\s*image_size", scan_fn,
         "anchor offset must be inside the image")
    need(r"sprintf_offset\s*>=\s*image_size", scan_fn,
         "sprintf offset must be inside the image")
    need(r"size\s*>\s*kernel_end\s*-\s*func_start", scan_fn,
         "symbol size must be bounded before computing function end")
    need(r"i\s*<\s*KP_SYMBOL_SCAN_MAX_STEPS", scan_fn,
         "symbol scan must retain a finite step budget")

    if Y73S_TARGET - Y73S_ANCHOR != 0x4298:
        raise AssertionError("Y73S anchor/target fixture changed unexpectedly")
    if not (Y73S_PREDECESSOR < Y73S_TARGET < Y73S_SUCCESSOR):
        raise AssertionError("Y73S neighboring-symbol fixture is invalid")
    if Y73S_SCAN_BUDGET <= Y73S_OBSERVED_FIXED_STEPS:
        raise AssertionError("scan budget does not cover the original Y73S symbol path")

    # Synthetic dense-symbol regression: one 8-byte interval changes the
    # parity of the old +4 walk, causing the target to be skipped.
    slots = (Y73S_TARGET - Y73S_ANCHOR) // 4
    symbols = [Y73S_ANCHOR + 4 * i for i in range(slots + 1) if i != 1]
    symbols.extend([Y73S_TARGET + 4, Y73S_TARGET + 8])
    symbols = sorted(set(symbols))
    if scan_model(symbols, Y73S_ANCHOR, Y73S_TARGET, 4, Y73S_SCAN_BUDGET) is not None:
        raise AssertionError("legacy +4 scan model unexpectedly found the skipped target")
    fixed_steps = scan_model(symbols, Y73S_ANCHOR, Y73S_TARGET, 0, Y73S_SCAN_BUDGET)
    if fixed_steps is None or fixed_steps >= Y73S_SCAN_BUDGET:
        raise AssertionError("boundary scan model did not find the target within budget")

    # Exact preset offsets are extracted from the same kernel image. Prefer
    # that exact value; invoke the expensive formatter scan only as fallback.
    preset_pos = start_fn.find("start_preset.kallsyms_lookup_name_offset")
    scan_pos = start_fn.find("resolve_kallsyms_lookup_name_by_symbol_lookup_anchor()")
    if preset_pos < 0 or scan_pos < 0 or preset_pos > scan_pos:
        raise AssertionError("start_init must prefer the exact preset symbol offset")


def verify_hidden_kernel_init():
    tools_symbol = TOOLS_SYMBOL.read_text(encoding="utf-8")
    patch = PATCH.read_text(encoding="utf-8")
    profile = PROFILE.read_text(encoding="utf-8")
    resolver = function_body(tools_symbol, "static int32_t resolve_kernel_init_from_rest_init(")
    fillin = function_body(tools_symbol, "int fillin_patch_config(")
    before = function_body(patch, "static void before_kernel_init(")
    after = function_body(patch, "static void after_kernel_init(")

    need(r"get_symbol_offset_and_size\(kallsym,\s*img_buf,\s*\"rest_init\"",
         resolver, "resolver must use the target rest_init symbol range")
    need(r"kernel_thread\.cfi", resolver,
         "resolver must locate the kernel_thread CFI call target")
    need(r"aarch64_insn_is_bl", resolver,
         "resolver must identify BL calls to kernel_thread")
    need(r"aarch64_insn_is_adrp", resolver,
         "resolver must decode the ADRP that materializes the thread entry")
    need(r"aarch64_insn_is_add_imm", resolver,
         "resolver must decode the ADD immediate that completes the entry pointer")
    need(r"aarch64_insn_is_b\(stub_insn\)", resolver,
         "resolver must follow the function-pointer CFI branch stub")
    need(r"body_offset\s*<=\s*rest_init_offset\s*\|\|\s*body_offset\s*>=\s*rest_init_end",
         resolver, "resolver must accept only a unique body inside the rest_init symbol span")
    need(r"symbol->kernel_init\s*=\s*resolve_kernel_init_from_rest_init",
         fillin, "fillin_patch_config must populate the hidden kernel_init offset")
    need(r"extra_event_init\(EXTRA_EVENT_PRE_KERNEL_INIT\)", before,
         "PRE_KERNEL_INIT must remain attached to the actual kernel_init entry")
    need(r"extra_event_init\(EXTRA_EVENT_POST_KERNEL_INIT\)", after,
         "POST_KERNEL_INIT must remain attached to the actual kernel_init return path")
    if "extra_event_init(EXTRA_EVENT_PRE_KERNEL_INIT)" in function_body(patch, "static void before_rest_init("):
        raise AssertionError("do not fire PRE_KERNEL_INIT prematurely at rest_init entry")
    need(r"PRE/POST_KERNEL_INIT events unavailable", patch,
         "unresolved kernel_init must fail closed and report both events unavailable")
    need(r"\"kernel_thread.cfi\"", profile,
         "Y73S KALLSYMS fixture must require kernel_thread CFI call target")
    need(r"\"rest_init\",\s*\"cgroup_init\"", profile,
         "Y73S KALLSYMS fixture must require rest_init and cgroup_init")
    need(r"\"kernel_init\"", profile,
         "Y73S KALLSYMS fixture must record kernel_init as absent")

    # Verify the actual original-image callsite, not just a source-level guess.
    if branch_target(KERNEL_INIT_CALL, KERNEL_INIT_BL) != KERNEL_THREAD_CFI:
        raise AssertionError("Y73S first kernel_thread call target mismatch")
    if adrp_add_target(KERNEL_INIT_CALL - 16, KERNEL_INIT_ADRP, KERNEL_INIT_ADD) != KERNEL_INIT_STUB:
        raise AssertionError("Y73S kernel_init CFI function pointer decode mismatch")
    if branch_target(KERNEL_INIT_STUB, KERNEL_INIT_STUB_BRANCH) != KERNEL_INIT_BODY:
        raise AssertionError("Y73S kernel_init CFI stub branch target mismatch")
    if not (REST_INIT < KERNEL_INIT_BODY < REST_INIT + REST_INIT_SIZE):
        raise AssertionError("derived Y73S kernel_init body is outside rest_init symbol extent")

    if branch_target(KTHREADD_CALL, KTHREADD_BL) != KERNEL_THREAD_CFI:
        raise AssertionError("Y73S kthreadd kernel_thread call target mismatch")
    if adrp_add_target(KTHREADD_CALL - 16, KTHREADD_ADRP, KTHREADD_ADD) != KTHREADD_STUB:
        raise AssertionError("Y73S kthreadd CFI function pointer decode mismatch")
    if branch_target(KTHREADD_STUB, KTHREADD_STUB_BRANCH) != KTHREADD_BODY:
        raise AssertionError("Y73S kthreadd CFI stub branch target mismatch")
    if REST_INIT < KTHREADD_BODY < REST_INIT + REST_INIT_SIZE:
        raise AssertionError("kthreadd must not be misidentified as kernel_init")


def main():
    verify_scan()
    verify_hidden_kernel_init()
    print("[PASS] Y73S 4.14.141 symbol-boundary scan and exact preset priority")
    print("[PASS] hidden kernel_init recovered from rest_init ADRP/ADD + CFI branch")
    print("[PASS] kernel_init and kthreadd callsites are distinguished")
    print("[PASS] PRE/POST_KERNEL_INIT remain on the real kernel_init hooks")


if __name__ == "__main__":
    main()
