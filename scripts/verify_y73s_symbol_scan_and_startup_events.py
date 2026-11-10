#!/usr/bin/env python3
"""Y73S 4.14.141 regression checks for runtime kallsyms scan and KPM init events."""
from bisect import bisect_right
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "kernel/base/symbol_lookup_scan.h"
START = ROOT / "kernel/base/start.c"
PATCH = ROOT / "kernel/patch/patch.c"
TOOLS_SYMBOL = ROOT / "tools/symbol.c"
PROFILE = ROOT / "scripts/verify_y73s_414_kallsyms_profile.py"

Y73S_ANCHOR = 0x0191E3E8       # show_stack in the original Y73s KALLSYMS dump
Y73S_TARGET = 0x01922680       # kallsyms_lookup_name
Y73S_PREDECESSOR = 0x0192267C  # module_kallsyms_lookup_name
Y73S_SUCCESSOR = 0x01922684    # cmdq_dev_alloc_reference_VA_by_name
Y73S_OBSERVED_FIXED_STEPS = 4237
Y73S_SCAN_BUDGET = 8192


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


def scan_model(symbols, anchor, target, extra, budget):
    """Model %pSb's symbol start/size result using the next distinct address."""
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

    # This count was independently reproduced from the full uploaded Y73s
    # KALLSYMS log. The former 4096-step limit was too small even after fixing
    # the +4 skip; the exact current log takes 4237 boundary queries.
    if Y73S_TARGET - Y73S_ANCHOR != 0x4298:
        raise AssertionError("Y73S anchor/target fixture changed unexpectedly")
    if not (Y73S_PREDECESSOR < Y73S_TARGET < Y73S_SUCCESSOR):
        raise AssertionError("Y73S neighboring-symbol fixture is invalid")
    if Y73S_SCAN_BUDGET <= Y73S_OBSERVED_FIXED_STEPS:
        raise AssertionError("scan budget does not cover the original Y73S symbol path")

    # Synthetic dense-symbol regression: one 8-byte interval changes the
    # parity of the old +4 walk, causing the target to be skipped. This models
    # the 4-byte-heavy vendor KALLSYMS region without checking in a multi-MB log.
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


def verify_init_events():
    patch = PATCH.read_text(encoding="utf-8")
    tools_symbol = TOOLS_SYMBOL.read_text(encoding="utf-8")
    profile = PROFILE.read_text(encoding="utf-8")
    before = function_body(patch, "static void before_rest_init(")
    after = function_body(patch, "static void after_kernel_init(")
    config = function_body(tools_symbol, "int fillin_patch_config(")

    need(r"early_init_failed", before,
         "rest_init fallback must distinguish failed early initialization")
    need(r"if\s*\(!early_init_failed\s*&&\s*patch_config->rest_init\s*&&\s*!patch_config->kernel_init\)",
         before, "PRE_KERNEL_INIT fallback must be restricted to successful Y73S rest_init path")
    need(r"extra_event_init\(EXTRA_EVENT_PRE_KERNEL_INIT\)", before,
         "Y73S rest_init path must emit the default PRE_KERNEL_INIT event")
    need(r"extra_event_init\(EXTRA_EVENT_POST_KERNEL_INIT\)", after,
         "POST_KERNEL_INIT must remain tied to the real kernel_init after-hook")
    need(r"POST_KERNEL_INIT unavailable", patch,
         "missing kernel_init must be reported as an unavailable post event")
    need(r"symbol->rest_init\s*=\s*try_get_symbol_offset_zero\(kallsym,\s*img_buf,\s*\"rest_init\"\)",
         config, "tool must resolve the Y73S rest_init symbol")
    need(r"if\s*\(!symbol->rest_init\)\s*symbol->cgroup_init", config,
         "cgroup_init must remain only the fallback when rest_init is absent")
    need(r"\"rest_init\",\s*\"cgroup_init\"", profile,
         "Y73S KALLSYMS fixture must require rest_init and cgroup_init")
    need(r"\"kernel_init\"", profile,
         "Y73S KALLSYMS fixture must record kernel_init as absent")


def main():
    verify_scan()
    verify_init_events()
    print("[PASS] Y73S 4.14.141 symbol-boundary scan and preset priority")
    print("[PASS] Y73S rest_init PRE_KERNEL_INIT fallback; no fabricated POST_KERNEL_INIT")
    print("[PASS] dense 4-byte symbol scan regression model")


if __name__ == "__main__":
    main()
