#!/usr/bin/env python3
"""Fail-closed source regression checks for the Y73S early mapping path.

This complements, but does not replace, target-kernel disassembly/ABI review.
It intentionally checks the runtime source's ordering and failure guards.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text, signature):
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function signature: {signature}")
    brace = text.find("{", start)
    if brace < 0:
        raise AssertionError(f"missing function body: {signature}")
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos]
    raise AssertionError(f"unterminated function body: {signature}")


def require(pattern, text, message):
    if not re.search(pattern, text, re.S):
        raise AssertionError(message)


def before(text, first, second, message):
    a, b = text.find(first), text.find(second)
    if a < 0 or b < 0 or a >= b:
        raise AssertionError(message)


def main():
    map_c = source("kernel/base/map.c")
    symbol_c = source("tools/symbol.c")
    hotpatch_c = source("kernel/base/hotpatch.c")
    hook_c = source("kernel/base/hook.c")
    patch_c = source("kernel/patch/patch.c")

    # The known-bad memblock_alloc_try_nid fallback returns a kernel VA on
    # the supplied Y73S binary. It must never be selected as a PA allocator.
    resolver = function_body(symbol_c, "int fillin_map_symbol(")
    if '"memblock_alloc_try_nid"' in resolver:
        raise AssertionError("unsafe memblock_alloc_try_nid fallback reintroduced")
    if "MAP_SYM_MEMBLOCK_ALLOC_TRY_NID" in map_c or "MAP_SYM_MEMBLOCK_ALLOC_TRY_NID" in symbol_c:
        raise AssertionError("unsafe virtual-return allocator enum reintroduced")
    require(r'"memblock_find_in_range"', resolver,
            "resolver must support the binary-verified physical range finder")
    require(r'"memblock_phys_alloc_try_nid"', resolver,
            "resolver may use only the explicitly physical allocator as fallback")

    # A range finder does not reserve. The exact selected PA must be reserved
    # before it is exposed to page-table construction or image relocation.
    alloc = function_body(map_c, "static uint64_t map_phys_alloc(")
    require(r"memblock_find_in_range_f[^;]*\)\(\s*0,\s*0,\s*size,\s*align\)",
            alloc, "physical range finder arguments changed")
    find_call = alloc.find("0, 0, size, align")
    reserve_call = alloc.find("(pa, size)")
    if find_call < 0 or reserve_call <= find_call:
        raise AssertionError("range result must be reserved before it is returned")
    require(r"if\s*\(\(\(memblock_reserve_f\).*?\)\(pa,\s*size\)\)\s*return 0;",
            alloc, "reservation failure must reject the physical allocation")
    require(r"return pa;", alloc, "physical allocator must return the reserved PA")

    # The target's 5-argument nopanic virtual allocator is only a probe after
    # Linux 4.14 paging_init has established the linear map.
    probe = function_body(map_c, "static void __noinline detect_y73s_linear_voffset(")
    require(r"memblock_virt_alloc_try_nid_f[^;]*\)\(\s*page_size,\s*page_size,\s*detect_phys,\s*detect_phys \+ page_size,\s*NUMA_NO_NODE\)",
            probe, "linear-map probe ABI/arguments changed")
    require(r"if\s*\(still_free\)\s*__builtin_trap\(\);", probe,
            "probe must reject allocator fallback to another physical page")
    require(r"if\s*\(\(\(memblock_free_f\).*?\)\(detect_phys,\s*page_size\)\)\s*__builtin_trap\(\);",
            probe, "probe reservation release failure must be detected")

    paging = function_body(map_c, "void __noinline _paging_init(")
    before(paging, "((paging_init_f)(paging_init_va))();",
           "detect_y73s_linear_voffset(data);",
           "linear-map probe must run after the original paging_init returns")
    require(r"if\s*\(!start_pa\s*\|\|\s*\(start_pa\s*&\s*\(page_size\s*-\s*1\)\).*?__builtin_trap\(\);",
            paging, "main destination PA must be nonzero, aligned, and bounded")
    before(paging, "if (!start_pa", "memblock_mark_nomap_f",
           "destination PA must be validated before NOMAP")
    require(r"memblock_mark_nomap_f[^;]*\)\(start_pa,\s*all_size\)\)\s*__builtin_trap\(\);",
            paging, "NOMAP failure must stop before mapping/copying")

    pte = function_body(map_c, "static uint64_t __noinline get_or_create_pte(")
    require(r"pxd_pa\s*=\s*map_phys_alloc\(data,\s*page_size,\s*page_size\);\s*if\s*\(!pxd_pa\)\s*__builtin_trap\(\);",
            pte, "page-table allocation must be checked before descriptor creation")

    # Y73S KALLSYMS lacks cpu_online_mask/nr_cpu_ids. The callback must
    # therefore never call num_online_cpus() or inspect unresolved cpumask state.
    callback = function_body(hotpatch_c, "static int hotpatch_cb(void *arg)")
    for forbidden in ("num_online_cpus", "cpu_online_mask", "nr_cpu_ids", "atomic_inc"):
        if forbidden in callback:
            raise AssertionError(f"hotpatch callback must not depend on {forbidden}")
    hotpatch_fn = function_body(hotpatch_c, "int hotpatch(void *addrs[], uint32_t values[], int cnt)")
    require(r"stop_machine\(hotpatch_cb,\s*&patch,\s*NULL\)", hotpatch_fn,
            "Y73S hotpatch must coordinate CPUs with stop_machine(..., NULL)")
    require(r"!kfunc\(stop_machine\).*?is_interrupt_masked\(\).*?return -EOPNOTSUPP;",
            hotpatch_fn, "missing stop_machine/interrupt state must fail closed")
    require(r"is_interrupt_masked\\(\\)\\s*&&\\s*!hotpatch_early_boot", hotpatch_fn,
            "IRQ-masked patching may only use the explicit early-boot window")
    patch_fn = function_body(patch_c, "int patch()")
    require(r"hotpatch_set_early_boot\\(1\\)", patch_fn,
            "initial pre-rest_init hooks must enable the early-boot window")
    before(patch_fn, "hotpatch_set_early_boot(1)", "hook_wrap4",
           "early-boot mode must be active before rest_init hook installation")
    before(function_body(patch_c, "static void before_rest_init("),
           "android_user_init()", "hotpatch_set_early_boot(0)",
           "early-boot mode must remain active through pre-rest_init hook setup")
    if "hotpatch_cb(&patch)" in hotpatch_fn:
        raise AssertionError("uncoordinated direct hotpatch callback fallback reintroduced")

    install = function_body(hook_c, "int hook_install(hook_t *hook)")
    require(r"return hotpatch\(", install, "hook_install must propagate hotpatch status")
    hook_fn = function_body(hook_c, "hook_err_t hook(void *func, void *replace, void **backup)")
    require(r"int patch_rc = hook_install\(hook\)", hook_fn,
            "hook() must inspect hook_install result")
    require(r"patch_rc == -EUCLEAN", hook_fn,
            "uncertain rollback must retain trampoline storage")
    unhook_fn = function_body(hook_c, "void unhook(void *func)")
    require(r"if \(rc\).*?return;", unhook_fn,
            "unhook must retain trampoline memory when restore fails")

    print("[PASS] Y73S allocator dispatch excludes virtual-return fallback")
    print("[PASS] physical ranges are reserved before use")
    print("[PASS] linear-map probe ordering and reservation checks")
    print("[PASS] destination and intermediate page-table allocation guards")
    print("[PASS] hotpatch avoids unresolved CPU-mask symbols and fails closed")
    print("[PASS] early-boot stop_machine window is explicitly scoped")
    print("[PASS] hook install/uninstall propagate patch failures safely")
    print("[NOTE] Source checks do not independently prove binary ABI or device boot")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(2)
