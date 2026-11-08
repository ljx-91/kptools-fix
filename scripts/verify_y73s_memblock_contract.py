#!/usr/bin/env python3
"""Read-only source contract checks for the Y73S Linux 4.14 memblock path.

These checks guard source/API assumptions; they do not certify the vendor kernel
binary, runtime behavior, or a successful device boot.
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


def main():
    map_c = source("kernel/base/map.c")
    symbol_c = source("tools/symbol.c")

    # Exact vendor-kernel ABI declarations used through function pointers.
    require(r"typedef int \(\*memblock_reserve_f\)\(phys_addr_t base, phys_addr_t size\);",
            map_c, "memblock_reserve must be modeled as int(base,size)")
    require(r"typedef int \(\*memblock_free_f\)\(phys_addr_t base, phys_addr_t size\);",
            map_c, "memblock_free must be modeled as int(base,size)")
    require(r"typedef int \(\*memblock_mark_nomap_f\)\(phys_addr_t base, phys_addr_t size\);",
            map_c, "memblock_mark_nomap must be modeled as int(base,size)")
    require(r"typedef phys_addr_t \(\*memblock_find_in_range_f\)\(phys_addr_t start, phys_addr_t end, phys_addr_t size,\s*phys_addr_t align\);",
            map_c, "memblock_find_in_range must retain its four-argument physical-address ABI")
    require(r"typedef void \*\(\*memblock_virt_alloc_try_nid_f\)\(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,\s*phys_addr_t max_addr, int nid\);",
            map_c, "memblock virtual allocator must retain its five-argument pointer ABI")

    alloc = function_body(map_c, "static uint64_t map_phys_alloc(")
    require(r"memblock_find_in_range_f[^;]*\)\(\s*0,\s*0,\s*size,\s*align\)",
            alloc, "physical allocation must call range finder with (0,0,size,align)")
    require(r"memblock_reserve_f[^;]*\)\(pa,\s*size\)", alloc,
            "range finder result must be reserved before use")
    require(r"return pa;", alloc, "physical allocator must return the reserved PA")

    probe = function_body(map_c, "static void __noinline detect_y73s_linear_voffset(")
    require(r"memblock_find_in_range_f[^;]*\)\(\s*0,\s*0,\s*page_size,\s*page_size\)",
            probe, "linear probe must select a page-aligned physical page")
    require(r"memblock_virt_alloc_try_nid_f[^;]*\)\(\s*page_size,\s*page_size,\s*detect_phys,\s*detect_phys \+ page_size,\s*NUMA_NO_NODE\)",
            probe, "linear probe must request the exact PA interval")
    require(r"still_free[\s\S]*?if \(still_free\) __builtin_trap\(\);",
            probe, "linear probe must reject allocator fallback to a different PA")
    require(r"data->linear_voffset\s*=\s*detect_virt\s*-\s*detect_phys;",
            probe, "linear offset must be derived from verified PA/VA pair")
    require(r"memblock_free_f[^;]*\)\(detect_phys,\s*page_size\)\)",
            probe, "linear probe reservation must be released and checked")

    paging = function_body(map_c, "void __noinline _paging_init(")
    paging_call = paging.find("((paging_init_f)(paging_init_va))();")
    probe_call = paging.find("detect_y73s_linear_voffset(data);")
    if paging_call < 0 or probe_call <= paging_call:
        raise AssertionError("Y73S linear-map probe must run only after paging_init returns")

    fill = function_body(symbol_c, "int fillin_map_symbol(")
    for sym in ("memblock_reserve", "memblock_free", "memblock_mark_nomap"):
        if f'"{sym}"' not in fill:
            raise AssertionError(f"preset symbol resolver missing required {sym}")
    if fill.find('"memblock_find_in_range"') < 0 or fill.find('"memblock_phys_alloc_try_nid"') < 0:
        raise AssertionError("preset resolver must prefer find_in_range and retain explicit fallback")
    if fill.find('"memblock_virt_alloc_try_nid_nopanic"') < 0 or fill.find('"memblock_virt_alloc_try_nid"') < 0:
        raise AssertionError("preset resolver must prefer nopanic virtual allocator and retain fallback")

    print("[PASS] Y73S memblock API, allocation, linear-probe, and preset source contracts")
    print("[NOTE] Source contract checks do not prove runtime boot compatibility")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(2)
