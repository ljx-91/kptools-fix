#!/usr/bin/env python3
"""Verify early KPIMG D-cache maintenance before executing modified kernel code."""
import re
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def block_between(disassembly: str, start: str, end: str) -> str:
    start_marker = f"<{start}>:"
    end_marker = f"<{end}>:"
    if start_marker not in disassembly or end_marker not in disassembly:
        fail(f"missing disassembly symbols: {start} / {end}")
    begin = disassembly.index(start_marker)
    finish = disassembly.index(end_marker, begin + len(start_marker))
    return disassembly[begin:finish]


def require_patterns(block: str, patterns: tuple[str, ...], label: str) -> None:
    for pattern in patterns:
        if not re.search(pattern, block, re.IGNORECASE):
            fail(f"{label} missing instruction pattern: {pattern}")


def call_positions(block: str, symbol: str) -> list[int]:
    return [m.start() for m in re.finditer(
        rf"bl\s+[^\n]*<{re.escape(symbol)}>", block
    )]


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: verify_y73s_early_cache_maintenance.py <kpimg.elf>")
    elf = Path(sys.argv[1])
    if not elf.is_file():
        fail(f"ELF not found: {elf}")

    result = subprocess.run(
        ["aarch64-none-elf-objdump", "-d", str(elf)],
        check=True, capture_output=True, text=True,
    )
    disassembly = result.stdout

    helper = block_between(disassembly, "dcache_clean_range", "start_prepare")
    require_patterns(helper, (
        r"cbz\s+x1",
        r"mrs\s+x2,\s*ctr_el0",
        r"ubfx\s+x2,\s*x2,\s*#16,\s*#4",
        r"mov\s+x3,\s*#4",
        r"lsl\s+x3,\s*x3,\s*x2",
        r"sub\s+x4,\s*x3,\s*#1",
        r"bic\s+x5,\s*x0,\s*x4",
        r"add\s+x0,\s*x0,\s*x1",
        r"add\s+x0,\s*x0,\s*x4",
        r"bic\s+x0,\s*x0,\s*x4",
        r"dc\s+cvau,\s*x5",
        r"add\s+x5,\s*x5,\s*x3",
        r"cmp\s+x5,\s*x0",
        r"b\.lo\s+",
        r"dsb\s+ish",
    ), "dcache_clean_range")

    start_prepare = block_between(disassembly, "start_prepare", "map_prepare")
    map_prepare = block_between(disassembly, "map_prepare", "setup")
    setup_start = disassembly.find("<setup>:")
    setup_end = disassembly.find("Disassembly of section", setup_start + 1)
    if setup_start < 0:
        fail("missing setup function disassembly")
    setup = disassembly[setup_start:setup_end if setup_end >= 0 else None]

    start_copy = start_prepare.find("<rmemcpy32>")
    start_clean = call_positions(start_prepare, "dcache_clean_range")
    if start_copy < 0 or len(start_clean) != 1 or start_clean[0] <= start_copy:
        fail("relocated start image/extra copy is not followed by exactly one D-cache clean")

    map_clean = call_positions(map_prepare, "dcache_clean_range")
    if len(map_clean) != 3:
        fail(f"expected 3 map_prepare cache-clean calls (PAC, branch, map), got {len(map_clean)}")
    pac_store = map_prepare.find("stur\\tw3, [x11, #-4]")
    branch_store = map_prepare.find("str\\tw15, [x13]")
    map_copy = map_prepare.rfind("<memcpy8>")
    if pac_store < 0 or not (pac_store < map_clean[0] < branch_store):
        fail("PAC/AUT instruction patch is not cleaned before the paging_init branch patch")
    if branch_store < 0 or not (map_clean[0] < branch_store < map_clean[1]):
        fail("paging_init branch patch is not followed by its D-cache clean")
    if not (map_clean[1] < map_copy < map_clean[2]):
        fail("relocated .setup.map copy is not followed by its D-cache clean")

    header_copy = setup.find("<memcpy8>")
    setup_clean = call_positions(setup, "dcache_clean_range")
    icache = setup.find("ic\\s+iallu")
    if header_copy < 0 or len(setup_clean) != 1 or setup_clean[0] <= header_copy:
        fail("restored Image header is not followed by exactly one D-cache clean")
    if icache < 0 or icache <= setup_clean[0]:
        fail("I-cache invalidation is not ordered after the final D-cache clean")
    if not re.search(r"dsb\\s+ish[\\s\\S]*ic\\s+iallu[\\s\\S]*dsb\\s+ish[\\s\\S]*isb", setup, re.IGNORECASE):
        fail("final DSB / I-cache invalidate / DSB / ISB handoff sequence is incomplete")

    print("PASS: CTR_EL0-sized, cache-line-aligned DC CVAU range cleaner is present")
    print("PASS: relocated start image, PAC/AUT, paging_init branch, .setup.map, and Image header are cleaned after writes")
    print("PASS: final D-cache clean, I-cache invalidation, DSB, and ISB are correctly ordered")


if __name__ == "__main__":
    main()
