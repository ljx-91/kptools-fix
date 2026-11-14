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
    required = (
        r"mrs\s+x2,\s*CTR_EL0",
        r"ubfx\s+x2,\s*x2,\s*#16,\s*#4",
        r"dc\s+cvau,\s*x5",
        r"dsb\s+ish",
    )
    for pattern in required:
        if not re.search(pattern, helper):
            fail(f"dcache_clean_range missing instruction pattern: {pattern}")

    start_prepare = block_between(disassembly, "start_prepare", "map_prepare")
    map_prepare = block_between(disassembly, "map_prepare", "setup")
    setup_start = disassembly.find("<setup>:")
    setup_end = disassembly.find("Disassembly of section", setup_start + 1)
    if setup_start < 0:
        fail("missing setup function disassembly")
    setup = disassembly[setup_start:setup_end if setup_end >= 0 else None]

    if not re.search(r"bl\s+.*<dcache_clean_range>", start_prepare):
        fail("relocated start image/extra copy is not D-cache-cleaned")

    map_calls = len(re.findall(r"bl\s+.*<dcache_clean_range>", map_prepare))
    if map_calls != 3:
        fail(f"expected 3 map_prepare cache-clean calls (PAC, branch, map), got {map_calls}")

    setup_calls = len(re.findall(r"bl\s+.*<dcache_clean_range>", setup))
    if setup_calls != 1:
        fail(f"expected 1 setup cache-clean call for restored Image header, got {setup_calls}")

    icache_match = re.search(r"ic\s+iallu", setup)
    last_clean = setup.rfind("<dcache_clean_range>")
    if not icache_match or last_clean < 0 or icache_match.start() < last_clean:
        fail("I-cache invalidation is not ordered after the final D-cache clean")

    print("PASS: CTR_EL0-sized DC CVAU range cleaner is present")
    print("PASS: relocated code, PAC instruction, paging_init branch, map code, and Image header are cleaned")
    print("PASS: D-cache clean precedes I-cache invalidation and final handoff")


if __name__ == "__main__":
    main()
