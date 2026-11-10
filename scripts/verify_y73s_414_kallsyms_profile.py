#!/usr/bin/env python3
"""Validate the exact symbol availability profile recovered from Y73S 4.14.141."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "scripts/fixtures/y73s_4.14.141_kallsyms.txt"
REQUIRED = {
    "module_alloc", "module_memfree", "vmalloc_to_page",
    "SyS_truncate.cfi", "sys_truncate", "__cfi_slowpath",
    "kallsyms_lookup_name", "kallsyms_on_each_symbol",
    "__flush_dcache_area", "flush_icache_range", "stop_machine",
    "security_secctx_to_secid", "prepare_binprm", "prepare_binprm.cfi",
    "open_exec", "open_exec.cfi", "rest_init", "cgroup_init",
}
ABSENT = {
    "init_mm", "sys_call_table", "set_memory_x", "set_memory_nx",
    "find_check_fn", "report_cfi_failure", "__cfi_slowpath_diag",
    "selinux_blob_sizes", "kernel_init", "kernel_init_freeable",
}


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    symbols = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"0x[0-9a-fA-F]+\s+\w\s+(\S+)", line)
        if not match:
            raise SystemExit(f"malformed KALLSYMS record: {line}")
        symbols.add(match.group(1))

    missing = sorted(REQUIRED - symbols)
    unexpected = sorted(ABSENT & symbols)
    if missing or unexpected:
        if missing:
            print("[FAIL] missing required symbols: " + ", ".join(missing), file=sys.stderr)
        if unexpected:
            print("[FAIL] expected-absent symbols found: " + ", ".join(unexpected), file=sys.stderr)
        return 1

    print("[PASS] exact Y73S 4.14.141 KALLSYMS required-symbol profile")
    print("[PASS] executable module allocator/free and vmalloc page translation exist")
    print("[PASS] legacy SyS_truncate CFI body and CFI slowpath exist")
    print("[PASS] hidden data symbols and newer set_memory/CFI hooks are absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
