#!/usr/bin/env python3
"""Static contract for Y73s Hook arena initialization failure handling."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

start = read("kernel/base/start.c")
hmem = read("kernel/base/hmem.c")
hook_h = read("kernel/include/hook.h")
hook_c = read("kernel/base/hook.c")
fphook_c = read("kernel/base/fphook.c")

checks = {
    "hook_mem_add result is captured": bool(re.search(
        r"int\s+hook_mem_rc\s*=\s*hook_mem_add\s*\(\s*_kp_hook_start\s*,\s*HOOK_ALLOC_SIZE\s*\)\s*;",
        start)),
    "failure is reported": "Hook engine disabled: hook_mem_add failed (%d)\\n" in start,
    "no unchecked hook_mem_add call remains": not bool(re.search(
        r"(?<![=\w])hook_mem_add\s*\(\s*_kp_hook_start\s*,\s*HOOK_ALLOC_SIZE\s*\)\s*;",
        re.sub(r"int\s+hook_mem_rc\s*=\s*hook_mem_add", "int hook_mem_rc = hook_mem_add", start))),
    "allocator refuses use before initialization": bool(re.search(
        r"void\s*\*hook_mem_zalloc\s*\([^)]*\)\s*\{\s*[^}]*!hook_locks_ready",
        hmem, re.S)),
    "origin lookup refuses use before initialization": bool(re.search(
        r"void\s*\*hook_get_mem_from_origin\s*\([^)]*\)\s*\{\s*[^}]*!hook_locks_ready",
        hmem, re.S)),
    "legacy inline chain embeds transit array": bool(re.search(
        r"typedef\s+struct\s+_hook_chain\s*\{[^}]*uint32_t\s+transit\[TRANSIT_INST_NUM\]",
        hook_h, re.S)),
    "legacy function-pointer chain embeds transit array": bool(re.search(
        r"typedef\s+struct\s+_fphook_chain\s*\{[^}]*uint32_t\s+transit\[TRANSIT_INST_NUM\]",
        hook_h, re.S)),
    "inline backend still derives owner from embedded transit": "local_container_of(transit, hook_chain_t, transit)" in hook_c,
    "function-pointer backend still derives owner from embedded transit": "local_container_of(transit, fp_hook_chain_t, transit)" in fphook_c,
}

failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
if failed:
    sys.exit(1)
print(f"PASS: {len(checks)} Y73s Hook initialization/ABI contracts")
