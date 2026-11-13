#!/usr/bin/env python3
"""Source contract for bounded Y73S paging_init entry inspection and B hook."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / "kernel/base/setup1.S").read_text(encoding="utf-8")

checks = {
    "kernel image size is loaded": "ldr x16, [x10, #setup_kernel_size_offset]",
    "entry offset is checked against image size": "cmp x15, x17",
    "PAC/AUT scan has an upper bound": "cmp x11, x17",
    "out-of-range PAC/AUT scan fails closed": "b.hi .bad_paging_init",
    "hook displacement alignment is checked": "tst x15, #3",
    "hook displacement is checked as signed 28-bit": "asr x16, x15, #27",
    "invalid hook aborts": "brk #0",
}
missing = [label for label, token in checks.items() if token not in src]
if missing:
    print("[FAIL] " + "; ".join(missing), file=sys.stderr)
    sys.exit(2)
# Ensure the scan's bound check occurs before its load, and the range checks
# occur before the immediate is extracted and written into the kernel.
scan = src.index(".cmp_auti:")
if src.index("cmp x11, x17", scan) > src.index("ldr w0, [x11], #4", scan):
    raise SystemExit("[FAIL] PAC/AUT load precedes its bound check")
if src.index("asr x16, x15, #27") > src.index("ubfx w15, w15, #2, #26"):
    raise SystemExit("[FAIL] branch immediate is extracted before range validation")
print("[PASS] Y73S paging_init entry scan and B-hook displacement are bounded")
