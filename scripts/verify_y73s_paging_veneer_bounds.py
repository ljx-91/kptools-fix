#!/usr/bin/env python3
"""Source contract for bounds-safe AArch64 B-veneer resolution."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
common = (ROOT / "tools/common.c").read_text(encoding="utf-8")
header = (ROOT / "tools/common.h").read_text(encoding="utf-8")
patch = (ROOT / "tools/patch.c").read_text(encoding="utf-8")

start = common.index("int32_t relo_branch_func(")
end = common.index("\nvoid read_file_align", start)
body = common[start:end]
checks = {
    "image pointer checked": "!img",
    "image length checked": "imglen < 4",
    "entry lower and upper bounds checked": "func_offset < 0 || func_offset > imglen - 4",
    "entry alignment checked": "(func_offset & 3)",
    "unaligned loads avoided": "memcpy(&inst, img + func_offset, sizeof(inst))",
    "signed B displacement decoded": "sign64_extend(imm26 << 2u, 28u)",
    "negative target rejected": "target < 0",
    "upper target bound checked": "target > (int64_t)imglen - 4",
    "target alignment checked": "(target & 3)",
}
missing = [name for name, token in checks.items() if token not in body]
if missing:
    print("[FAIL] " + "; ".join(missing), file=sys.stderr)
    sys.exit(2)
if "int32_t relo_branch_func(const char *img, int32_t imglen, int32_t func_offset);" not in header:
    raise SystemExit("[FAIL] updated prototype missing")
if "relo_branch_func(kallsym_kimg, ori_kimg_len, paging_init_offset)" not in patch:
    raise SystemExit("[FAIL] paging_init call does not pass image bounds")
if "if (setup->paging_init_offset < 0)" not in patch:
    raise SystemExit("[FAIL] invalid veneer target is not rejected")
if "\\\\n" in body or "\\\\n" in patch:
    raise SystemExit("[FAIL] diagnostics contain a double-escaped newline")
print("[PASS] paging_init B-veneer resolution is image-bounded")
