#!/usr/bin/env python3
"""Source contract for byte-exact, bounded map-anchor restoration."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / "kernel/base/start.c").read_text(encoding="utf-8")
start = src.index("void restore_map()")
end = src.index("\n#define log_reg", start)
body = src[start:end]

checks = {
    "backup length is positive": "start_preset.map_backup_len <= 0",
    "backup length fits fixed field": "start_preset.map_backup_len > MAP_MAX_SIZE",
    "map offset is nonnegative": "start_preset.map_offset < 0",
    "map offset and length fit kernel image": "start_preset.map_offset > start_preset.kernel_size - start_preset.map_backup_len",
    "kernel VA addition is checked": "(~(uint64_t)0) - kernel_va",
    "page size is validated": "page_size <= 0 || (page_size & (page_size - 1))",
    "restore uses byte stores": "*(uint8_t *)j = start_preset.map_backup[j - start]",
}
missing = [label for label, token in checks.items() if token not in body]
if missing:
    print("[FAIL] " + "; ".join(missing), file=sys.stderr)
    sys.exit(2)
if "*(uint64_t *)j" in body:
    raise SystemExit("[FAIL] wide tail store remains in restore_map")
if "map_restored = 1;" not in body:
    raise SystemExit("[FAIL] restore idempotence guard missing")
print("[PASS] map backup restoration is bounded and byte-exact")
