#!/usr/bin/env python3
"""Source contract for byte-exact, bounded map-anchor restoration."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / "kernel/base/start.c").read_text(encoding="utf-8")
start = src.index("static void restore_map_internal(bool quiet)")
end = src.index("\nvoid restore_map(void)", start)
body = src[start:end]
wrapper_start = end
wrapper_end = src.index("\n#define log_reg", wrapper_start)
wrapper = src[wrapper_start:wrapper_end]

start_fn = src[src.index("int __attribute__((section(\".start.text\"))) __noinline start("):]
map_init = src[src.index("static int start_mapping_context_init("):src.index("\nvoid symbol_init();")]

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
if "if (!quiet && printk && vsnprintf)" not in body:
    raise SystemExit("[FAIL] quiet restoration still depends on printk/vsnprintf")

if "restore_map_internal(false);" not in wrapper:
    raise SystemExit("[FAIL] public restore_map wrapper does not use common restoration routine")

if "start_mapping_context_init(kimage_voff, linear_voff)" not in start_fn:
    raise SystemExit("[FAIL] minimal page-table context is not initialized before startup")

if start_fn.find("start_mapping_context_init(kimage_voff, linear_voff)") > start_fn.find("start_init(kimage_voff, linear_voff)"):
    raise SystemExit("[FAIL] mapping context must be ready before fallible start_init")

failure = start_fn[start_fn.find("if (rc) {"):start_fn.find("uint64_t id_aa64mmfr1_el1")]
if "restore_map_internal(true);" not in failure or "return rc;" not in failure:
    raise SystemExit("[FAIL] start_init failure does not restore the map anchor before returning")

for token in ("page_size = 1ull << page_shift;", "pgd_pa = baddr & page_size_mask;",
              "pgd_va = phys_to_virt(pgd_pa);", "|| !linear_voffset"):
    if token not in map_init:
        raise SystemExit("[FAIL] early mapping context missing: " + token)

print("[PASS] early KP startup failure restores the original map anchor without printk")
print("[PASS] map backup restoration is bounded and byte-exact")
