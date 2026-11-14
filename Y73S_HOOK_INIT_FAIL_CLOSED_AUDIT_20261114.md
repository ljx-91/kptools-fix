# Y73s Hook arena initialization fail-closed audit

Date: 2026-11-14  
Branch: `y73s-cred-layout-guards-20261108`

## Change

`kernel/base/start.c` now captures the return value from `hook_mem_add()` and emits an explicit boot diagnostic when initialization fails:

- `Hook engine disabled: hook_mem_add failed (<errno>)`

The change deliberately does not alter Hook arena mappings, permissions, allocator layout, public structures, or Hook ABI.

## Why continuing initialization is fail-closed

The inspected `kernel/base/hmem.c` implementation gates both allocation and origin lookup on `hook_locks_ready`. A failed `hook_mem_add()` leaves that flag false, so:

- `hook_mem_zalloc()` returns NULL;
- `hook_get_mem_from_origin()` and the typed lookup return NULL;
- Hook creation paths consequently report allocation failure rather than publishing a partially initialized record.

This is a controlled degradation of Hook functionality, not proof that the rest of KernelPatch is boot-safe on the target device.

## ABI constraints confirmed

`hook_chain_t` and `fp_hook_chain_t` remain public in `kernel/include/hook.h`, with inline `transit[TRANSIT_INST_NUM]` arrays. Both implementations still recover their owner with `local_container_of(transit, ..., transit)`. Replacing those arrays with pointers would change public structure layout and invalidate this ownership calculation.

No transit-storage migration or W^X permission change is included in this patch.

## Validation

A static contract script, `scripts/verify_y73s_hook_init_fail_closed.py`, checks the diagnostic, the fail-closed allocator gates, and the preserved inline/FP chain ABI assumptions.

This is source-level validation only. It does not replace an ARM64 build, KPM compatibility testing, or boot testing on the vivo Y73s (V2031A / PD2031, MT6853, Linux 4.14.141+).
