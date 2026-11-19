# Y73S LKM KPM W^X and executable-image lifetime audit

Date: 2026-11-17  
Branch: `y73s-cred-layout-guards-20261108`

## Scope

This audit compares the standalone LKM KPM loader (`lkm/kpm/module.c`) with the in-tree KPIMG KPM loader (`kernel/patch/module/module.c`) and its executable allocator (`kernel/base/exec_alloc.c`). It focuses on section layout, final symbol/string-table placement, executable permission classes, permission-transition failure handling, and image release/quarantine.

This is a source audit plus host-side regression coverage. It is not a vendor-kernel build, runtime PTE fault-injection result, or Vivo Y73s device validation.

## Main finding: LKM KPM does not enforce page-class W^X

The LKM loader computes `text_size` and `ro_size` in `layout_sections()`. Its `layout_symtab()` appends the symbol table and string table and stores their offsets in `kp_load_info`, but the LKM `struct kp_module` has no `symtab_start` field. The loader does not retain the start of the appended symbol/string area as a module permission boundary.

After relocation, `kp_load_module()` calls `kp_clear_bti_gp(mod->start, mod->size)` over the complete image before invoking the module's init callback. That helper changes/validates PXN, UXN, and the BTI Guarded-Page bit only. It does not apply read-only permissions to text or rodata, does not set the writable-data policy from `ro_size`, and does not protect appended symbol/string tables as RO-NX.

On the Y73S 4.14 compatibility path, the source allows `init_mm` to be absent when the selected backend is `module_alloc()` and `PTE_GP` is unavailable. In that case `kp_update_bti_gp()` returns success without walking PTEs; the code relies on the module allocator's `PAGE_KERNEL_EXEC` contract. The LKM loader therefore does not itself establish per-section W^X on this path. Where `init_mm` is present, it also processes the entire image as executable rather than separating code, data, rodata, and appended symbols.

**Conclusion:** LKM KPM currently verifies/enables privileged execution bits for the whole image, but it does not implement a text RX / writable-data RW-NX / rodata-and-symbol RO-NX policy. This is a W^X release blocker for the LKM KPM path. The source does not establish the exact AP/DBM state supplied by the specific Vivo vendor `module_alloc()` implementation, so this audit deliberately does not claim an exact vendor PTE value or make a device-level RWX observation.
## Additional W^X gap: mutable callback trampoline page

The LKM KPM allocates a one-page callback trampoline through the executable-memory backend using `kp_malloc_exec(PAGE_SIZE)`. The source comment explicitly describes this as a module-allocated RWX page. `kp_kpm_safe_kallsyms_on_each_symbol()` writes the four instruction words for a selected slot directly into that page and flushes the instruction cache; it does not perform an RW-NX-to-RX permission transition around the write. This is a separate mutable-executable-storage gap from the loaded KPM image's section layout.

This should not be fixed by naively toggling the whole page NX during each slot write. The implementation deliberately gives concurrent iterators distinct slots in the same trampoline page, so a whole-page permission transition can race with another iterator executing a different slot. A safe redesign needs an explicitly reviewed write/execute alias strategy or a synchronization/quiescence protocol that covers all in-flight trampoline calls. The actual AP/DBM permissions still depend on the selected allocator and exact vendor implementation; the source proves the mutable executable design and the lack of a per-write permission transition, not the exact Vivo PTE descriptor.


## KPIMG reference behavior

The KPIMG implementation has a separate page-class protection path:

- `layout_sections()` page-aligns executable, read-only, and writable segment boundaries.
- `layout_symtab()` records `symtab_start` before appending symbol/string data, after requiring the existing image size to be page-aligned.
- `load_module_ex()` calls `kp_exec_protect_module(start, size, text_size, ro_size, symtab_start)` before entering module init, and aborts loading if protection fails.
- `exec_set_module_protection()` validates the ordered, page-aligned boundaries and preflights the complete target allocation with `exec_prepare_pages()` before changing any page.
- The page classes are RX for the text range, RW-NX for writable data, and RO-NX for rodata plus the appended symbol/string range. The descriptor helper updates AP/DBM and PXN/GP as appropriate, while the allocator performs the required TLB maintenance.

This is a source-level comparison of two implementations, not proof that the KPIMG protection path has been compiled against the Vivo vendor headers or exercised on the device.

## Second finding: LKM KPM loses retry metadata after NX restoration failure

The LKM `kp_free_exec()` helper returns `void`. If `kp_restore_nx_gp()` cannot verify NX/BTI restoration, it logs the failure and returns without freeing the executable allocation. This avoids returning a possibly executable range to its allocator.

However, callers cannot observe that failure. In the normal KPM unload path, the caller proceeds to free the module state after `kp_free_exec()` returns. Thus the executable allocation can remain leaked while its module registry record is discarded. The load-failure cleanup path also cannot distinguish a successful image release from a leak.

The KPIMG reference behaves differently: its free operation returns an error, the loader retains a retryable module/quarantine record on failure, and the unload path can attempt reclamation again. The LKM version currently has no equivalent quarantined module state.

The same unobservable failure affects the callback-trampoline allocation, not just loaded KPM images. In `kp_kpm_init()`, if trampoline permission verification fails, the code calls `kp_free_exec(kp_callback_tramp, PAGE_SIZE)` and then clears `kp_callback_tramp` and its size. `kp_kpm_exit()` likewise calls `kp_free_exec()` and clears the pointer/size before resetting the allocator backend function pointers. If NX restoration fails in either path, the page is leaked without a retained retry record; during subsystem exit, the matching free-backend references are also discarded.

The concrete LKM call sites are the load-failure cleanup, normal unload, trampoline-init failure cleanup, and subsystem exit. Each uses the same `void kp_free_exec()` contract, so none can distinguish successful reclamation from deliberate leak-on-failure.

**Conclusion:** LKM's NX failure behavior is conservative about freeing executable pages, but incomplete as a lifecycle protocol because a retained allocation is no longer represented by retryable metadata. The trampoline page shares this defect.

## Additional lifecycle gap: LKM does not retain ownership after failed NX restoration

The LKM implementation differs materially from the KPIMG reference loader:

- `kp_free_exec()` returns `void`. If `kp_restore_nx_gp()` fails, it logs and returns without freeing the allocation, but its caller cannot distinguish that retained allocation from a completed free.
- The LKM load-failure cleanup path calls `kp_free_exec(mod->start, mod->size)` and then frees `mod` unconditionally. If NX restoration failed, the executable allocation remains but its owning metadata is discarded.
- Normal LKM unload removes `mod` from the registry, marks it DEAD, unlocks, calls the void free helper, and then frees `mod`. A failed permission restore therefore leaves no registry entry or retry handle.
- `kp_kpm_exit()` similarly clears `kp_callback_tramp`, its size, backend selection, and allocator function pointers after calling the void free helper. If the transition failed, teardown loses the information needed to retry safely.

The KPIMG reference already demonstrates a stronger pattern: checked free return value, stable module name, a dedicated quarantine list/state for images that never completed load, and retryable unload for retained executable images. The LKM port does not yet implement that protocol.

**Required LKM fix design:** change the executable free helper to return an error; retain the module object and executable pointer in a quarantine registry whenever NX restoration fails; do not unlink normal modules or free metadata until executable release succeeds; and make KPM teardown preserve backend/trampoline ownership if the trampoline cannot be safely reclaimed. The retry path must not rerun module init/exit callbacks. Do not simply copy KPIMG code: LKM uses a different lock, allocator wrapper, and module structure.

## Additional verification gap: failed executable-permission setup on the no-init_mm path

The LKM main-image load path calls `set_memory_x()` when the symbol is available. A non-zero return is logged, but it does not stop loading. The code then calls `kp_clear_bti_gp()` and treats a zero return as permission verification success.

That final step is not an independent PTE verification when `init_mm` is unavailable and the selected backend is `module_alloc()` or `execmem_alloc()`: `kp_update_bti_gp()` takes the `kp_kpm_can_skip_init_mm()` branch and returns success without reading or changing any PTE. Consequently, a failed `set_memory_x()` can be followed by a successful loader-side status even though this LKM code has not established the executable descriptor state. The source comment relies on the executable-mapping contract of the allocator, but the exact Vivo Y73s 4.14.141 implementation has not yet been obtained and verified.

The callback-trampoline setup has the same boundary more directly: `kp_kpm_init()` calls `kp_do_set_memory_x()` but discards its return value, then invokes the same helper. If the no-`init_mm` fallback is active, a failed transition is not detected by a PTE walk before the trampoline page is initialized and the KPM subsystem is marked ready.

**Interpretation:** this is an unresolved proof gap, not evidence by itself that the Y73s allocator returns NX memory or that this caused the reported reboot. To close it, verify the exact target allocator implementation and its page protections. If its executable guarantee is not explicit and reliable, make a failed/missing `set_memory_x()` fatal on the no-`init_mm` path; do not count the skipped PTE walk as verification. Extend host fault-injection coverage for both the main image and trampoline setup.

## Permission-transition partial-state limit

The LKM PTE helper walks and changes pages in the same loop. A later page-table lookup or post-write permission-verification failure can occur after earlier PTEs have been modified. The function returns an error without restoring those earlier PTEs. The optional whole-range `set_memory_x()` / `set_memory_nx()` call is also performed before this loop and is not undone if a later per-page check fails.

The KPIMG allocator's module-protection function first resolves and validates the complete set of PTEs, then performs its page-class changes in a second pass. This narrows the failure window compared with the LKM loop, although it still is not a general rollback transaction for arbitrary hardware/runtime failures after the write pass begins.

The no-`init_mm` fallback is another distinct case: it cannot inspect PTEs, so a backend-specific allocator contract becomes authoritative. This must be validated against the exact vendor implementation, not generalized from generic upstream ARM64 headers.

## Test coverage added or wired into CI

- `verify_lkm_kpm_loader_contract.py` compares the LKM permission path to the KPIMG reference page classes and emits explicit `[KNOWN GAP]` diagnostics. It also checks the callback trampoline allocation, distinct slot use, all instruction-word writes, I-cache flush ordering, and the absence of an RW-NX/RX transition.
- The verifier checks the KPIMG symbol-table boundary, page-class assignments, AP/DBM permission masks, whole-range PTE preflight ordering, and KPIMG quarantine behavior.
- The verifier independently checks the LKM no-`init_mm` fallback and the void/leak free path, including the loss of retryable module metadata.
- `test_kpm_layout_copy.py` host-executes the production layout/copy functions for LKM and KPIMG and covers valid layouts, section alignment rejection, destination bounds, and allocation failure. It does not model page permissions.
- `test_kpm_execmem_restore.py` host-executes the production KPM NX-restoration helper with stubbed results. It tests the no-`init_mm` fail-closed path and the `init_mm` fallback. It does not execute the actual ARM64 page-table walk or inject faults into a real vendor kernel.
- `test_kpm_trampoline_slots.py` host-executes the production slot allocator/free functions with a pthread-backed lock. It races 32 threads to allocate all 256 slots, checks uniqueness and `-EBUSY` on exhaustion, then verifies release and reuse. It does not execute the generated AArch64 trampoline or test real PTE permissions.
- Both host tests and the KPM loader verifier are wired into the FolkPatch regression workflow. The layout and NX-restore host tests are also wired into the main Linux build workflow.

These checks prove source contracts and selected helper behavior only. They do not prove the actual vendor PTE layout, kernel ABI, full section W^X at runtime, or real multi-CPU transitions.

## Required work before clearing the blocker

1. Obtain the exact Vivo Y73s 4.14.141 vendor KDIR, generated configuration, and matching symbol/version data. Confirm the backend allocator's real AP/PXN/UXN/GP descriptors and all page-table/cache/TLB APIs.
2. Carry the section boundaries through the LKM module object, including an explicit page-aligned `symtab_start`.
3. Add LKM image page-class protection (RX / RW-NX / RO-NX) and redesign the mutable callback trampoline so instruction writes cannot occur through an executable writable mapping. Preserve correctness for concurrent iterator slots; do not use an unsynchronized whole-page permission toggle.
4. Define failure semantics for a partial PTE transition. At minimum, retain a precise changed-page set, attempt restoration with required TLB maintenance, and do not report a clean state if rollback fails. Do not release the image if its permissions cannot be established.
5. Change LKM executable-free APIs to propagate NX-restoration errors. Retain retryable records for both KPM images and the callback trampoline; preserve the backend/free-function state until all executable allocations are safely reclaimed.
6. Add host fault-injection tests for first/middle/last page preflight failures and an instrumented vendor-kernel test for permission application/rollback and free quarantine. Then compile with the exact vendor KDIR and validate the loaded KPM lifecycle.

## Status

- LKM KPM section layout and image copy: host-testable coverage already exists.
- KPIMG page-class W^X reference: source-confirmed; not a substitute for validating the LKM backend.
- LKM KPM full-image permission handling: **known W^X gap; not fixed**.
- No-`init_mm` executable-permission establishment after failed `set_memory_x()`: **verification gap; target allocator contract not confirmed**.
- KPM callback trampoline writable/executable storage: **known W^X gap; not fixed**.
- LKM KPM quarantine/retry after NX restore failure, including callback-trampoline cleanup: **known lifecycle gap; not fixed**.
- Multi-page LKM permission rollback: **not transactional; not fixed**.
- Production kernel code: unchanged in this audit.
- Vendor-KDIR compilation, real PTE fault injection, and Y73s device validation: not performed.
