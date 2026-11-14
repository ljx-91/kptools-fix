# Y73S executable allocator and KPM permission design audit

Branch: `y73s-cred-layout-guards-20261108`
Audited source revision: `88888069b3446e9719e01d2332ff6e127b9b09df`

## Status

Design/audit only. This document does not implement a new allocator, alter PTE permissions, generate KPIMG, or authorize flashing. No runtime or device test was performed.

## Confirmed current design

- `kernel/include/kpmalloc.h` routes `kp_malloc_exec`, `kp_memalign_exec`, `kp_realloc_exec`, and `kp_free_exec` to `kp_rox_mem`.
- `kernel/base/start.c` creates the TLSF control object from the RW pool, then adds the 4 MiB ROX region as a TLSF pool. The control object is outside the ROX pool, but TLSF block headers and free-list links are stored in the pool itself.
- `kernel/base/tlsf.c` writes pool-resident metadata during split, trim, free, merge, and insertion. In particular, `block_split`, `block_absorb`, and `tlsf_add_pool` mutate block headers inside the managed region.
- The KPM loader in `kernel/patch/module/module.c` is the observed consumer of the executable allocation API: it allocates one image, zeroes it, copies allocated ELF sections, applies relocations, calls `flush_icache_all()`, and frees the allocation on failed load or unload.
- `layout_sections()` page-aligns `mod->text_size` and `mod->ro_size`, but `kp_malloc_exec()` uses ordinary `tlsf_malloc()`; the returned base is not guaranteed page-aligned. Therefore section-relative page boundaries do not imply page-aligned virtual addresses.
- `struct module` stores `size`, `text_size`, and `ro_size`. Candidate page-level ranges relative to a page-aligned module base are text `[0,text_size)`, read-only data `[text_size,ro_size)`, and writable/remainder `[ro_size,align_up(size,page_size))`. This must be validated against every section layout and relocation before applying permissions.
- The ROX region is 4 MiB (1024 pages at 4 KiB/page); the RW region is 2 MiB. The hook arena is a separate 1 MiB region with its own fixed-slot allocator and currently RWX treatment.

## Recommended architecture (not yet implemented)

Replace only the executable pool's TLSF use with a page-run allocator:

1. Keep the existing RW TLSF for ordinary allocations and allocator metadata.
2. Reserve a compact page bitmap (1024 bits = 128 bytes for the current 4 MiB arena) and a lock/state in RW memory.
3. Allocate contiguous page runs from the executable arena. Validate nonzero page count, overflow, bounds, alignment, and allocation-state transitions. Return only page-aligned bases and record the exact run length.
4. Free only an exact allocation base with a matching recorded extent; reject interior, duplicate, partial, and out-of-range frees. Do not infer allocation size from user memory.
5. Remove `kp_realloc_exec` unless a complete caller audit proves it is unused; if required, implement it as allocate-copy-free with checked copy bounds and failure atomicity.
6. During KPM load, keep allocated pages writable and PXN while sections are copied and relocations are applied. Perform required data-cache clean / instruction-cache invalidation and barriers before making executable text visible.
7. Only after relocation and cache maintenance succeed, apply page-granular final permissions: text RX, read-only data R-XN, remaining data RW-XN. Flush corresponding TLB ranges and use the target's correct arm64 PTE encoding.
8. On failed load, unwind temporary permissions and free the exact page run. On unload, wait until callbacks and hook references have drained (existing module lifetime protocol), then transition pages to non-executable writable state before clearing/releasing them.
9. Fail closed if the kernel mapping layout cannot safely express separate writable and executable permissions. Do not globally toggle WXN as a substitute for per-region permission correctness.

## Important blockers before implementation

- The current `prot_myself()` permission path applies some data NX / text RO protections only when `has_vmalloc_area()` is true. Y73s runtime values of `kimage_voffset` and `linear_voffset` must be observed and validated before relying on those transitions.
- Boot-time KP region and KPM arena mappings must be checked for aliases. A writable alias to the same physical code pages would defeat RX protection.
- The existing hook arena remains RWX. It is separate from the KPM executable arena and requires its own write/execute lifecycle audit before WXN can be restored globally.
- `flush_icache_all()` currently occurs after relocation, but exact cache maintenance, ordering, and TLB invalidation requirements must be validated for the Y73s 4.14.141+ target.
- Module layout's `text_size` and `ro_size` boundaries, symbol/string table placement, all section flags, and every relocation target need automated invariants before PTE changes are enabled.
- The executable arena is currently only 4 MiB. A page allocator can fragment; contiguous-run exhaustion and maximum module size need explicit tests and diagnostics.

## Required regression tests

- Exhaustive allocator model tests for all 1024 pages: allocate/free, full exhaustion, fragmentation, coalescing, alignment, overflow, zero-size, double-free, interior-free, wrong-size-free, and concurrent contention.
- Assert every returned base is page-aligned, every extent is inside the arena, and no two live extents overlap.
- ELF layout tests with text, rodata, writable data, NOBITS, high alignment, empty sections, large symbol/string tables, and malformed offsets.
- Assert `text_size` and `ro_size` are page-aligned and ordered; final rounded allocation extent covers all allocated sections and relocation targets.
- Permission transition tests over synthetic PTEs: writable+PXN during load; RX text after success; RO+PXN rodata; RW+PXN data; rollback on every failure edge.
- Lifetime tests for failed init, `-EBUSY` exit, active calls, hook references, retryable unload, and freeing only after all references drain.
- Build and disassembly checks with the exact Arm GNU GCC 14.2 toolchain; then static image audit. No device flash until independent boot and recovery gates are met.

## Decision

A page-run allocator with metadata stored in the existing RW region is the preferred direction. It avoids TLSF headers inside executable pages and naturally provides the page alignment required for PTE permissions. This is a design recommendation, not a claim that the implementation or boot path is complete.
