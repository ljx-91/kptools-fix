# Vivo Y73s first-screen reboot loop audit

Date: 2026-11-19
Repository: https://github.com/ljx-91/kptools-fix
Branch: `y73s-cred-layout-guards-20261108`

## Scope and confidence

This review treats “first-screen reboot loop” as a restart while the Vivo logo is still displayed, before Android userspace reaches the launcher. It is distinct from a restart after entering the desktop.

No failing-boot panic, Oops, SError, or serial trace is currently available. Consequently, the cause cannot be confirmed against the exact failing boot at runtime. The findings below distinguish an earlier, high-confidence source/binary defect from additional failure paths found and guarded in the current branch.

## Primary old-image defect: virtual address used as a physical address

The prior d09/d0a Y73s images used an incorrect physical allocator fallback:

- The Y73s 4.14.141 symbol report does not expose `memblock_phys_alloc_try_nid`.
- The earlier resolver selected `memblock_alloc_try_nid`.
- Binary analysis of the exact Y73s kernel showed that `memblock_alloc_try_nid.cfi` returns a kernel virtual pointer.
- The old KPIMG path treated that pointer as a physical address and passed it into physical reservation / NOMAP, linear-map arithmetic, page-table construction, and image relocation.

This is a strong common explanation for the early reboot reports against both older images. It is more compelling than the old stack-frame-only theory, but is not runtime-confirmed without a trace from the failed boot.

The current branch already removes this mismatch:

- Prefer `memblock_find_in_range(0, 0, size, align)` as the physical-range finder and explicitly reserve its returned PA.
- Permit only the correctly typed `memblock_phys_alloc_try_nid` as an alternate physical allocator.
- Never select the virtual-return `memblock_alloc_try_nid` as a PA allocator.
- For Y73s, derive the linear-map offset only after the original 4.14 `paging_init()` has created the mapping, and verify the virtual allocation landed in the exact requested PA interval.
- Fail closed on missing/invalid allocation results or failed NOMAP marking.

The static guard is `scripts/verify_y73s_memblock_contract.py`.

## Additional early-startup recovery defect found in this pass

`start_init()` can return an error when kallsyms / `printk` / `vsnprintf` resolution fails. The KP map hook has already replaced a temporary kernel text “map anchor” with the copied `.setup.map` implementation. Returning from `start()` without restoring that anchor would leave temporary patch code in the kernel text path.

The current branch now:

1. Establishes the minimal page-table context before calling fallible `start_init()`.
2. If `start_init()` returns an error, restores the exact original map-anchor bytes with a quiet path that does not depend on resolved `printk` or `vsnprintf`.
3. Returns to the caller, where `map.c` restores the original WXN bit.
4. If the page-table context itself cannot be established, it still stops rather than attempting an unsafe restore without valid page-table translation state.

Implementation: `kernel/base/start.c`, commits `f7b3e350`, `529db41e`.

## Additional cache-coherency correction

The restored map-anchor bytes are executable kernel code. The old restoration path invalidated I-cache but did not first clean the newly written D-cache lines to the Point of Unification. An I-cache-only invalidate is not a complete self-modifying-code sequence on ARM64.

The current branch now calls `flush_icache_range(start, end)` to clean the restored instruction range to PoU and invalidate the local range, followed by `flush_icache_all()` for the early global instruction-cache invalidate.

Implementation: `kernel/base/start.c`, commit `a2ed2f68`. Static ordering checks are in `scripts/verify_y73s_restore_map_bounds.py` and `scripts/verify_y73s_runtime_contract.py`.

## Build and verification status

The following source/build checks have passed on earlier branch commits:

- Linux offline audit passed on `8fe1c88b`.
- Linux offline audit passed on `cf74ff39`.
- The Y73s memblock API / allocator / reservation contracts passed.
- The stack-handoff checker previously measured the target `_paging_init` frame as `0x140` and verified the saved-register slots and SP restore on a built KPIMG.

The latest combined changes are on commit `15b58b20`. Its Linux audit, Windows build, combined artifact build, and Arm GNU GCC 14.2 KPIMG build were triggered; check the Actions run page for their final results:
https://github.com/ljx-91/kptools-fix/actions?query=branch%3Ay73s-cred-layout-guards-20261108

## Conclusion

The old d09/d0a images should be considered invalid for Y73s because of the physical/virtual allocator mismatch. The current branch corrects that defect and adds two further early-startup protections: restore the map anchor on recoverable startup-resolution failure, and perform D-cache-to-PoU maintenance before I-cache invalidation.

This is **not yet a device-verified fix**. A successful static audit and cross-build cannot prove the handset boots. The missing evidence is a failure-boot log from the exact image under test (pstore/ramoops or serial output) and a controlled runtime validation. The earlier uploaded `console-ramoops` content was from a prior normal Android session and is not evidence for the failed boot.

No boot image is declared ready for device use from these source checks alone.
