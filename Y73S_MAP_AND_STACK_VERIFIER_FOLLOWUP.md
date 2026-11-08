# Y73S follow-up audit: map allocation and stack verifier limits

Branch: `y73s-gcc-audit-20261108`

This is a documentation-only follow-up. No runtime source or boot image was changed.

## Findings from current branch source

### A. `_paging_init()` has unchecked allocator and callback results

In `kernel/base/map.c`, the current implementation:

- calls `memblock_reserve_relo` without checking that the resolved pointer is nonzero;
- calls `map_phys_alloc()`, then may call `memblock_mark_nomap_relo` with the returned address without validating it;
- computes `start_va = start_pa + kimage_voffset` and uses the range for page-table updates and copies;
- calls `memblock_free_relo` without checking that the resolved pointer is nonzero.

These are concrete source-level precondition gaps. They do not establish that the Y73S bootloop was caused by any one of them. A safe fix cannot simply return after the reserve/nomap operations: it must account for partial reservations, page-table changes, and the fact that this hook is replacing `paging_init`.

### B. `get_or_create_pte()` cannot report allocation failure

When an intermediate descriptor is invalid, the function calls `map_phys_alloc()`, writes the result into a table descriptor, and clears the resulting page. There is no validation of the returned physical address and no error return for callers. Later callers dereference the returned entry pointer.

This needs a designed error propagation/rollback model before a runtime change is safe.

### C. `mem_proc()` makes the virtual allocator mandatory

The current code enters `__builtin_trap()` when `memblock_virt_alloc_relo` is absent. If present, it performs a zero-size probe using the physical allocator result as both min and max address. The exact semantics of this probe must be checked against the target kernel's implementation and CFI entry, not inferred from current upstream headers.

### D. Function-signature caution

Current upstream Linux documents `memblock_alloc_try_nid` as a five-argument API (`size, align, min_addr, max_addr, nid`), while `memblock_phys_alloc_try_nid` is three arguments. See:
- https://github.com/torvalds/linux/blob/master/include/linux/memblock.h
- https://code.googlesource.com/linux/torvalds/linux/+/058f2c4b7533365d99d4868fb29a68a5b62ecf5a/mm/memblock.c

That is not proof of the Vivo vendor kernel's implementation. The previous claim that the Y73S `memblock_alloc_try_nid` CFI entry is three arguments must remain provisional until the exact symbol body and call site are independently extracted from the original Y73S kernel binary. Do not generalize the vendor-specific claim to other kernels.

## Stack-frame verifier limitations

The current `scripts/verify_kpimg_stack_frame.py`:
- scans the whole binary for a fixed _paging_init prologue byte pattern;
- scans the whole binary for a fixed restore sequence;
- requires exactly one match of each;
- computes expected restore immediate as frame-size minus 0x10.

It does fail closed on missing or ambiguous patterns. However, it does not parse ELF symbols or confirm that the matches lie inside the actual `_paging_init` and `start` symbol ranges. It also does not validate the `start()` prologue's saved-frame-pointer convention that makes `ldr x10, [x29]` valid. Therefore a PASS is only a narrow byte-pattern consistency check, not a full ABI proof.

A stronger verifier should:
1. require an ELF with a valid AArch64 machine type and symbol table;
2. locate exact `_paging_init` and `start` function ranges;
3. disassemble each function independently;
4. verify the _paging_init frame allocation and frame-pointer establishment;
5. verify start's frame record saves caller FP/LR in the assumed layout;
6. verify the tail restore sequence and SP calculation against those actual frame records;
7. reject stripped ELF or ambiguous/missing symbols rather than silently scanning the flat KPIMG.

## Evidence required to close the audit

- Original Y73S kernel binary and exact extracted symbol bodies for all resolved memblock functions.
- Actual resolver log with addresses and selected symbol types for reserve/free/phys alloc/virt alloc/mark_nomap.
- Exact unstripped GCC-built KPIMG ELF, map file, compiler version, and disassembly.
- No runtime patch or image generation until the above preconditions and failure paths are understood.

## Status

- Source review: completed for the paths above.
- Documentation update: committed.
- Runtime code changes: none.
- Exact Y73S memblock ABI: not independently revalidated in this follow-up.
- GCC CI result and device boot: not verified.
