# Y73S continuation audit: allocator dispatch and preconditions

Branch: `y73s-gcc-audit-20261108`

This is a source-audit note only. It does not change runtime code, build a KPIMG, modify a boot image, or establish that a particular failure caused the device reboot loop.

## Newly confirmed source-level issue: allocator pointer precondition

In `kernel/base/map.c`, `mem_proc()` enters the probe when
`memblock_virt_alloc_relo` is nonzero, but it calls
`memblock_phys_alloc_relo` first without checking that pointer.

Consequently, the condition currently proves only that the virtual allocator
pointer exists. It does not prove that the physical allocator pointer exists.
If the physical pointer is unresolved, the first indirect call can fail before
the map hook reaches its later work.

A source-level correction would need to validate both pointers and provide a
defined failure path. Merely adding an early return is not automatically safe:
`_paging_init()` is replacing a kernel paging hook, and callers depend on
memory reservations, mappings, and the original paging_init call being handled
consistently.

## Allocator dispatch is ABI-sensitive

`map_phys_alloc()` dispatches both
`MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID` and
`MAP_SYM_MEMBLOCK_ALLOC_TRY_NID` through the same three-argument function
pointer type returning a physical address.

That is valid only if the selected target entry really has the three-argument,
physical-address-returning ABI expected by this call site. Current upstream
Linux declares `memblock_phys_alloc_try_nid(size, align, nid)` as a physical
allocator, but declares `memblock_alloc_try_nid(size, align, min_addr,
max_addr, nid)` as a virtual allocator. These upstream declarations do not
settle the ABI of Vivo's vendor 4.14.141 kernel. The branch comment asserting a
Y73S-specific three-argument CFI entry must therefore be treated as a
target-specific hypothesis until the exact original-kernel function body,
CFI entry, and call sites are independently disassembled.

Do not change the dispatch based only on upstream headers. First identify
whether the resolver selected a real function, a CFI jump-table entry, or a
compiler-generated wrapper, and verify argument registers and return-value
semantics in the original Y73S binary.

## Zero-size probe is another target-specific assumption

`mem_proc()` invokes the physical allocator with size zero, then invokes the
virtual allocator with size zero and `min_addr == max_addr == detect_phys`.
The computed `linear_voffset` assumes both calls have meaningful and
compatible zero-size semantics on this exact vendor kernel.

The source alone does not establish that assumption. Verify the actual
4.14.141 implementations and the CFI entry bodies before relying on this
probe. A nonzero pointer result is not sufficient evidence that the returned
virtual/physical pair is valid.

## Required checks before any runtime patch

1. Record every resolved memblock symbol address, symbol category, and resolver
   path in one diagnostic report.
2. Disassemble the exact target entry and any CFI thunk; identify argument
   registers, return type/semantics, and whether the symbol is a wrapper.
3. Verify the zero-size allocation behavior in the target implementation.
4. Add explicit validation for both allocator pointers and all allocation
   results, with a rollback/fallback design for partially completed map work.
5. Make `get_or_create_pte()` propagate intermediate-table allocation failure
   rather than publishing a descriptor for an unchecked address.
6. Build an ELF-aware verifier that checks actual `start` and
   `_paging_init` symbol ranges and frame-record instructions. The existing
   flat-binary pattern checker is not a full ABI verifier.

## Status

- Confirmed: missing physical-allocator pointer check in `mem_proc()`.
- Confirmed: both allocator categories share one three-argument dispatch type.
- Not confirmed: whether Vivo's selected `memblock_alloc_try_nid` CFI entry
  actually has that three-argument physical allocator ABI.
- Not confirmed: zero-size probe semantics on the target kernel.
- Not changed: runtime code, KPIMG, boot image, or flashing state.
