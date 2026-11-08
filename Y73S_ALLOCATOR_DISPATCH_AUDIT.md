# Y73S allocator ABI audit — binary-level correction

Branch: `y73s-gcc-audit-20261108`

Scope: read-only analysis of the original `kernel-b`, the supplied patch log, and the current branch source. No runtime source was changed, no KPIMG or boot image was generated, and no device operation was performed.

## Exact input identity

- Original `kernel-b`: 47,517,708 bytes
- SHA-256: `345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`
- Matching Kallsyms report: `Y73S-kallsyms-report.txt`
- Patch log examined: `patch-test(3).log`, which reports the same 4.14.141 banner and decompressed kernel size.

## Confirmed resolver selection

The supplied `patch-test(3).log` explicitly records:

- no symbol `memblock_phys_alloc_try_nid`;
- `memblock_virt_alloc_try_nid` found at `0x01914930`;
- `memblock_alloc_try_nid` found at `0x01914928);
- `use memblock_alloc_try_nid as map phys alloc`.

The current branch `tools/symbol.c` confirms why: when
`memblock_phys_alloc_try_nid` is absent, it stores the
`memblock_alloc_try_nid` address into `memblock_phys_alloc_relo` and marks
the type `MAP_SYM_MEMBLOCK_ALLOC_TRY_NID`. The virtual allocator is resolved
separately to `memblock_virt_alloc_try_nid` when that symbol exists.

Thus this is not merely a hypothetical fallback selection: the supplied patch
log shows that the fallback was selected for the Y73S image.

## Confirmed binary finding: fallback returns a virtual address

The Kallsyms report contains:

- `memblock_alloc_try_nid` at image offset `0x01914928`
- `memblock_alloc_try_nid.cfi` at `0x0211af28`
- `memblock_virt_alloc_try_nid` at `0x01914930`
- `memblock_virt_alloc_try_nid.cfi` at `0x0211b364`

No `memblock_phys_alloc_try_nid` symbol appears in the supplied complete
Kallsyms report.

AArch64 disassembly of `memblock_alloc_try_nid.cfi` at `0x0211af28`
confirms a three-argument entry: it consumes `x0` (size), `x1` (alignment),
and `x2` (node ID). However, its return semantics are **not physical-address
semantics**:

1. The allocator's internal result is retained as a physical address.
2. The function subtracts a kernel physical-memory base/offset value from that
   result.
3. It ORs the result with the kernel virtual base pattern
   `0xffffffc000000000`.
4. It uses the converted address as the destination for zeroing and returns
   that converted value in `x0`.

This is the physical-to-virtual conversion pattern. For this exact binary, the
three-argument `memblock_alloc_try_nid.cfi` entry returns a kernel virtual
pointer, not a physical address.

The separate `memblock_virt_alloc_try_nid.cfi` entry at `0x0211b364`
consumes five arguments (`x0`–`x4`) and is also a virtual allocator. These
two symbols must not be conflated.

## Direct mismatch in current branch source

In `kernel/base/map.c`, `map_phys_alloc()` sends both
`MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID` and
`MAP_SYM_MEMBLOCK_ALLOC_TRY_NID` through a function pointer typed as:

```c
typedef phys_addr_t (*memblock_phys_alloc_try_nid_f)(
    phys_addr_t size, phys_addr_t align, int nid);
```

It then treats the return value as a physical address.

Combining the patch log, resolver source, and target disassembly establishes
the mismatch for this supplied Y73S patch path: the three-argument call
convention is compatible, but the return value is a virtual address that the
KP code treats as a physical address.

The consequences propagate into the current map path:

- `mem_proc()` stores this result in `detect_phys`, then supplies it as a
  physical-address bound to `memblock_virt_alloc_try_nid`.
- `_paging_init()` uses the allocation result as `start_pa`.
- It passes `start_pa` to `memblock_mark_nomap`.
- It computes `start_va = start_pa + kimage_voffset` and uses the result for
  page-table construction and copying.

A virtual address misinterpreted as a physical address can therefore corrupt
the early mapping calculations before `start()` is reached.

## Assessment

<em>High-confidence static defect in the supplied Y73S fallback path.</em>
The patch log proves the fallback is selected; the original binary proves
that the fallback returns a virtual pointer; and the current source treats
that return as a physical address. This is a strong candidate for the early
reboot loop.

It is not yet proof that this is the only fault or that every tested patched
image used this exact source/build. The next check is to compare the embedded
KPIMG in the exact failing boot image with the standalone KPIMG and verify
its embedded preset values and resolver version.

## Additional confirmed source risks

- `mem_proc()` checks `memblock_virt_alloc_relo` but does not check
  `memblock_phys_alloc_relo` before calling it.
- The zero-size probe assumes meaningful behavior from both allocators and
  assumes the returned pair is suitable for calculating `linear_voffset`.
- `get_or_create_pte()` does not propagate intermediate page-table
  allocation failure.
- `_paging_init()` does not validate the main allocation before mark-nomap,
  mapping, and copying.

## Next safe engineering step

Do not patch the runtime path by guessing an inverse address conversion.
First verify the exact embedded KPIMG/preset data and inspect whether the
target exposes a genuinely physical allocator or a reliable physical-range
allocation primitive. Any replacement must be checked for its exact ABI,
allocation semantics, reservation behavior, and rollback requirements.

The stack-frame verifier remains a separate issue: it needs ELF symbol-range
awareness and verification of the caller's frame-record setup. A passing
flat-binary byte-pattern check is not a full ABI proof.

## Fail-closed source guard committed

A tool-side guard was committed in `tools/symbol.c` (commit
`6880bd05d95214357726d1a3ed5bbba0a5447f62`). It no longer substitutes
`memblock_alloc_try_nid` for either the physical allocator or the
five-argument virtual allocator. If either correctly typed allocator is
missing, the patching tool exits with an explicit diagnostic instead of
emitting a KPIMG with an incompatible pointer.

This is intentionally a compatibility stop, not a completed Y73S allocator
implementation. It prevents the known-bad fallback from being generated, but
does not yet make APatch boot on this kernel. The source change has not yet
been built or exercised in CI; no boot image was produced.

## Physical allocator candidate for further investigation

The original binary also contains `memblock_find_in_range.cfi` at
`0x003919a8`. Its wrapper consumes four arguments (`start, end, size,
align`) and forwards them to `memblock_find_in_range_node` with
`NUMA_NO_NODE`, returning the range result directly. Unlike
`memblock_alloc_try_nid.cfi`, this wrapper does not perform a physical-to-
virtual conversion in its own body, so it is a plausible physical-range
allocator candidate.

It is not wired into the runtime path. Before using it, the implementation
must verify the target's exact range-bound semantics and add an explicit
reservation step: the find-range wrapper itself does not reserve the selected
range. Reservation failure and rollback must be handled before this can be a
safe replacement.
