# Y73S runtime-failure path audit (read-only)

Branch: `y73s-gcc-audit-20261108`

This note records source-level risks found while reviewing the branch. It does **not** claim a confirmed bootloop root cause and does not change runtime code.

## Confirmed source-level gaps

### 1. Allocation result is used without validation

In `kernel/base/map.c`, `_paging_init()` obtains:

```c
uint64_t start_pa = map_phys_alloc(data, all_size, page_size);
```

The return value is then passed to `memblock_mark_nomap` (when present), used to construct `start_va`, and used for page mapping/copying. There is no immediate check that `start_pa` is nonzero or page-aligned, nor that the requested range is valid and does not overflow.

`map_phys_alloc()` itself returns 0 when the detected allocator type is not one of its supported cases. That makes the unchecked use particularly important.

### 2. Intermediate page-table allocation is unchecked

In `get_or_create_pte()`, an invalid non-leaf entry triggers `map_phys_alloc(data, page_size, page_size)`. The code immediately builds a table descriptor and clears the returned address. A zero result is not propagated as an error. The function also returns an entry pointer without a failure status, and its callers dereference that pointer.

This is a separate failure path from the main `start_pa` allocation.

### 3. The memory-probe path has a hard trap

In `mem_proc()`, absence of `memblock_virt_alloc_relo` reaches `__builtin_trap()`. This is fail-stop behavior, not a recoverable fallback. Before relying on this path, the Y73S report must establish that the symbol is found and that the function-pointer ABI and returned physical/virtual pair are valid on this exact kernel.

## Stack-frame verifier scope

`scripts/verify_kpimg_stack_frame.py` checks a hard-coded `_paging_init` prologue pattern, a hard-coded restore sequence, and the immediate used by `add sp, x10, #imm`. It fails closed when the patterns are absent or ambiguous, which is good.

However, the verifier does not identify the restore sequence by ELF symbol/range and does not independently validate the compiler-generated prologue of `start()` (which is relied on by the inline assembly using `x29`). The next audit should use the ELF symbol table and disassembly to verify both function boundaries and the relevant frame-chain assumptions.

## Target-specific relevance

For the reported Y73S Linux 4.14.141 kernel, `new_era = kmajor > 5` is false, so the newer-kernel scratch mapping branch is not selected. That does not eliminate the allocation and page-table failure paths above.

## Required evidence before any runtime change

1. Obtain the exact Y73S preset/log showing which allocator symbols and types were selected.
2. Disassemble the exact GCC-built `kpimg.elf`; verify `_paging_init` and `start` by symbol boundaries, not byte-pattern search alone.
3. Trace the 4.14.141 `memblock_alloc_try_nid`, `memblock_virt_alloc_try_nid`, `memblock_mark_nomap`, and `memblock_free` implementations and call conventions from the original kernel.
4. Define a safe abort/rollback path before adding null checks. Returning from the hook after partially reserving or changing page tables is not automatically safe.
5. Keep generated images out of flashing until a complete static audit and a recoverable test plan are in place.

## Status

- Source audit: findings recorded.
- Runtime source changes: none in this audit note.
- GCC CI execution: not verified from this review.
- Device boot: not verified.

A passing build or byte-pattern check is not proof that the Y73S device will boot.


## Follow-up on hardening branch (2026-11-08)

The isolated branch `y73s-runtime-contract-hardening-20261108` adds source regression gates and updates the current status. The following previously recorded source gaps are guarded in the current branch source:

- `_paging_init()` rejects a zero, unaligned, or overflowing main destination PA before `memblock_mark_nomap()`.
- `get_or_create_pte()` traps when an intermediate page-table allocation returns zero before writing a table descriptor.
- The Y73S linear-map probe is checked to run only after the original `paging_init()` returns, and checks the exact-page probe and release result.
- The known-bad `memblock_alloc_try_nid` virtual-return fallback is rejected by the resolver and by the new source regression verifier.

The new CI verifier is `scripts/verify_y73s_runtime_contract.py`. It is a source-level regression check, not a replacement for disassembling the target kernel and validating the ABI independently.

### Verified CI result

- Workflow run: https://github.com/ljx-91/kptools-fix/actions/runs/42474139101
- Commit: `01b8b028d3eb258bfc340a75868945220a01e1ed`
- Arm GNU Toolchain 14.2.rel1 build: passed
- ELF stack-frame verifier: passed
- Existing memblock source contract verifier: passed
- New runtime contract verifier: passed
- KPIMG map-relocation verifier: passed
- Artifact: `y73s-kpimg-arm-gnu-gcc14-audit`
- Artifact SHA-256: `8a9a18167fce3b7bb40d76eeaeb11dacbf86e71a2dd4bd626c6ceb0732ad8742`

This validates the CI build and the listed static checks only. It does not establish device boot, APatch initialization, AVB validity, or root availability. No device-side test or partition write was performed.
