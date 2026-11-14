# Y73S Hook Arena W^X Feasibility Audit

Date: 2026-11-14
Branch: `y73s-cred-layout-guards-20261108`
Audited source: current branch HEAD before this document was committed.

## Scope

Offline source audit of the 1-MiB Hook arena, `kernel/base/hmem.c`,
`kernel/base/hook.c`, `kernel/base/fphook.c`, and the public Hook layouts in
`kernel/include/hook.h`. No target boot, runtime page-table capture, or device
test was performed.

## Confirmed layout

- `start.c` assigns `HOOK_ALLOC_SIZE` (1 MiB) to `_kp_hook_start..end`.
- Every KIMG leaf in that interval is changed to writable and executable:
  DBM/SH are set, PXN and RDONLY are cleared, and GP is cleared.
- `hook_mem_add()` treats the entire interval as a fixed-slot arena.
- `hook_mem_warp_t` contains allocator state (`using`, `type`, `addr`) and
  one union containing `hook_t`, `hook_chain_t`, or `fp_hook_chain_t`.
- The largest union member is `fp_hook_chain_t`; it contains the transit
  instruction array. `hook_chain_t` likewise embeds `transit[]`.
- The same record therefore contains both mutable management/callback metadata
  and executable transit instructions. The allocator zeroes the whole union
  before publication, and Hook preparation writes the transit buffer before
  it is installed.

## Why the arena cannot simply become RX or RW-NX

- Making the whole arena RX would break allocator state, callback arrays,
  owner pointers, chain state, active-reader counters, and initialization.
- Making the whole arena RW-NX would prevent execution of transit code.
- Keeping the whole arena RWX preserves current behavior but does not provide
  W^X.
- A page permission change around only `transit[]` is not currently possible:
  transit is embedded in a variable-sized union record and records are packed
  at `sizeof(hook_mem_warp_t)` strides, not allocated from page-isolated
  code/data sub-arenas. Different records can share a 4-KiB page.

## Required redesign before permission changes

1. Split each Hook record into a data/control object and a separately allocated
   page-aligned transit-code object. Keep all mutable state, callback pointers,
   owner tokens, and reader counters in RW-NX storage.
2. Replace embedded `transit[]` assumptions with an explicit pointer/capacity
   in the control record. Audit all transit emitters and dispatchers for pointer
   use, capacity checks, alignment, and branch reachability.
3. Build transit code in RW-NX pages, clean D-cache to PoU, invalidate the
   relevant I-cache on all CPUs, then change only the code pages to RX.
4. On removal, first prevent new dispatch and wait for every in-flight
   dispatcher and any delayed branch arrival. Only then may code pages be
   reclaimed. If the lifetime proof cannot cover a CPU that fetched the old
   branch but has not entered the Gate, the code page must remain resident.
5. Validate both KIMG and linear aliases. A writable linear alias of an RX
   transit page violates physical W^X even if the KIMG alias is RX.
6. Preserve the existing branch-range and ABI guarantees for all transit
   variants, including the 12-argument path.

## Additional correctness risks found

- `hook_mem_add()` returns an error, but the caller in `start.c` does not
  check it before continuing. Initialization failure should be fatal to Hook
  activation, not silently treated as a ready arena.
- `hook_mem_zalloc()` marks a slot as initializing, drops the lock, and then
  zeroes its union. This avoids holding the lock over a large memset, but every
  lookup/retire/free path must consistently reject the initializing state.
- Retired records are intentionally not ordinary free slots. Reuse must not
  be introduced until the delayed-arrival and trampoline-retention protocol is
  proven; reclaiming a retired code page prematurely can redirect a stale
  branch into unrelated code.
- The current 1-MiB arena has a finite fixed-record capacity. Splitting code
  pages from data records changes memory consumption and must be measured
  against the existing maximum Hook workload.

## Release decision

Do not change Hook arena permissions in this phase. The current mixed record
layout makes page-granular W^X impossible without an ABI/layout refactor.
The safe next implementation unit is a source-compatible pointer-based transit
buffer abstraction plus a host layout test; permission changes must wait until
the dispatch lifetime and alias checks are implemented and tested.

This audit is static source evidence only. It is not a claim of target-device
bootability or runtime W^X enforcement.
