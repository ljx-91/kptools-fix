# Y73S Hook Transit Split: Consumer and ABI Audit

Date: 2026-11-14
Branch: `y73s-cred-layout-guards-20261108`

## Result

The Hook arena cannot be split by changing only `hook_mem_warp_t`. The
transit buffer is embedded in two public chain structures and its address is
used as an identity token throughout hook setup and dispatch.

## Direct consumers

### Inline Hook chain (`kernel/base/hook.c`)

- `hook_chain_prepare(uint32_t *transit, int32_t argno)` recovers the owner
  using `local_container_of(transit, hook_chain_t, transit)`.
- `hook_wrap` stores `chain->transit` in `hook->replace_addr`.
- The generated entry stub embeds the `chain` pointer as a literal and branches
  to one of the resident `_transit{0,4,8,12}` implementations.
- The same chain owns mutable reader counts, states, callback arrays, owner
  references, and original-function metadata.

### Function-pointer Hook chain (`kernel/base/fphook.c`)

- Its private `hook_chain_prepare` similarly recovers `fp_hook_chain_t`
  from the embedded `transit` pointer.
- `fp_hook_wrap` stores `chain->transit` in `replace_addr`.
- The entry stub embeds the `fp_hook_chain_t *` and branches to the resident
  `_fp_transit{0,4,8,12}` implementation.
- Its chain also contains mutable callback and reader state.

### Allocator (`kernel/base/hmem.c`)

- The arena uses fixed-size `hook_mem_warp_t` slots.
- `hook_mem_zalloc` reserves a slot under a spinlock, drops the lock, then
  clears the embedded union before returning its address.
- Publication, retirement, claim/cancel-retire and origin lookup operate on
  the wrapper's `using` state and origin address.
- The retire states are part of the existing delayed-reclamation protocol;
  they must not be collapsed into a simple free bit.

## Compatibility constraints

1. `hook_chain_t` and `fp_hook_chain_t` are public types in `hook.h`.
   Existing KPMs may allocate them, embed them, or inspect `transit`.
2. Existing code assumes `transit` is an inline array. Moving it behind a
   pointer changes structure size, offsets, initialization, and potentially
   KPM binary compatibility.
3. The entry stub carries the owner-chain address in its literal. A split
   implementation must keep this owner pointer stable for the entire period
   during which the transit code can be entered.
4. The current transit ABI classes 0/4/8/12 and the 12-argument trampoline
   capacity are compatibility requirements; do not change them as part of
   the memory-permission refactor.
5. Inline Hook and function-pointer Hook paths must be converted together.
   Converting only one leaves the same RWX arena requirement in place.

## Safe migration design

- Keep the public legacy structures and inline transit arrays unchanged in
  the compatibility layer for one migration stage.
- Introduce private backend records with explicit `control` and
  `code_pages` pointers, and route only internal creation paths through the
  new backend after proving no public KPM API returns the private object as a
  `hook_chain_t *`.
- Add a versioned/internal accessor for transit entry addresses. Do not infer
  the owner with `container_of` from a separately allocated code pointer.
- Make the transit page allocator return page-aligned executable buffers;
  build in RW-NX, clean D-cache to PoU, invalidate I-cache on all CPUs, then
  publish RX.
- Preserve the current owner-chain literal and lifetime pin. On retirement,
  prevent new dispatch, wait for readers and delayed-arrival safety, then
  reclaim code pages. If delayed arrival cannot be bounded, retain the page.
- Audit all public KPM headers and exported symbols before changing the ABI.
  A compatibility shim may retain legacy RWX records for old KPM callers;
  strict W^X can only be claimed for the new backend until legacy use is
  eliminated.

## Newly confirmed initialization issue

`start.c` currently calls `hook_mem_add(_kp_hook_start, HOOK_ALLOC_SIZE)`
without checking its return value. A failed initialization must disable Hook
activation or abort KP initialization; continuing silently risks use of an
uninitialized allocator. This should be fixed independently of the arena
layout redesign.

## Release gate

No Hook permission change is approved by this audit. The split requires an
ABI migration, paired inline/FP Hook conversion, concurrency/lifetime tests,
branch-reach tests, cache-maintenance checks, and KIMG/linear-alias permission
verification. No device boot or runtime validation is claimed.
