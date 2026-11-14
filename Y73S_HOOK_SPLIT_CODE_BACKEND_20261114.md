# Y73s split Hook control/code backend migration

Date: 2026-11-14  
Target: vivo Y73s V2031A / PD2031, MT6853, Linux 4.14.141+  
Branch: `y73s-cred-layout-guards-20261108`

## Implementation

The internal Hook manager no longer executes code from its Hook arena.

- The 1 MiB Hook arena is mapped RW-NX and remains the storage area for the existing Hook control records.
- `hook_mem_warp_t` tracks separate executable allocations for relocated inline-hook code and generated transit stubs.
- Relocated inline-hook instructions are generated using their final executable address, copied into a page-run allocation, cache-flushed, and sealed RX before the origin is patched.
- Inline Hook and Function Pointer Hook transit stubs are each allocated from the executable page-run allocator, populated with the chain pointer and resident transit branch, cache-flushed, and sealed RX before publication.
- The executable allocator's new `kp_exec_seal()` operation changes a complete allocation to RX using its existing KIMG/linear-alias permission manager. Freeing an unpublished allocation returns it to RW-NX before release.
- The new backend passes the executable transit pointer as `replace_addr`; it no longer derives a chain owner with `container_of(transit, ...)`.

## ABI compatibility

No public structure fields, offsets, or sizes were changed:

- `hook_chain_t.transit[TRANSIT_INST_NUM]` remains present.
- `fp_hook_chain_t.transit[TRANSIT_INST_NUM]` remains present.
- `hook_t`, `fp_hook_t`, callback argument structures, exported Hook function signatures, and the 0/4/8/12 argument dispatch classes remain unchanged.
- The legacy embedded transit arrays are retained as ABI compatibility storage but are not used as executable storage by the new internal `hook_wrap` / `fp_hook_wrap` backend.
- The 12-argument callback and trampoline layouts remain unchanged.

This preserves the public binary layout; it does not prove compatibility with every third-party KPM. A KPM that relied on undocumented assumptions about the old internal `replace_addr` value or directly executed its own embedded transit buffer must be tested separately. The legacy public structure/API path is not silently reinterpreted as a W^X-safe external code allocator.

## Concurrency and delayed reclamation

Callback owner pinning, reader accounting, slot retirement, and the existing remove/retry behavior are retained.

Executable pages are released only for a record still in the unpublished construction state. Once a record is published and later retired, its executable pages remain quarantined with the retired record. This is deliberate: `active_readers` is incremented after entering the transit routine and alone cannot prove that no CPU has already fetched the patched branch but has not yet reached that increment. Without a proven system-wide grace-period mechanism, reclaiming the transit or relocation page would create a use-after-free race.

This is safe retention, not full reclamation. Repeated hook/unhook cycles consume the finite Hook-record and executable-page arenas. A later reclamation optimization must first add and validate a real grace-period protocol; it must not free retired code merely because `active_readers == 0`.

## Failure behavior

- Failure to allocate a code page, register it with the constructing record, prepare the stub, or seal it RX aborts the unpublished Hook setup.
- The failure path releases any tracked unpublished executable pages.
- Uncertain patch outcomes keep the record and executable code published, matching the existing fail-safe behavior.
- If the executable allocator did not initialize, Hook creation fails with the existing no-memory/transit error path; no RWX fallback is attempted.

## Validation added

`scripts/verify_y73s_hook_init_fail_closed.py` now checks:

- RW-NX Hook control arena;
- separate relocation and transit allocations;
- RX sealing for Inline and Function Pointer paths;
- unchanged public chain layouts and 12-argument API;
- removal of transit-owner `container_of`;
- unpublished cleanup and conservative retired-code retention;
- reader/callback pinning and all four ABI dispatch entry points.

The check is included in the Y73s ARM64 KPIMG build workflow.

## Validation added

`scripts/verify_y73s_hook_init_fail_closed.py` now checks:

- RW-NX Hook control arena;
- separate relocation and transit allocations;
- RX sealing for Inline and Function Pointer paths;
- unchanged public chain layouts and 12-argument API;
- removal of transit-owner `container_of`;
- unpublished cleanup and conservative retired-code retention;
- reader/callback pinning and all four ABI dispatch entry points;
- integer literal relocation loads from the correct literal slot;
- SIMD/PRFM literal relocation loads from the correct literal slot and restores X16/X17 plus SP.

A second-round instruction audit found and fixed two relocation defects in `relo_ldr()`:

- Integer literal loads used `LDR Xt, #12`, which addressed the intervening NOP rather than the literal at `+16`; this is now encoded as `0x58000080 | Rt` (`LDR Xt, #16`).
- SIMD/PRFM literal loads used `LDR X17, #16`, which addressed the NOP rather than the literal at `+20` from that instruction; this is now `0x580000B1` (`LDR X17, #20`). The old restore instruction decoded as `LDUR X17, [SP, #-8]`, leaving the stack frame unbalanced and X16 unrestored; it is now `0xA8C147F0` (`LDP X16, X17, [SP], #16`).

The corrected instruction words were assembled/disassembled with the AArch64 LLVM toolchain, and the static regression checks passed in the Y73s KPIMG workflow.

## Validation status

- ARM GNU GCC 14.2 Y73s KPIMG build and audit completed successfully: [workflow run 43568926760](https://github.com/ljx-91/kptools-fix/actions/runs/43568926760).
- Linux kptools host build and source audit completed successfully: [workflow run 43568926767](https://github.com/ljx-91/kptools-fix/actions/runs/43568926767).
- The current static contract suite reports 24 passing Y73s split-Hook checks.

Static source contracts and targeted instruction-word disassembly are not a substitute for:

- disassembly inspection of every generated transit and relocated-code path;
- stress testing concurrent hook removal while callbacks are executing;
- testing third-party KPM binaries against the unchanged public layouts;
- booting and exercising the resulting image on the physical Y73s.

No AVB changes are included. No claim of device boot success is made.
