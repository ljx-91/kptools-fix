# Y73S KPIMG relocation and stack-handoff audit — 2026-11-14 (round 2)

Target: vivo Y73s V2031A / PD2031, MT6853, stock Linux 4.14.141+.
Branch: `y73s-cred-layout-guards-20261108`.
Audited build: local `kpimg-android.elf` generated for the Y73S target; SHA256 is recorded in the accompanying build artifact manifest.

## 1. Exact _paging_init/start stack handoff — PASS for this ELF

Disassembly of the current ELF shows:

- `_paging_init` begins with `stp x29, x30, [sp, #-0x130]!` followed by `mov x29, sp`.
- Callee-saved pairs are stored at `sp+0x10`, `+0x20`, `+0x30`, `+0x40`, and `+0x50` for x19/x20 through x27/x28.
- `start`'s tail handoff loads the prior frame record from `[x29]`, restores those five pairs from the matching slots, restores x29/x30 from the frame record, sets SP to frame address + `0x130`, then returns.
- The observed instructions match `scripts/verify_kpimg_elf_stack_frame.py`'s expected contract.

This is a binary-specific pass, not a guarantee for future compiler/toolchain builds. Every produced KPIMG must continue to pass the ELF stack-frame verifier.

## 2. Relocated start image sizing — linker arithmetic consistent

Current ELF linker symbols:

- `_link_base = 0xd000`
- `_kp_start = 0x10000`
- `_kp_end = _link_end = 0x60000`

Therefore the linked start payload is `_kp_end - _kp_start = 0x50000`. The setup logic computes `start_img_size = kpimg_size - (_kp_start - _link_base)`; with the linked KPIMG extent ending at `_kp_end`, this yields the same `0x50000`. The runtime destination layout reserves `start_size + ALIGN(extra_size) + alloc_size`, copies the start image at offset 0 and extra data at offset `start_size`. The current linker layout therefore does not show a start-image/extra-data overlap.

This depends on the preset's `kpimg_size` matching the actual linked KPIMG extent. A corrupted or stale preset should be rejected; the runtime currently validates nonnegative sizes and arithmetic overflow but does not explicitly assert `start_img_size <= start_size` (or equality). Add that explicit invariant in a future hardening change, and enforce it in the host-side preset verifier.

## 3. Relocation / release ordering — static review

Observed sequence in `_paging_init`:

1. Reserve the old start image plus extra range.
2. Allocate and reserve the destination physical range.
3. Mark the destination range NOMAP and create the destination kernel-image VA mapping.
4. Run the original `paging_init()`, then derive the Y73S linear-map offset.
5. Copy the start image and extra data into the destination.
6. Flush instruction cache.
7. Free the old start image range.
8. Branch to the relocated `start()` entry.

The currently executing `_paging_init` code is in the copied map region, not in the old start payload. The active kernel stack is the caller's kernel stack; the new `start()` uses that stack and explicitly restores the suspended `_paging_init` frame before returning to its caller. The map anchor is restored by `restore_map()` while the KP start image is executing, and the tail handoff bypasses the overwritten map-function epilogue.

This ordering is internally consistent under the audited linker/runtime assumptions. It is not runtime proof: we do not have a live MT6853 memblock dump, page-table dump, or successful boot trace for this exact patched image.

## 4. Remaining checks / hardening

- Add explicit preset invariant `start_img_size <= start_size` (prefer equality for the current linker contract), and verify `kpimg_size` against the actual image extent before patching.
- Verify the actual Y73s memblock range and that `memblock_virt_alloc_try_nid_nopanic(size, align, detect_phys, detect_phys + page_size, NUMA_NO_NODE)` returns a VA for the exact reserved physical page. Source checks already reject allocator fallback by querying whether the requested page remains free.
- Runtime page-table attributes, TLB/cache coherency, and physical RAM coverage still require target-device evidence.
- Do not treat this audit as a green light to flash. No device boot success is claimed. AVB is intentionally outside this audit's acceptance scope, per project direction.
