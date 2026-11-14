# Y73S executable KPM allocator and W^X implementation audit

Date: 2026-11-14
Branch: `y73s-cred-layout-guards-20261108`
Validated source revision: `df2b33410baf13e3300dda976db34d4011ecb201`

## Scope

This phase replaces the TLSF pool previously used for executable KPM images with a page-run allocator and adds page-granular permissions for loaded module images. It does not change AVB, vbmeta, boot-image signing, or device flashing.

## Allocator

- The 4-MiB executable arena is managed as at most 1024 4-KiB pages.
- The allocator state, per-page run metadata, flags, and temporary PTE pointer arrays are allocated from `kp_rw_mem`; no allocator metadata is stored inside executable module pages.
- Allocation is contiguous and page-aligned. `kp_memalign_exec` supports power-of-two alignment.
- The page-state encoding distinguishes free pages, run heads, continuation pages, and in-progress permission transitions.
- Free accepts only the exact allocation base and verifies the complete continuation run. Interior, duplicate, malformed, and out-of-range frees are rejected.
- Reallocation is refused for finalized module images. For ordinary, not-yet-finalized allocations, the move-copy path copies outside the IRQ-safe allocator lock.
- Free first restores the entire allocation to RW-NX. If permission reset fails, the run remains reserved and is reported rather than being reused.

## Module image layout and permissions

The module loader's existing section layout page-aligns the end of executable sections (`text_size`) and the end of read-only sections (`ro_size`). The end of the writable segment is page-aligned before the appended symbol and string tables. This phase records that boundary as `symtab_start`.

After relocation and instruction-cache maintenance, the image is finalized as:

| Image range | KIMG mapping |
|---|---|
| `[0, text_size)` | RX |
| `[text_size, ro_size)` | R-NX |
| `[ro_size, symtab_start)` | RW-NX |
| `[symtab_start, align_up(size, 4 KiB))` | R-NX |

The image is not published to the module registry or allowed to run its init callback until the permission transition succeeds. A failed transition aborts loading; the free path attempts to restore the allocation to RW-NX before reuse.

## KIMG and linear aliases

Permission updates are not made from a name-only assumption about virtual addresses:

- The KIMG mapping must resolve to 4-KiB leaf PTEs.
- Every KIMG leaf is checked for the expected physical output address, kernel-text AttrIndx, Inner Shareable attributes, AF, and absence of a contiguous hint.
- When KIMG and linear offsets differ, the linear alias is also checked against the same physical page.
- A linear alias implemented with leaf PTEs is updated to the matching permission.
- A linear alias implemented with a block descriptor is accepted only when the descriptor maps the exact expected physical address, has matching memory attributes/shareability and AF, and is privileged-XN. Such a block is not split or rewritten; it remains NX.
- Ancestor APTable[1] and PXNTable restrictions, unsupported translation geometry, missing mappings, and unexpected executable block aliases fail closed.

**Important limitation:** when the linear alias is a privileged-XN block mapping, it is left unchanged. It is non-executable, but may remain writable. Thus this phase enforces no writable+executable virtual alias and applies RX/R-NX/RW-NX to the KIMG module mapping; it does not claim strict physical write-protection across a writable linear alias. Splitting kernel linear-map blocks is intentionally out of scope until the target's live page-table layout is known.

The existing Hook arena remains a separate RWX region because trampoline generation writes there. This phase does not claim that all KernelPatch memory is globally W^X.

## Instruction-cache coherency

After symbol simplification and relocations, the loader now calls `flush_icache_range(start, start + text_size)` to clean modified text from D-cache to PoU and invalidate the local I-cache range, then `flush_icache_all()` to broadcast I-cache invalidation before changing text pages to RX and invoking module init.

The global I-cache invalidation alone does not perform the required D-cache clean.

## Verification

Regression coverage: `scripts/test_y73s_exec_allocator.py`

The test checks source wiring and fail-closed guards and exercises a deterministic allocator model for:
- 1024-page exhaustion and fragmentation;
- contiguous allocation and alignment;
- interior and duplicate free rejection;
- in-place growth/shrink and moved realloc;
- non-overlap under deterministic mixed allocation/free operations;
- W^X permission classes and alias validation source contracts.

Target toolchain build: GitHub Actions run [43563634485](https://github.com/ljx-91/kptools-fix/actions/runs/43563634485), using Arm GNU GCC 14.2, completed successfully at revision `df2b33410baf13e3300dda976db34d4011ecb201`. The allocator model test, KPIMG build, early cache-maintenance audit, stack-frame audit, mapping relocation audit, and KPM loader source contract all passed.

Built audit artifact hashes:
- `kpimg-android`: `a6aa31504d3e43074116b49cf1c5c61968d65500f5e2d1f27a20f1c0c83b7c10`
- `kpimg-android.elf`: `4e3eee6674c293287a7876b1565afd9fbe0cdfacc0e26862796ae94b39c41148`

## Not verified

- No live Y73s boot has been performed with this KPIMG.
- The runtime result of `kp_exec_allocator_init()` and the actual KIMG/linear PTE shapes are unknown until early-boot diagnostics are captured.
- The CI allocator test is a deterministic host model plus source-contract assertions; it is not a host execution of the kernel C allocator.
- A successful toolchain build does not prove the device boots, that the linear alias is NX on the target, or that a KPM module loads and executes correctly.

Do not flash this artifact as a boot image. Do not treat it as a device-validated image.
