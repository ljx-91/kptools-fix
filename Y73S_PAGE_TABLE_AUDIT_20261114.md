# Y73S page-table descriptor audit — 2026-11-14

Target: vivo Y73s V2031A / PD2031, MT6853, Linux 4.14.141+.
Branch: `y73s-cred-layout-guards-20261108`.

## Finding: block descriptors must not be returned as leaf PTEs

The previous `get_or_create_pte()` walked the translation tables and, on an existing block descriptor (`Desc[1:0] == 0b01`), computed its output-address base and broke out of the walk. The caller then treated the returned entry address as a page descriptor and wrote a page-sized mapping into it. That would replace the larger block mapping, not update one page. Neighboring translations covered by that block could be lost or corrupted.

## Changes committed

- `kernel/base/map.c`: intermediate newly allocated levels now receive a table descriptor (`PA | 0x3`); only the final level receives the leaf-page attributes (`PA | attr_prot`).
- `kernel/base/map.c`: encountering an existing block descriptor now traps instead of returning its descriptor slot to a page-level writer. Block splitting is deliberately not implemented without a target-specific proof of descriptor attributes, table allocation, and mapping preservation.
- `scripts/verify_y73s_runtime_contract.py`: regression checks enforce both descriptor-level selection and fail-closed block handling.

Commits:
- `139a56cf84a9d0e0c33011dbe9cd7da562d87903` — descriptor construction and block guard.
- `7401feaa15a162a1f850ee7fa2d0312768c7c32d` — regression verifier.

## Consequences and limits

This is a safety hardening, not proof that the target path will boot. If the Y73S destination virtual range already contains a block mapping, this version will stop at the guard. The correct next step is to inspect the target's live TTBR1 page-table hierarchy for the exact destination VA range, or implement and test a block-splitting routine that preserves all relevant attributes. No target-device page-table dump is currently available.

This audit does not establish the physical RAM map, page-table memory attributes, TLB behavior on the target, or successful boot. Do not treat it as a flash-ready verdict. AVB remains outside this audit's scope by project direction.

## Additional finding: an existing leaf PTE must map the requested PA

A second correctness gap was found during the follow-up audit. At the final level, an existing page descriptor (Desc[1:0] == 0b11) was accepted and returned without checking its output address against the requested destination PA. The caller only adjusts descriptor permission bits; it does not rewrite the output address. If the VA already mapped a different physical page, the zero/copy loop could therefore write through the old mapping while believing it had mapped the newly allocated destination.

### Fix

- kernel/base/map.c: after the walk, require the final descriptor to be a page descriptor.
- For nonzero requested PA (the destination mapping path), compare the descriptor output address against the requested page-aligned PA and trap on mismatch.
- Preserve the existing pa == 0 lookup-only use used to read the kernel text AttrIndx; that path does not request a remapping.

Commits:
- 9287ce98541ab9f05d11136ed1a26b9491cad638 — validate existing leaf PTE output address.
- 755e550f27d4614e4191f5d5e4f32c356cbca6c5 — add source regression assertions.

This closes a static source-level mismatch hazard. It does not prove that the requested VA range is free of block descriptors or that the live TTBR1 hierarchy and physical RAM layout match the assumptions.
The leaf output-address guard also rejects requested PAs with any bits above bit 47, because the current descriptor OA mask and implementation support at most a 48-bit output address. The regression verifier checks this bound. Latest verifier adjustment: 228502831a208e0f82773f52119506f57b79c6cb.

## Follow-up: enforce the Y73S translation geometry

The runtime walker previously consumed TCR_EL1.T1SZ and TG1 but did not reject a geometry that differed from the target assumptions. For the audited Y73s kernel layout, the supported configuration is:

- TG1 == 0b10: 4-KiB translation granule.
- T1SZ == 25: 39-bit TTBR1 virtual-address space.
- page_shift == 12, va1_bits == 39.
- The kernel VA handled by this walker must be canonical in the TTBR1 39-bit half (va >> 39 == 0x1ffffff).

The Y73s path now fails closed if these conditions are not met. The page-level count is also range-checked before the walk. This prevents a different TCR configuration from silently reusing the Y73s-specific indexing assumptions.

## Follow-up: initialize child tables before publishing them

A further ordering issue was found in the intermediate-table allocation path. The old sequence wrote a valid parent Table Descriptor and only then zeroed the newly allocated child table. The sequence is now:

1. Allocate and reserve the child table.
2. Validate the physical-to-linear address conversion and the full table window.
3. Zero the entire child table.
4. Execute dsb ishst.
5. Publish the parent Table Descriptor through a volatile store.

The root TTBR1 table and each subsequently followed table descriptor also receive physical/linear address overflow checks before dereference.

Regression assertions in scripts/verify_y73s_runtime_contract.py now check the TCR geometry, canonical TTBR1 address, page-level bounds, child-table initialization/barrier/publication ordering, and table-address overflow guards.

These are source-level hardening changes. The target's live TTBR1 value, actual descriptor hierarchy, and real-device execution remain unverified; no flash-ready claim is made.

## Follow-up: do not force the optional DBM bit

The Y73S mapping permission update previously ORed bit 51 into every destination PTE. Bit 51 is the Dirty Bit Modifier (DBM) field; hardware dirty-state updates are optional and are identified by ID_AA64MMFR1_EL1.HAFDBS. Linux also enables TCR_EL1.HD only when the CPU feature is present and the reported HAFDBS level supports dirty-state updates.

The Y73S mapping update now clears AP[2] and PXN as required for the intended writable/executable kernel mapping, but does not force-set DBM. An existing descriptor's DBM state is preserved. This avoids imposing an optional hardware dirty-state feature on newly created mappings.

The runtime source verifier rejects reintroduction of the unconditional DBM bit. This is a descriptor-level compatibility hardening; it does not replace validation against the device's live ID_AA64MMFR1_EL1 and TCR_EL1 values.

## Follow-up: enforce EL1-only write permissions and validate existing leaves

A review of the inherited permission mask found that it cleared AP[2] (bit 7) but left AP[1] (bit 6) unchanged. AP[1] controls EL0 access. If an existing destination leaf had AP[1]=1, clearing only AP[2] could leave AP[2:1]=01 and retain EL0 access. The destination mapping must be EL1 read/write and EL0 inaccessible, so the mask now clears both AP[2:1] bits and PXN. It does not force-set DBM.

For an already-valid destination leaf, the walker now additionally requires:
- Output Address matches the requested physical page.
- AttrIndx matches the kernel text memory type used for the destination.
- AF is already set, avoiding an early access-flag fault.
- Contiguous hint is clear, because this mapper does not update a whole contiguous-descriptor group atomically.

These checks intentionally fail closed rather than silently modifying a mapping whose memory type or access semantics differ from the expected kernel mapping.

The rationale follows Arm's AArch64 memory attributes guide: AP, AttrIndx, AF and execution permissions are independent descriptor properties; AF=0 can produce an Access Flag fault when software-managed, and incompatible memory type/shareability aliases can behave incorrectly. This audit has not yet validated inherited APTable/PXNTable restrictions in every ancestor descriptor; that remains a separate item.

## Follow-up: reject restrictive ancestor table attributes

Arm's AArch64 memory attributes guide explains that access permissions and execute-never properties can be hierarchical: a table descriptor can impose restrictions that a leaf descriptor cannot undo. The TTBR1 walker now checks each non-leaf table descriptor and fails closed if APTable[1] (bit 62) forces read-only access or PXNTable (bit 59) prevents EL1 execution.

APTable[0] and UXNTable are not rejected by this check because they further restrict EL0 access/execution, which is consistent with the intended EL1-only kernel mapping. This remains a conservative source-level guard; the actual Y73S page-table hierarchy has not yet been captured from a running device.

Existing destination leaves are also required to be Inner Shareable (SH[1:0] == 0b11). The destination RAM can have a normal-memory linear-map alias, and Arm recommends compatible cacheability and shareability attributes for aliases of the same physical location. A non-Inner-Shareable pre-existing leaf is therefore rejected rather than silently reused.


## Follow-up: do not force PBHA on newly-created leaf mappings

A descriptor audit found that the former leaf template `0x40000000000703` set bit 62. For a final-level AArch64 stage-1 page descriptor, bits [62:59] are the PBHA / implementation-defined hardware-use field when FEAT_HPDS2 is implemented; bit 62 is not an ordinary page permission bit.

The Cortex-A76 and Cortex-A55 technical reference manuals both document HPDS value `0x2`, which supports handing final-level descriptor bits [62:59] to implementation-defined hardware use. Whether those bits are actually consumed depends on the active TCR controls, which have not been captured from the Y73S runtime.

### Fix

- `kernel/base/map.c`: new leaf descriptors now use `0x703 | attr_indx`, leaving PBHA[3:0] clear instead of forcing PBHA[3].
- Existing valid leaves retain their existing upper-attribute bits; this change does not rewrite or normalize an inherited mapping.
- `scripts/verify_y73s_runtime_contract.py`: regression assertion prevents reintroduction of the old PBHA-setting template.

This is a conservative descriptor compatibility fix. It does not prove the device's live HPD1/HWU settings, nor does it replace a target page-table dump or a real-device boot test.

References:
- Arm Cortex-A76 TRM, ID_AA64MMFR1_EL1.HPDS: https://www.easymanua.ls/arm/cortex-a76-core/manual?p=224
- Arm Cortex-A55 TRM, ID_AA64MMFR1_EL1.HPDS: https://documentation-service.arm.com/static/5e7e09f6a3736a0d2e862d2f
- Arm ID_AA64MMFR1_EL1 HPDS field description: https://www.df.lth.se/~getz/ARM/SysReg/AArch64-id_aa64mmfr1_el1.html


## Five-track follow-up (2026-11-15)

### 1. Runtime TCR / HPDS / PBHA diagnostics

The live Y73S `TCR_EL1` is now captured in `_paging_init` after the original `paging_init()` returns and passed as the fourth argument to relocated `start()`. The relocated start code also reads `ID_AA64MMFR1_EL1` and records:
- raw `TCR_EL1`
- `ID_AA64MMFR1_EL1.HPDS[15:12]`
- `TCR_EL1.HPD1[42]`
- `TCR_EL1.HWU162:HWU159[50:47]`

The boot log line is `Y73S TCR_EL1=... HPDS=... HPD1=... HWU159_162=...`. This is runtime instrumentation, not a claim that the current device's register values are already known. Arm's current register description states HWU162 is effective for TTBR1 bit 62 only when HPD1 is 1, and HPDS=2 identifies HPDS2 support. References: https://support.arm.com/documentation/111107/2026-09/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1- and https://support.arm.com/documentation/111107/2026-09/AArch64-Registers/ID-AA64MMFR1-EL1--AArch64-Memory-Model-Feature-Register-1

### 2. Linux 4.14 memblock API and fallback audit

The exact upstream Linux v4.14 sources were inspected:
- `MEMBLOCK_ALLOC_ACCESSIBLE == 0`; `memblock_find_in_range(0, 0, size, align)` therefore resolves its end to `memblock.current_limit` and excludes the first page.
- `memblock_virt_alloc_try_nid_nopanic(size, align, min_addr, max_addr, nid)` first tries the requested interval, but if it cannot allocate there it drops `min_addr` and retries from zero. On success it reserves the PA, converts it with `phys_to_virt()`, and zeroes the allocation.
- `memblock_reserve`, `memblock_free`, and `memblock_mark_nomap` return status codes; the current Y73S code checks the critical reserve/free/NOMAP results.
- The current probe's second `memblock_find_in_range(detect_phys, detect_phys + page_size, page_size, page_size)` detects whether the exact requested page remained free. A nonzero result fails closed rather than accepting the allocator's fallback VA/PA mismatch.

This validates the rationale of the existing fallback guard against upstream v4.14 semantics. The Vivo vendor kernel may contain local changes; exact vendor binary behavior still requires runtime confirmation. Reference: https://github.com/torvalds/linux/blob/v4.14/mm/memblock.c

### 3. Destination mapping / alias attributes

The destination mapping is created as a 4-KiB TTBR1 leaf using the kernel text AttrIndx, inner-shareable, AF set, EL1 RW / EL0 no-access, and EL1 executable while the relocation code runs. Existing mappings are checked for the expected output address and memory attributes; legal block descriptors are lookup-only and mapping requests fail closed rather than splitting or replacing a live block. New leaf descriptors leave PBHA[3:0] clear. The KPM executable allocator separately validates both KIMG and linear aliases before permission changes; writable linear block aliases are rejected, and only already-RO/PXN block aliases are accepted.

### 4. D-cache / I-cache ordering correction

A further early-boot correctness issue was found: `flush_icache_all()` invalidates I-cache but does not clean dirty D-cache lines to PoU. The C relocation path writes the restored `paging_init` instruction and copies the KP start image / extras into newly allocated cacheable memory. The previous code invalidated I-cache without first cleaning those writes.

The fix adds an inline, self-contained `clean_dcache_range_to_pou()` helper using `CTR_EL0.DminLine`, `dc cvau` for every touched line, and `dsb ish`. It now runs:
1. after restoring the original `paging_init` instruction and before I-cache invalidation / calling it;
2. after zeroing/copying the complete relocated allocation and before I-cache invalidation / branching into relocated KP code.

The runtime source verifier now enforces both orderings. This fix is not yet device-boot tested.

### 5. Rebuild and offline image validation

The latest source changes trigger four CI workflows: combined FolkPatch build/regressions, Linux kptools/source audit, Android ARM64 KPIMG, and Windows KPIMG/kptools. Only after all complete successfully should a new Boot be repacked from the exact stock image and latest KPIMG artifact, then compared byte-for-byte for ramdisk, DTB, vbmeta/footer placement and expected kernel payload changes. No AVB metadata is to be rewritten or re-signed.

### Evidence boundary

CI and static source contracts do not establish the actual Y73S runtime TCR/HPDS values, memblock map, TTBR1 page-table contents, or successful boot. Those require the instrumented boot log / ramoops or a controlled real-device test with the stock boot readily restorable.


## Offline Boot candidate built from the cache/TCR-instrumented KPIMG

Source commit used for this candidate: `9de668e952813384945ea8cf4ceedb4a94b3fcd3` (documentation-only follow-up commits do not change its source payload).

Inputs:
- Original stock Boot SHA-256: `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`
- KPIMG version: `0xd0a`, Android release ARM64, size 304,992 bytes.
- KPIMG file SHA-256: `f71c57d5cd230cdf45e788fb5066488f7f5dab73993cc1450d7ceb47cd6d776e`

Output:
- `y73s-stock-patched-dcache-tcr-9de668e.img`
- Size: 100,663,296 bytes.
- SHA-256: `0d36a81a4d499aedc6e94df205cf29ebe6e3607cf0eede93286f269deb332ff0`
- kptools re-unpack and `-l` report `patched=true`; embedded KPIMG reports `0xd0a`.
- KPIMG injection offset: `0x02d52000`, region size `0x4a760`.
- Embedded KPIMG bytes from offset `0x200` through the end match the CI KPIMG payload byte-for-byte. The 113 differing bytes are confined to the first `0x200` bytes, the per-image preset/header area.
- The embedded KPIMG contains the new `Y73S TCR_EL1=... HPDS=... HPD1=... HWU159_162=...` runtime diagnostic string.

Boot structure comparison:
- Android Boot Header v2 and 2048-byte page size retained.
- Ramdisk remains 777,508 bytes and is byte-for-byte identical (SHA-256 `f14df852dfc9d2dc7fe17edfbceedb564d616b19e2ace7ef0f633d94798065dc`).
- DTB remains 158,376 bytes and is byte-for-byte identical.
- Decompressed kernel grows from 47,517,708 to 47,826,912 bytes.
- Header kernel_size changes from 16,678,904 to 16,751,793 bytes.
- AVB footer remains v1.0; original_image_size moves from 17,618,944 to 17,692,672, vbmeta_offset from 17,620,992 to 17,694,720; vbmeta_size remains 1,472.
- Embedded vbmeta blob remains byte-for-byte identical, SHA-256 `5374b5d334a275eb682ec80f87345468e0994e0fa1c0c611d37196e062b6ed85`.
- The original Boot Hash Descriptor remains unchanged. Its original digest matches the stock image; recomputing the descriptor digest over the candidate yields `9e31e35ef2f078974ff589684caf4c8b4710b34c5062a5a4c3fc6249c5199ac6`, which does not match the stored OEM digest `36a3d398fc5a5350e1642f54584ebca8d06e20644e622993f9547e057467623c`.
- No AVB digest, vbmeta payload, or signature was changed or regenerated.

CI evidence for source commit `9de668e952813384945ea8cf4ceedb4a94b3fcd3`:
- Combined FolkPatch main build and Y73S regression test job: success (run 43622185940, job 132530098653).
- Linux kptools build and LKM/KPM source audit: success (run 43622186076).
- Android KPIMG build and Windows kptools build: success (run 43622185989).
- Separate Android KPIMG workflow was still queued at the time of this report (run 43622185966); the same KPIMG version was already built successfully by the combined and Windows workflows.
- Patch-only APK packaging in the combined workflow was still running (job 132530607064).

This is an offline candidate only. The new runtime TCR log has not yet been collected from the device. No flash or real-device boot test has been performed; do not treat the candidate as boot-verified or AVB-digest-valid.
