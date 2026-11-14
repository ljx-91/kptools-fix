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
