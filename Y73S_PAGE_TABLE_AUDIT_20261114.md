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
