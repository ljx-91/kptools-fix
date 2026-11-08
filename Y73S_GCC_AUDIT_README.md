# Vivo Y73s KPIMG offline audit branch

This branch is isolated from the original audit branch. It adds source-level regression gates for the early memory-mapping path.

## Added in this branch

- `scripts/verify_y73s_runtime_contract.py` checks that the known-bad `memblock_alloc_try_nid` virtual-return fallback is not selected as a physical allocator.
- It checks that a `memblock_find_in_range` result is explicitly reserved before use.
- It checks that the Y73S linear-map probe occurs only after the original `paging_init()` returns, validates the exact-page allocation result, and checks release failure.
- It checks the main destination PA and intermediate page-table allocations before descriptors or memory copies are performed.
- The GCC 14.2 workflow runs this verifier alongside the existing memblock source contract, ELF stack-frame, and map-relocation checks.

## Limits and safety

These are source-level regression checks. They do not independently prove the vendor binary ABI, the target allocator's runtime behavior, successful device boot, APatch initialization, or root availability.

The KPIMG artifact is not a flashable boot image. AVB, boot-image repacking, Vivo boot-chain behavior, and real-device cold boot remain unverified. Do not flash an artifact solely because CI passes.

No Fastboot, partition write, boot/vbmeta modification, or device-side operation is part of this branch.

- The Y73S hotpatch callback no longer uses `num_online_cpus()`, `cpu_online_mask`, or `nr_cpu_ids`; it uses `stop_machine(..., NULL)`, preflights targets, snapshots original instructions, and attempts reverse rollback on failure.
- Hook install/uninstall now propagate patch errors. Trampoline storage is retained when rollback or restore state is uncertain.
- The latest GCC 14.2 run passed: https://github.com/ljx-91/kptools-fix/actions/runs/42474757991
