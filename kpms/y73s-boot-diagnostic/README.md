# Y73s read-only startup diagnostic KPM

This KPM is intentionally passive. It installs no hooks, registers no callbacks,
does not alter kernel memory, and does not suppress panic or vendor security
checks. Its init callback prints the event name and KernelPatch version.

Build from the repository root:

```sh
make -C kpms/y73s-boot-diagnostic \
  TARGET_COMPILE=aarch64-none-elf- KP_DIR=../..
```

For an isolated diagnostic image, embed it with:

```sh
kptools patch boot.img -M kpms/y73s-boot-diagnostic/y73s-boot-diagnostic.kpm \
  -T kpm -V pre-kernel-init -o boot-pre-kernel-diagnostic.img
```

The Y73s `paging-init` hook runs inside `setup_arch()`, before Linux 4.14's
`mm_init()` initializes slab and vmalloc. The KPM loader and RELA transaction
use those allocators, so this branch deliberately skips KPM dispatch at
`paging-init` rather than risking an early-boot allocator fault. Use
`pre-kernel-init`: its hook is attached to `kernel_init`, which is spawned by
`rest_init()` after `mm_init()` has completed. This still runs before the
`kernel_init()` body and records the startup event without relying on an
uninitialized allocator. The artifact is for offline validation only; do not
flash or boot it without separately resolving AVB requirements and establishing
a recovery path.
