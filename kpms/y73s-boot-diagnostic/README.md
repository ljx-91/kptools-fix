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
  -T kpm -V paging-init -o boot-paging-diagnostic.img
```

The `paging-init` event occurs after KPIMG's early paging/memory setup and
KernelPatch's symbol initialization, when `patch()` dispatches the event. It
cannot diagnose failures that happen before that point. This artifact is for
offline validation only; do not flash or boot it without separately resolving
the device's AVB requirements and establishing a recovery path.
