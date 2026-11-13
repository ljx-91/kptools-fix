#!/usr/bin/env python3
"""Check that setup1.S rejects malformed Y73S preset ranges before copying kernel bytes."""
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    source = Path("kernel/base/setup1.S").read_text()
    require("start_prepare:" in source, "missing start_prepare")
    begin = source.index("start_prepare:")
    end = source.index("\n.text", begin)
    body = source[begin:end]

    map_area = body.index("// backup map area")
    first_map_copy = body.index("bl memcpy8", map_area)
    first_relocation_copy = body.index("bl rmemcpy32")

    # KPIMG size must include its setup prefix, and the copied start image
    # must fit the linker-reserved start region before any kernel backup.
    checks_before_kernel_access = [
        "ldr x22, [x10, #setup_kpimg_size_offset]",
        "cmp x22, x23",
        "b.lo .bad_paging_init",
        "sub x22, x22, x23",
        "cmp x22, x23",
        "b.hi .bad_paging_init",
        "tst x22, #0xf",
        "b.ne .bad_paging_init",
    ]
    first_kernel_access = first_map_copy
    for item in checks_before_kernel_access:
        pos = body.find(item)
        require(pos >= 0 and pos < first_kernel_access,
                f"missing or late early-preset check: {item}")

    # Extra data must be nonnegative/aligned, and the total backward copy
    # must be aligned and remain inside the enlarged kernel Image footprint.
    for item in [
        "ldr x3, [x10, #setup_extra_size_offset]",
        "tbnz x3, #63, .bad_paging_init",
        "tst x3, #0xf",
        "adds x4, x22, x3",
        "tst x4, #3",
        "ldr x5, [x10, #setup_kernel_size_offset]",
        "cmp x4, x5",
        "adds x5, x19, x21",
    ]:
        pos = body.find(item)
        require(pos >= 0 and pos < first_kernel_access,
                f"missing or late copy-size validation: {item}")

    # map_backup has a fixed destination buffer and a kernel-relative source.
    map_checks = body[map_area:first_map_copy]
    for item in [
        "cmp x2, #MAP_MAX_SIZE",
        "ldr x4, [x10, #setup_kernel_size_offset]",
        "cmp x20, x4",
        "sub x4, x4, x20",
        "cmp x2, x4",
        "adds x4, x19, x20",
        "b.cs .bad_paging_init",
    ]:
        require(item in map_checks, f"missing map-backup bound: {item}")

    # The final early relocation copy may only happen after all preflight checks.
    require(body.index("str x22, [x9, #map_start_img_size_offset]") < first_relocation_copy,
            "start_img_size is not committed before the relocation copy")
    require("brk #0" in source[source.index(".bad_paging_init:"):],
            "invalid preset must fail closed")
    print("[PASS] Y73S setup preset bounds are checked before kernel-memory copies")


if __name__ == "__main__":
    main()
