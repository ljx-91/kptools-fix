#!/usr/bin/env python3
"""Check Y73S setup preset guards against the actual appended-Image layout."""
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def align_up(value, align):
    return (value + align - 1) & ~(align - 1)


def main():
    source = Path("kernel/base/setup1.S").read_text()
    patcher = Path("tools/patch.c").read_text()
    require("start_prepare:" in source, "missing start_prepare")
    begin = source.index("start_prepare:")
    end = source.index("\n.text", begin)
    body = source[begin:end]

    map_area = body.index("// backup map area")
    first_map_copy = body.index("bl memcpy8", map_area)
    first_relocation_copy = body.index("bl rmemcpy32")
    preflight = body[:map_area]

    # KPIMG size must include its setup prefix; the copied start payload must
    # fit the linker-reserved destination before any kernel-memory access.
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
    for item in checks_before_kernel_access:
        require(item in preflight, f"missing early-preset check: {item}")

    # The patcher stores the original Image.image_size in setup_kernel_size,
    # but appends the temporary copy at start_offset >= that original size.
    # The expanded Image.image_size is computed separately from start_offset,
    # kpimg_len and extra_size. Never compare the appended range against the
    # original setup_kernel_size (that would reject every normal Y73S image).
    require("setup->kernel_size = kinfo->kernel_size;" in patcher,
            "preset kernel_size no longer records the original Image size")
    require("setup->start_offset = start_offset;" in patcher,
            "preset start_offset assignment changed")
    require("uint64_t image_size64 = align_ceil((uint64_t)start_offset + (uint64_t)kpimg_len + extra_size64, SZ_4K);" in patcher,
            "patcher no longer declares the appended Image footprint")
    for item in [
        "ldr x3, [x10, #setup_extra_size_offset]",
        "tbnz x3, #63, .bad_paging_init",
        "tst x3, #0xf",
        "adds x4, x22, x3",
        "b.cs .bad_paging_init",
        "tst x4, #3",
        "ldr x21, [x10, #setup_start_offset_offset]",
        "tbnz x21, #63, .bad_paging_init",
        "tst x21, #0xfff",
        "adds x5, x19, x21",
        "adds x5, x5, x4",
    ]:
        require(item in preflight, f"missing appended-range validation: {item}")
    require("ldr x5, [x10, #setup_kernel_size_offset]" not in preflight,
            "original kernel_size is incorrectly used to bound the appended copy")
    require(preflight.index("adds x5, x19, x21") < first_map_copy,
            "destination arithmetic validation occurs after kernel access")

    # Regression fixture from the exact Y73S boot preset captured from the
    # failed device image. The old Image size equals start_offset; the valid
    # appended copy is covered only by the enlarged Image.image_size.
    original_image_size = 0x389D000
    start_offset = 0x389D000
    kpimg_size = 0x4A750
    setup_prefix = 0x3000
    extra_size = 0x80
    copied_start_size = kpimg_size - setup_prefix
    copied_total = copied_start_size + extra_size
    enlarged_image_size = align_up(start_offset + kpimg_size + extra_size, 0x1000)
    require(start_offset == original_image_size,
            "regression fixture no longer models the captured Y73S preset")
    require(original_image_size - start_offset < copied_total,
            "fixture must fail the old original-Image-size bound")
    require(start_offset + copied_total <= enlarged_image_size,
            "captured appended copy exceeds the enlarged Image footprint")

    # The map backup remains inside the original kernel Image and its fixed
    # destination buffer; this is a different range and may use kernel_size.
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

    require(body.index("str x22, [x9, #map_start_img_size_offset]") < first_relocation_copy,
            "start_img_size is not committed before the relocation copy")
    require("brk #0" in source[source.index(".bad_paging_init:"):],
            "invalid preset must fail closed")
    print("[PASS] Y73S setup preset bounds match the appended-Image layout")


if __name__ == "__main__":
    main()
