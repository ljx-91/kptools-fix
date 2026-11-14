/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
/* map_data_t offsets; guarded by matching C static assertions in setup.h. */
#define map_paging_init_relo_offset 64
#ifdef MAP_DEBUG
#define map_page_shift_offset 184
#define map_kimage_voffset_offset 192
#define map_linear_voffset_offset 200
#else
#define map_page_shift_offset 136
#define map_kimage_voffset_offset 144
#define map_linear_voffset_offset 152
#endif

    .text
    .align  2
    .global map_start_call
    .type   map_start_call, %function
map_start_call:
    str     x30, [sp, #-16]!
    mov     x9, x0
    ldr     x16, [x9, #map_paging_init_relo_offset]
    ldr     x0, [x9, #map_kimage_voffset_offset]
    ldr     x1, [x9, #map_linear_voffset_offset]
    ldr     x2, [x9, #map_page_shift_offset]
    blr     x16
    ldr     x30, [sp], #16
    ret
    .size   map_start_call, .-map_start_call
