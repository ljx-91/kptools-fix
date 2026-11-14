/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

// todo: 
    .text
    .align  2
    .global map_start_call
    .type   map_start_call, %function
map_start_call:
    stp     x29, x30, [sp, #-16]!
    adrp    x16, map_start_target
    add     x16, x16, :lo12:map_start_target
    ldr     x16, [x16]
    adrp    x9, map_start_arg0
    add     x9, x9, :lo12:map_start_arg0
    ldr     x0, [x9]
    adrp    x9, map_start_arg1
    add     x9, x9, :lo12:map_start_arg1
    ldr     x1, [x9]
    adrp    x9, map_start_wxn
    add     x9, x9, :lo12:map_start_wxn
    ldr     x2, [x9]
    blr     x16
    ldp     x29, x30, [sp], #16
    ret
    .size   map_start_call, .-map_start_call
