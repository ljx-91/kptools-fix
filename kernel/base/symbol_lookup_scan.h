/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SYMBOL_LOOKUP_SCAN_H_
#define _KP_SYMBOL_LOOKUP_SCAN_H_

#include <kallsyms.h>

typedef int (*kp_symbol_scan_sprintf_t)(char *buf, const char *fmt, ...);

static inline int kp_symbol_scan_strcmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;

    while (1) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch) break;
    }
    return d;
}

static inline char *kp_symbol_scan_strchr(char *s, int c)
{
    do {
        if (*s == (char)c) return s;
    } while (*s++);
    return 0;
}

static inline int kp_symbol_scan_parse_hex(const char *s, unsigned long *value)
{
    unsigned long v = 0;
    int n = 0;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (1) {
        char ch = *s++;
        if (ch >= '0' && ch <= '9') {
            v = (v << 4) + (unsigned long)(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            v = (v << 4) + (unsigned long)(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            v = (v << 4) + (unsigned long)(ch - 'A' + 10);
        } else {
            break;
        }
        n++;
    }
    *value = v;
    return n > 0;
}

static inline int kp_symbol_scan_parse_info(char *buf, unsigned long *offset, unsigned long *size)
{
    char *plus = kp_symbol_scan_strchr(buf, '+');
    char *slash;

    if (!plus) return 0;
    *plus++ = 0;

    slash = kp_symbol_scan_strchr(plus, '/');
    if (slash) {
        *slash++ = 0;
    }

    if (!kp_symbol_scan_parse_hex(plus, offset)) return 0;
    if (!slash) {
        *size = 0;
        return 1;
    }
    return kp_symbol_scan_parse_hex(slash, size);
}

#define KP_SYMBOL_SCAN_MAX_STEPS 8192

static inline unsigned long kp_resolve_symbol_by_lookup_anchor(unsigned long kernel_va, unsigned long image_size,
                                                               unsigned long sprintf_offset,
                                                               unsigned long anchor_offset, const char *name)
{
    char buf[KSYM_NAME_LEN + 64];
    unsigned long addr;
    unsigned long func_start;
    unsigned long func_end;
    unsigned long offset;
    unsigned long size;
    unsigned long anchor_addr;
    unsigned long sprintf_addr;
    unsigned long kernel_end;
    kp_symbol_scan_sprintf_t kernel_sprintf;

    if (!anchor_offset || !sprintf_offset || !image_size ||
        anchor_offset >= image_size || sprintf_offset >= image_size) return 0;

    kernel_end = kernel_va + image_size;
    if (kernel_end < kernel_va) return 0;

    anchor_addr = kernel_va + anchor_offset;
    sprintf_addr = kernel_va + sprintf_offset;
    if (anchor_addr < kernel_va || anchor_addr >= kernel_end ||
        sprintf_addr < kernel_va || sprintf_addr >= kernel_end) return 0;

    kernel_sprintf = (kp_symbol_scan_sprintf_t)sprintf_addr;
    addr = anchor_addr;

    /*
     * Linux kallsyms reports a symbol's size up to the next distinct address.
     * Query the exact end address to visit the next symbol. Adding another
     * instruction skips 4-byte symbols, which are common in the Y73s vendor
     * kernel's kallsyms table (including entries immediately before
     * kallsyms_lookup_name).
     */
    for (int i = 0; i < KP_SYMBOL_SCAN_MAX_STEPS && addr >= anchor_addr && addr < kernel_end; i++) {
        kernel_sprintf(buf, "%pSb", (void *)addr);
        if (!kp_symbol_scan_parse_info(buf, &offset, &size) || !size || offset > addr - kernel_va) break;

        func_start = addr - offset;
        if (func_start < kernel_va || func_start >= kernel_end ||
            size > kernel_end - func_start) break;

        if (!kp_symbol_scan_strcmp(buf, name)) {
            return func_start - kernel_va;
        }

        func_end = func_start + size;
        if (func_end <= addr || func_end <= func_start) break;
        addr = func_end;
    }

    return 0;
}
#endif
