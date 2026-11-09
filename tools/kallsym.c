/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "bootimg.h"
#include "kallsym.h"
#include "order.h"
#include "insn.h"
#include "common.h"
#include "preset.h"

#define IKCFG_ST "IKCFG_ST"
#define IKCFG_ED "IKCFG_ED"
#include "zlib.h"

/*
 * Fail closed when the stripped kernel does not provide enough evidence to
 * identify the kallsyms address table.  This is especially important for
 * older Android 4.14 vendor kernels with CONFIG_KALLSYMS_ALL=n, where a
 * guessed symbol count can make the vector heuristic accept a false table.
 * Define KP_STRICT_KALLSYMS=0 only for a deliberate compatibility bisect.
 */
#ifndef KP_STRICT_KALLSYMS
#define KP_STRICT_KALLSYMS 1
#endif

int find_ikconfig_blob(char *img, int32_t imglen, size_t *start, size_t *size)
{
    if (!img || imglen <= 0 || !start || !size) return -1;

    char *pos_start = memmem(img, (size_t)imglen, IKCFG_ST, strlen(IKCFG_ST));
    if (!pos_start) return 1;

    size_t kcfg_start = (size_t)(pos_start - img) + strlen(IKCFG_ST);
    if (kcfg_start > (size_t)imglen) return 2;
    char *pos_end = memmem(img + kcfg_start, (size_t)imglen - kcfg_start,
                           IKCFG_ED, strlen(IKCFG_ED));
    if (!pos_end) return 2;

    while (kcfg_start < (size_t)imglen &&
           (img[kcfg_start] == '\0' || img[kcfg_start] == '\n')) {
        kcfg_start++;
    }

    size_t kcfg_bytes = (size_t)(pos_end - (img + kcfg_start));
    if (!kcfg_bytes) return 3;

    *start = kcfg_start;
    *size = kcfg_bytes;
    return 0;
}

int find_linux_banner(kallsym_t *info, char *img, int32_t imglen, void *opt)
{
    /*
     * A vendor kernel image can contain multiple copies of linux_banner.
     * Keep only the last four offsets, matching the fixed metadata capacity.
     */
    if (!info || !img || imglen <= 0) return -1;

    int32_t *kver = (int32_t *)opt;
    static const char linux_banner_prefix[] = "Linux version ";
    const size_t prefix_len = sizeof(linux_banner_prefix) - 1;
    char *imgend = img + imglen;
    char *search = img;

    info->banner_num = 0;
    while (search < imgend) {
        char *banner = (char *)memmem(search, (size_t)(imgend - search),
                                      linux_banner_prefix, prefix_len);
        if (!banner) break;

        size_t remaining = (size_t)(imgend - banner);
        if (remaining > prefix_len + 1 &&
            isdigit((unsigned char)banner[prefix_len]) &&
            banner[prefix_len + 1] == '.') {
            int32_t slot;
            if (info->banner_num < (int32_t)ARRAY_SIZE(info->linux_banner_offset)) {
                slot = info->banner_num++;
            } else {
                memmove(info->linux_banner_offset, info->linux_banner_offset + 1,
                        (ARRAY_SIZE(info->linux_banner_offset) - 1) *
                            sizeof(info->linux_banner_offset[0]));
                slot = (int32_t)ARRAY_SIZE(info->linux_banner_offset) - 1;
            }
            info->linux_banner_offset[slot] = (int32_t)(banner - img);
            if (!kver)
                tools_logi("linux_banner %d offset: 0x%lx\n",
                           info->banner_num, (unsigned long)(banner - img));
        }
        search = banner + 1;
    }

    if (!info->banner_num) {
        tools_loge("no valid linux_banner in image\n");
        return -1;
    }

    char *banner = img + info->linux_banner_offset[info->banner_num - 1];
    char *uts_release_start = banner + prefix_len;
    char *space = (char *)memchr(uts_release_start, ' ',
                                 (size_t)(imgend - uts_release_start));
    if (!space) {
        tools_loge("linux_banner release string is not terminated inside image\n");
        return -1;
    }

    size_t release_len = (size_t)(space - uts_release_start);
    char release[128];
    if (!release_len || release_len >= sizeof(release)) {
        tools_loge("linux_banner release string has invalid length\n");
        return -1;
    }
    memcpy(release, uts_release_start, release_len);
    release[release_len] = '\0';

    char *cursor = release;
    char *end = NULL;
    unsigned long major = strtoul(cursor, &end, 10);
    if (end == cursor || *end != '.' || major > UINT8_MAX) return -1;
    cursor = end + 1;

    if (!isdigit((unsigned char)*cursor)) return -1;
    unsigned long minor = strtoul(cursor, &end, 10);
    if (end == cursor || *end != '.' || minor > UINT8_MAX) return -1;
    cursor = end + 1;

    if (!isdigit((unsigned char)*cursor)) return -1;
    unsigned long patch = strtoul(cursor, &end, 10);
    if (end == cursor || (*end && *end != '+' && *end != '-')) return -1;

    info->version.major = (uint8_t)major;
    info->version.minor = (uint8_t)minor;
    info->version.patch = patch <= UINT8_MAX ? (uint8_t)patch : UINT8_MAX;
    if (kver)
        *kver = (info->version.major << 16) |
                (info->version.minor << 8) | info->version.patch;

    if (!kver)
        tools_logi("kernel version major: %d, minor: %d, patch: %d\n",
                   info->version.major, info->version.minor, info->version.patch);
    return 0;
}

static int dump_kernel_config(kallsym_t *info, char *img, int32_t imglen)
{
    // todo:
    /*
  kernel configuration
  when CONFIG_IKCONFIG is enabled
  archived in GZip format between the magic string 'IKCFG_ST' and 'IKCFG_ED' in
  the built kernel.
  */
    tools_logw("not implemented\n");
    return 0;
}

static int find_token_table(kallsym_t *info, char *img, int32_t imglen, void *opt)
{
    char nums_syms[20] = { '\0' };
    char letters_syms[20] = { '\0' };
    char *imgend;
    char *pos;
    char *num_start = NULL;
    char *token_pos;
    int32_t offset;

    if (!info || !img || imglen <= (int32_t)(sizeof(nums_syms) + 2)) {
        tools_loge("invalid image for kallsyms token table\n");
        return -1;
    }
    imgend = img + imglen;

    for (int32_t i = 0; i < 10; i++) {
        nums_syms[i * 2] = '0' + i;
        letters_syms[i * 2] = 'a' + i;
    }

    /*
     * Locate the numeric tokens, then verify the expected alphabetic
     * sequence without ever probing beyond the supplied image.
     */
    pos = img;
    while (pos < imgend) {
        char *num_end;
        char *letter;
        int32_t zero_count = 0;

        num_start = (char *)memmem(pos, imgend - pos, nums_syms, sizeof(nums_syms));
        if (!num_start) {
            tools_loge("find kallsyms token_table error\n");
            return -1;
        }

        num_end = num_start + sizeof(nums_syms);
        if (imgend - num_end < 2 || !*num_end || !*(num_end + 1)) {
            pos = num_start + 1;
            continue;
        }

        letter = num_end;
        while (letter < imgend && zero_count < 'a' - '9' - 1) {
            if (!*letter) zero_count++;
            letter++;
        }
        if (zero_count != 'a' - '9' - 1 ||
            imgend - letter < (ptrdiff_t)sizeof(letters_syms) ||
            memcmp(letter, letters_syms, sizeof(letters_syms))) {
            pos = num_start + 1;
            continue;
        }
        break;
    }

    if (!num_start || num_start >= imgend) {
        tools_loge("find kallsyms token_table error\n");
        return -1;
    }

    /*
     * Walk back over the preceding token terminators. The historical
     * layout includes a two-byte gap before the aligned token table.
     */
    pos = num_start;
    int32_t preceding_terminators = 0;
    while (pos > img && preceding_terminators < '0' + 1) {
        --pos;
        if (!*pos) preceding_terminators++;
    }
    if (preceding_terminators != '0' + 1) {
        tools_loge("kallsyms token_table start is not bounded by the image\n");
        return -1;
    }

    offset = (int32_t)(pos + 2 - img);
    if (offset < 0 || offset > imglen - 4) {
        tools_loge("kallsyms token_table offset is outside the image\n");
        return -1;
    }
    offset = align_ceil(offset, 4);
    if (offset < 0 || offset >= imglen) {
        tools_loge("aligned kallsyms token_table offset is outside the image\n");
        return -1;
    }

    info->kallsyms_token_table_offset = offset;
    tools_logi("kallsyms_token_table offset: 0x%08x\n", offset);

    token_pos = img + offset;
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        char *token_end;
        if (token_pos >= imgend) {
            tools_loge("kallsyms token_table is truncated at token %d\n", i);
            return -1;
        }
        token_end = (char *)memchr(token_pos, '\0', imgend - token_pos);
        if (!token_end) {
            tools_loge("kallsyms token %d has no in-image terminator\n", i);
            return -1;
        }
        info->kallsyms_token_table[i] = token_pos;
        token_pos = token_end + 1;
    }

    return 0;
}

static int find_token_index(kallsym_t *info, char *img, int32_t imglen, void *opt)
{
    uint16_t le_index[KSYM_TOKEN_NUMS] = { 0 };
    uint16_t be_index[KSYM_TOKEN_NUMS] = { 0 };
    int32_t start;
    int32_t offset;

    if (!info || !img || imglen <= 0) {
        tools_loge("invalid image for kallsyms token_index\n");
        return -1;
    }
    start = info->kallsyms_token_table_offset;
    if (start < 0 || start >= imglen) {
        tools_loge("kallsyms token_table start is outside the image\n");
        return -1;
    }
    offset = start;

    /* Build both endian forms, validating every NUL-terminated token. */
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        char *token_end;
        uint32_t token_offset;
        if (offset < start || offset >= imglen) {
            tools_loge("kallsyms token_table is truncated at token %d\n", i);
            return -1;
        }
        token_offset = (uint32_t)(offset - start);
        if (token_offset > UINT16_MAX) {
            tools_loge("kallsyms token_table exceeds 16-bit token_index range\n");
            return -1;
        }
        le_index[i] = u16le((uint16_t)token_offset);
        be_index[i] = u16be((uint16_t)token_offset);
        token_end = (char *)memchr(img + offset, '\0', imglen - offset);
        if (!token_end) {
            tools_loge("kallsyms token %d has no in-image terminator\n", i);
            return -1;
        }
        offset = (int32_t)(token_end - img) + 1;
    }

    char *lepos = (char *)memmem(img, imglen, le_index, sizeof(le_index));
    char *bepos = (char *)memmem(img, imglen, be_index, sizeof(be_index));
    if (!lepos && !bepos) {
        tools_loge("kallsyms_token_index error\n");
        return -1;
    }

    tools_logi("endian: %s\n", lepos ? "little" : "big");
    char *pos = lepos ? lepos : bepos;
    info->is_be = lepos ? 0 : 1;
    info->kallsyms_token_index_offset = (int32_t)(pos - img);
    tools_logi("kallsyms_token_index offset: 0x%08x\n",
               info->kallsyms_token_index_offset);
    return 0;
}

static int get_markers_elem_size(kallsym_t *info)
{
    if (info->kallsyms_markers_elem_size) return info->kallsyms_markers_elem_size;

    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;

    return elem_size;
}

static int get_num_syms_elem_size(kallsym_t *info)
{
    // the same as kallsyms_markers
    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;
    return elem_size;
}

static inline int get_addresses_elem_size(kallsym_t *info)
{
    return info->asm_PTR_size;
}

static inline int get_offsets_elem_size(kallsym_t *info)
{
    return info->asm_long_size;
}

static int32_t decode_relative_symbol_offset(kallsym_t *info, const char *entry)
{
    int32_t raw = (int32_t)int_unpack((void *)entry, get_offsets_elem_size(info), info->is_be);

    if (info->arch == X86_64 && info->has_absolute_percpu) {
        if (raw >= 0) return raw;
        return -1 - raw;
    }

    return (uint32_t)raw;
}

static int try_find_arm64_relo_table(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen < 24) {
        tools_logw("invalid image for ARM64 relocation scan\n");
        return -1;
    }
    if (!info->try_relo) return 0;

    uint64_t min_va = ELF64_KERNEL_MIN_VA;
    uint64_t max_va = ELF64_KERNEL_MAX_VA;
    uint64_t kernel_va = max_va;
    int32_t cand = 0;
    int rela_num = 0;
    while (cand < imglen - 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        uint32_t r_type = r_info & 0xffffffff;
        if ((r_offset & 0xffff000000000000) == 0xffff000000000000 && (r_type == 0x101 || r_type == 0x403)) {
            if (!(r_addend & 0xfff) && r_addend >= min_va && r_addend < kernel_va) kernel_va = r_addend;
            cand += 24;
            rela_num++;
        } else if (rela_num && !r_offset && !r_info && !r_addend) {
            cand += 24;
            rela_num++;
        } else {
            if (rela_num >= ARM64_RELO_MIN_NUM) break;
            cand += 8;
            rela_num = 0;
            kernel_va = max_va;
        }
    }

    if (rela_num < ARM64_RELO_MIN_NUM) {
        tools_logw("can't find arm64 relocation table\n");
        return 0;
    }

    int32_t cand_start = cand - 24 * rela_num;
    int32_t cand_end = cand - 24;
    if (cand_start < 0 || cand_end < cand_start || cand_end > imglen - 24) {
        tools_logw("ARM64 relocation candidate range is outside the image\n");
        return -1;
    }

    /*
     * Ignore trailing all-zero RELA slots, but never walk before the
     * candidate range. A truncated or zero-filled image must fail closed.
     */
    while (cand_end >= cand_start) {
        uint64_t ro = uint_unpack(img + cand_end, 8, info->is_be);
        uint64_t ri = uint_unpack(img + cand_end + 8, 8, info->is_be);
        uint64_t ra = uint_unpack(img + cand_end + 16, 8, info->is_be);
        if (ro || ri || ra) break;
        cand_end -= 24;
    }
    if (cand_end < cand_start) {
        tools_logw("ARM64 relocation candidate contains no complete nonzero entry\n");
        return 0;
    }
    cand_end += 24;

    rela_num = (cand_end - cand_start) / 24;
    if (rela_num < ARM64_RELO_MIN_NUM) {
        tools_logw("ARM64 relocation table is shorter than the required minimum\n");
        return 0;
    }

    if (info->kernel_base) {
        tools_logi("arm64 relocation kernel_va: 0x%" PRIx64 ", try: %" PRIx64 "\n", kernel_va, info->kernel_base);
        kernel_va = info->kernel_base;
    } else {
        if (kernel_va == max_va) {
            tools_logw("ARM64 relocation entries do not provide a valid kernel base\n");
            return 0;
        }
        info->kernel_base = kernel_va;
        tools_logi("arm64 relocation kernel_va: 0x%" PRIx64 "\n", kernel_va);
    }

    tools_logi("arm64 relocation table range: [0x%08x, 0x%08x), count: 0x%08x\n", cand_start, cand_end, rela_num);

    // apply relocations
    int32_t max_offset = imglen - 8;
    int32_t apply_num = 0;
    for (cand = cand_start; cand < cand_end; cand += 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if (!r_offset && !r_info && !r_addend) continue;
        if (r_offset <= kernel_va || r_offset >= max_va - imglen) {
            // tools_logw("warn ignore arm64 relocation r_offset: 0x%08lx at 0x%08x\n", r_offset, cand);
            continue;
        }

        uint64_t offset64 = r_offset - kernel_va;
        if (offset64 >= (uint64_t)max_offset) {
            /*
             * Some vendor kernels (e.g. 5.4 qgki) carry a relocation whose target lies
             * just past the loaded image (init/bss tail). Skipping it and continuing lets
             * later relocations overwrite the kallsyms_offsets table with pointer values,
             * which corrupts the monotonic offset sequence and truncates symbol resolution
             * (memblock_phys_alloc_try_nid & co then cannot be found). Abort so the caller
             * retries with a pristine image, as before 47a5014.
             */
            info->try_relo = 0;
            return -1;
        }

        int32_t offset = (int32_t)offset64;
        uint32_t r_type = r_info & 0xffffffff;
        if (r_type == 0x101) {
            r_addend += kernel_va;
        }

        uint64_t value = uint_unpack(img + offset, 8, info->is_be);
        if (value == r_addend) continue;
        *(uint64_t *)(img + offset) = value + r_addend;
        apply_num++;
    }
    if (apply_num) apply_num--;
    tools_logi("apply 0x%08x relocation entries\n", apply_num);

    if (apply_num) info->relo_applied = 1;

#if 0
#include <stdio.h>
    FILE *frelo = fopen("./kernel.relo", "wb+");
    int w_len = fwrite(img, 1, imglen, frelo);
    tools_logi("===== write relo kernel image: %d ====\n", w_len);
    fclose(frelo);
#endif

    return 0;
}

static int find_approx_addresses(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen <= 0 ||
        (info->asm_PTR_size != 4 && info->asm_PTR_size != 8) ||
        imglen < KSYM_MIN_NEQ_SYMS * info->asm_PTR_size) {
        tools_logw("invalid kallsyms_addresses scan range or element size\n");
        return -1;
    }

    int32_t sym_num = 0;
    int32_t elem_size = info->asm_PTR_size;
    uint64_t prev_offset = 0;
    int32_t cand = 0;

    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        uint64_t address = uint_unpack(img + cand, elem_size, info->is_be);
        if (!sym_num) { // first address
            if (address & 0xff) continue;
            if (elem_size == 4 && (address & 0xff800000) != 0xff800000) continue;
            if (elem_size == 8 && (address & 0xffff000000000000) != 0xffff000000000000) continue;
            prev_offset = address;
            sym_num++;
            continue;
        }
        if (address >= prev_offset) {
            prev_offset = address;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        tools_loge("find approximate kallsyms_addresses error\n");
        return -1;
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_addresses end
    prev_offset = 0;
    for (; cand <= imglen - elem_size; cand += elem_size) {
        uint64_t offset = uint_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // end is not include
    info->_approx_addresses_or_offsets_end = cand;
    info->has_relative_base = 0;
    int32_t approx_num_syms = (cand - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    tools_logi("approximate kallsyms_addresses range: [0x%08x, 0x%08x) "
               "count: 0x%08x\n",
               approx_offset, cand, approx_num_syms);

    //
    if (info->relo_applied) {
        tools_logw("ARM64 relocations were applied before the absolute-address scan; "
                   "the candidate must pass exact symbol-count and vector checks\n");
    }

    return 0;
}

static int find_approx_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_long_size;
    uint64_t prev_offset = 0;
    int32_t cand = 0;
    int32_t MAX_ZERO_OFFSET_NUM = 10;
    int32_t zero_offset_num = 0;

    if (!img || imglen <= 0 || elem_size != 4 ||
        imglen < KSYM_MIN_NEQ_SYMS * elem_size) {
        tools_logw("invalid kallsyms_offsets scan range or element size\n");
        return -1;
    }

    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        int64_t raw_offset = int_unpack(img + cand, elem_size, info->is_be);
        uint64_t offset = raw_offset < 0 ? (1ull << 32) + (uint32_t)(-raw_offset) : (uint32_t)raw_offset;
        if (!sym_num) {
            if (!raw_offset) continue;
            prev_offset = offset;
            sym_num++;
            continue;
        }
        if (offset == prev_offset) {
            continue;
        } else if (offset > prev_offset) {
            prev_offset = offset;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        tools_logw("find approximate kallsyms_offsets error\n");
        return -1;
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    if (cand < 0 || cand > imglen - elem_size) {
        tools_logw("kallsyms_offsets candidate start is outside the image\n");
        return -1;
    }

    /* Locate the zero sentinel before the relative-offset array. */
    while (cand >= 0 && int_unpack(img + cand, elem_size, info->is_be))
        cand -= elem_size;
    if (cand < 0) {
        tools_logw("kallsyms_offsets zero sentinel is not bounded by the image\n");
        return -1;
    }

    /* Walk back across the bounded run of zero entries preceding the table. */
    while (cand >= 0 && !int_unpack(img + cand, elem_size, info->is_be)) {
        if (zero_offset_num++ >= MAX_ZERO_OFFSET_NUM) break;
        cand -= elem_size;
    }
    if (cand < 0) {
        tools_logw("kallsyms_offsets table start underflows the image\n");
        return -1;
    }

    cand += elem_size;
    if (cand < 0 || cand > imglen - elem_size) {
        tools_logw("kallsyms_offsets table start has no complete entry\n");
        return -1;
    }
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    /* Read only complete elements; the kernel image may end with a short tail. */
    prev_offset = 0;
    for (; cand <= imglen - elem_size; cand += elem_size) {
        int64_t raw_offset = int_unpack(img + cand, elem_size, info->is_be);
        uint64_t offset = raw_offset < 0 ? (1ull << 32) + (uint32_t)(-raw_offset) : (uint32_t)raw_offset;
        if (offset < prev_offset) break;
        prev_offset = offset;
    }

    /* end is exclusive and never extends beyond imglen */
    int32_t end = cand;
    info->_approx_addresses_or_offsets_end = end;
    info->has_relative_base = 1;
    int32_t approx_num_syms = (end - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    tools_logi("approximate kallsyms_offsets range: [0x%08x, 0x%08x) "
               "count: 0x%08x\n",
               approx_offset, end, approx_num_syms);
    return 0;
}

static int32_t find_approx_addresses_or_offset(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t ret = 0;
    if ((info->arch == ARM64 || info->arch == X86_64) && info->is_64) {
        /*
         * Vendor arm64 kernels can carry kallsyms_offsets even on older
         * version strings such as 4.4, so don't gate the relative-base path
         * purely on the reported kernel version.
         */
        tools_logi("try kallsyms_offsets first for 64-bit relative-base kernel\n");
        ret = find_approx_offsets(info, img, imglen);
        if (!ret) return 0;
    }
    tools_logi("fallback to kallsyms_addresses scan\n");
    ret = find_approx_addresses(info, img, imglen);
    return ret;
}

static int find_num_syms(kallsym_t *info, char *img, int32_t imglen)
{
#define NSYMS_MAX_GAP 10

    if (!info || !img) {
        tools_logw("invalid kallsyms_num_syms input\n");
        return -1;
    }

    /* Do not allow a failed retry to leak a stale count into the next pass. */
    info->kallsyms_num_syms = 0;
    info->kallsyms_num_syms_offset = 0;

    int32_t approx_end = info->kallsyms_names_offset;
    const int32_t num_syms_elem_size = 4;
    int32_t approx_num_syms = info->_approx_addresses_or_offsets_num;

    if (imglen < num_syms_elem_size ||
        approx_end < 0 || approx_end > imglen - num_syms_elem_size ||
        approx_num_syms <= 0 || approx_num_syms > KSYM_MAX_SYMS) {
        tools_logw("invalid kallsyms_num_syms search range or approximate count\n");
        return -1;
    }

    int32_t lower = approx_end > 4096 ? approx_end - 4096 : 0;
    for (int32_t cand = approx_end;
         cand >= lower && cand <= imglen - num_syms_elem_size;
         cand -= num_syms_elem_size) {
        int nsyms = (int)int_unpack(img + cand, num_syms_elem_size, info->is_be);
        if (nsyms <= 0 || nsyms > KSYM_MAX_SYMS) continue;
        if (approx_num_syms > nsyms && approx_num_syms - nsyms > NSYMS_MAX_GAP) continue;
        if (nsyms > approx_num_syms && nsyms - approx_num_syms > NSYMS_MAX_GAP) continue;

        info->kallsyms_num_syms = nsyms;
        info->kallsyms_num_syms_offset = cand;
        break;
    }

    if (!info->kallsyms_num_syms_offset || !info->kallsyms_num_syms) {
#if KP_STRICT_KALLSYMS
        tools_logw("cannot verify exact kallsyms_num_syms (approximate count 0x%08x); "
                   "rejecting this address-table candidate and retrying\n",
                   approx_num_syms);
        return -1;
#else
        if (approx_num_syms <= NSYMS_MAX_GAP) return -1;
        info->kallsyms_num_syms = approx_num_syms - NSYMS_MAX_GAP;
        tools_logw("can't find kallsyms_num_syms, try: 0x%08x\n", info->kallsyms_num_syms);
#endif
    } else {
        tools_logi("kallsyms_num_syms offset: 0x%08x, value: 0x%08x\n",
                   info->kallsyms_num_syms_offset, info->kallsyms_num_syms);
    }

    if (info->arch == X86_64 && info->has_relative_base) {
        int32_t begin = info->kallsyms_num_syms_offset - 32;
        if (begin < 0) begin = 0;
        for (int32_t pos = info->kallsyms_num_syms_offset - 8;
             pos >= begin && pos <= imglen - 8; pos -= 8) {
            uint64_t value = uint_unpack(img + pos, 8, info->is_be);
            if ((value & 0xffff000000000000ull) == 0xffff000000000000ull) {
                info->kallsyms_relative_base = value;
                info->kernel_base = value;
                tools_logi("kallsyms_relative_base offset: 0x%08x, value: 0x%llx\n",
                           pos, (unsigned long long)value);
                break;
            }
        }
    }
    return 0;
}

static int find_markers_internal(kallsym_t *info, char *img, int32_t imglen, int32_t elem_size)
{
    if (!info || !img || imglen <= 0 ||
        (elem_size != 4 && elem_size != 8) ||
        info->kallsyms_token_table_offset < 0 ||
        info->kallsyms_token_table_offset > imglen - elem_size) {
        tools_logw("invalid kallsyms_markers scan range\\n");
        return -1;
    }

    int32_t cand = info->kallsyms_token_table_offset;

    int64_t marker, last_marker = imglen;
    int count = 0;
    while (cand > 0x10000) {
        marker = int_unpack(img + cand, elem_size, info->is_be);
        if (last_marker > marker) {
            count++;
            if (!marker && count > KSYM_MIN_MARKER) break;
        } else {
            count = 0;
            last_marker = imglen;
        }

        last_marker = marker;
        cand -= elem_size;
    }

    if (count < KSYM_MIN_MARKER) {
        tools_logw("find kallsyms_markers error\n");
        return -1;
    }

    int64_t marker_end64 = (int64_t)cand + (int64_t)count * elem_size + elem_size;
    if (cand < 0 || marker_end64 < cand || marker_end64 > imglen) {
        tools_logw("kallsyms_markers range exceeds the image\\n");
        return -1;
    }
    int32_t marker_end = (int32_t)marker_end64;

    // Validate marker values read forward. Each marker is a byte offset into
    // kallsyms_names, which ends at markers_offset (== cand), so every value
    // must be non-negative, strictly less than cand, and the sequence must be
    // non-decreasing. A wrong elem_size (e.g. reading 4-byte markers as 8-byte
    // on a vendor 4.19 kernel that uses unsigned int markers) merges adjacent
    // entries into huge values that still pass the backward decreasing scan
    // above but are nonsense here; reject so find_markers() falls back to the
    // other elem_size instead of trusting a false positive.
    int64_t prev = -1;
    for (int i = 0; i < count; i++) {
        int64_t v = int_unpack(img + cand + i * elem_size, elem_size, info->is_be);
        if (v < 0 || v >= cand || v < prev) {
            tools_logw("kallsyms_markers elem_size %d rejected at [%d] (val 0x%llx)\n", elem_size, i,
                       (unsigned long long)v);
            return -1;
        }
        prev = v;
    }

    info->kallsyms_markers_offset = cand;
    info->_marker_num = count;
    info->kallsyms_markers_elem_size = elem_size;

    tools_logi("kallsyms_markers range: [0x%08x, 0x%08x), count: 0x%08x\n", cand, marker_end, count);
    return 0;
}

static int find_markers(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t elem_size = get_markers_elem_size(info);
    int rc = find_markers_internal(info, img, imglen, elem_size);
    if (rc && elem_size == 8) {
        return find_markers_internal(info, img, imglen, 4);
    }
    return rc;
}

static int decompress_symbol_name(kallsym_t *info, char *img, int32_t *pos_to_next,
                                  char *out_type, char *out_symbol)
{
    if (!info || !img || !pos_to_next || info->image_size <= 0 ||
        info->kallsyms_markers_offset <= 0 ||
        info->kallsyms_markers_offset > info->image_size) {
        return -1;
    }

    int32_t limit = info->kallsyms_markers_offset;
    int32_t pos = *pos_to_next;
    if (pos < 0 || pos >= limit) return -1;

    int32_t len = (uint8_t)img[pos++];
    if (len > 0x7F) {
        if (pos >= limit) return -1;
        len = (len & 0x7F) + ((uint8_t)img[pos++] << 7);
    }
    if (!len || len >= KSYM_SYMBOL_LEN || len > limit - pos) return -1;

    for (int32_t i = 0; i < len; i++) {
        uint8_t tokidx = (uint8_t)img[pos + i];
        char *token = info->kallsyms_token_table[tokidx];
        if (!token) return -1;

        uintptr_t image_base = (uintptr_t)img;
        uintptr_t token_addr = (uintptr_t)token;
        if (token_addr < image_base || token_addr - image_base >= (uintptr_t)info->image_size)
            return -1;

        size_t token_remaining = info->image_size - (size_t)(token_addr - image_base);
        char *token_end = (char *)memchr(token, '\0', token_remaining);
        if (!token_end) return -1;
        size_t token_len = (size_t)(token_end - token);
        if (!token_len) return -1;

        size_t skip = 0;
        if (!i) {
            if (out_type) *out_type = token[0];
            skip = 1;
        }
        if (out_symbol) {
            size_t used = strnlen(out_symbol, KSYM_SYMBOL_LEN);
            if (used >= KSYM_SYMBOL_LEN || token_len < skip) return -1;
            size_t append_len = token_len - skip;
            if (append_len > KSYM_SYMBOL_LEN - 1 - used) return -1;
            memcpy(out_symbol + used, token + skip, append_len);
            out_symbol[used + append_len] = '\0';
        }
    }

    *pos_to_next = pos + len;
    return 0;
}

static int is_symbol_name_pos(kallsym_t *info, char *img, int32_t pos, char *symbol)
{
    if (!info || !img || !symbol || info->image_size <= 0 ||
        info->kallsyms_markers_offset <= 0 ||
        info->kallsyms_markers_offset > info->image_size ||
        pos < 0 || pos >= info->kallsyms_markers_offset) return 0;

    int32_t limit = info->kallsyms_markers_offset;
    int32_t len = (uint8_t)img[pos++];
    if (len > 0x7F) {
        if (pos >= limit) return 0;
        len = (len & 0x7F) + ((uint8_t)img[pos++] << 7);
    }
    if (!len || len >= KSYM_SYMBOL_LEN || len > limit - pos) return 0;

    size_t symbol_len = strnlen(symbol, KSYM_SYMBOL_LEN);
    if (symbol_len >= KSYM_SYMBOL_LEN) return 0;
    size_t symidx = 0;
    for (int32_t i = 0; i < len; i++) {
        uint8_t tokidx = (uint8_t)img[pos + i];
        char *token = info->kallsyms_token_table[tokidx];
        if (!token) return 0;
        uintptr_t image_base = (uintptr_t)img;
        uintptr_t token_addr = (uintptr_t)token;
        if (token_addr < image_base || token_addr - image_base >= (uintptr_t)info->image_size)
            return 0;
        size_t remaining = info->image_size - (size_t)(token_addr - image_base);
        char *token_end = (char *)memchr(token, '\0', remaining);
        if (!token_end) return 0;
        size_t token_len = (size_t)(token_end - token);
        size_t skip = i ? 0 : 1;
        if (token_len < skip) return 0;
        size_t append_len = token_len - skip;
        if (append_len > symbol_len - symidx ||
            memcmp(symbol + symidx, token + skip, append_len)) return 0;
        symidx += append_len;
    }
    return symidx == symbol_len;
}

static int correct_addresses_or_offsets_by_banner(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen <= 0 || info->image_size != imglen ||
        info->banner_num <= 0 ||
        info->banner_num > (int32_t)ARRAY_SIZE(info->linux_banner_offset) ||
        info->kallsyms_markers_offset <= 0 ||
        info->kallsyms_markers_offset > imglen) return -1;

    int32_t pos = info->kallsyms_names_offset;
    if (pos < 0 || pos >= info->kallsyms_markers_offset) return -1;
    int32_t index = 0;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };

    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) return ret;
        if (!strcmp(symbol, "linux_banner")) {
            tools_logi("names table linux_banner index: 0x%08x\n", index);
            break;
        }
        index++;
    }

    if (pos >= info->kallsyms_markers_offset ||
        index < 0 || index >= info->kallsyms_num_syms) {
        tools_loge("no valid linux_banner entry in names table\n");
        return -1;
    }

    int32_t elem_size = info->has_relative_base ?
        get_offsets_elem_size(info) : get_addresses_elem_size(info);
    int32_t table_start = info->_approx_addresses_or_offsets_offset;
    int32_t table_end = info->_approx_addresses_or_offsets_end;
    if ((elem_size != 4 && elem_size != 8) || table_start < 0 ||
        table_end > imglen || table_end < table_start) {
        tools_loge("invalid kallsyms address-table candidate range\n");
        return -1;
    }

    int64_t index_bytes = (int64_t)index * elem_size;
    int64_t max_base_pos = (int64_t)table_end - index_bytes - elem_size;
    if (max_base_pos < table_start) {
        tools_loge("linux_banner index exceeds candidate address-table coverage\n");
        return -1;
    }

    int64_t search_end = (int64_t)table_start + 4096 + elem_size;
    if (search_end > max_base_pos + elem_size)
        search_end = max_base_pos + elem_size;

    pos = -1;
    int32_t matched_banner = -1;
    for (int32_t banner_idx = 0; banner_idx < info->banner_num; banner_idx++) {
        int32_t target_offset = info->linux_banner_offset[banner_idx];
        for (int64_t candidate = table_start; candidate < search_end; candidate += elem_size) {
            int64_t target_pos = candidate + index_bytes;
            uint64_t base = uint_unpack(img + candidate, elem_size, info->is_be);
            uint64_t target = uint_unpack(img + target_pos, elem_size, info->is_be);

            if (info->arch == X86_64 && info->has_relative_base) {
                int32_t raw = (int32_t)int_unpack(img + target_pos, elem_size, info->is_be);
                if ((uint32_t)raw == (uint32_t)target_offset) {
                    info->has_absolute_percpu = 0;
                    pos = (int32_t)candidate;
                    matched_banner = banner_idx;
                    break;
                }
                if (raw < 0 && -1 - raw == target_offset) {
                    info->has_absolute_percpu = 1;
                    tools_logi("x86 kallsyms uses absolute percpu offsets\n");
                    pos = (int32_t)candidate;
                    matched_banner = banner_idx;
                    break;
                }
                continue;
            }

            if (target >= base && target - base <= INT32_MAX &&
                (int32_t)(target - base) == target_offset) {
                pos = (int32_t)candidate;
                matched_banner = banner_idx;
                break;
            }
        }
        if (pos >= 0) break;
    }

    if (pos < table_start || (int64_t)pos >= search_end || matched_banner < 0) {
        tools_loge("correct kallsyms address or offsets error\n");
        return -1;
    }

    info->symbol_banner_idx = matched_banner;
    tools_logi("linux_banner index: %d\n", matched_banner);

    if (info->has_relative_base) {
        info->kallsyms_offsets_offset = pos;
        tools_logi("kallsyms_offsets offset: 0x%08x\n", pos);
    } else {
        info->kallsyms_addresses_offset = pos;
        info->kernel_base = uint_unpack(img + pos, elem_size, info->is_be);
        tools_logi("kallsyms_addresses offset: 0x%08x\n", pos);
        tools_logi("kernel base address: 0x%llx\n", (unsigned long long)info->kernel_base);
    }

    if (info->arch == ARM64) {
        int32_t pid_vnr_offset = get_symbol_offset(info, img, "pid_vnr");
        if (pid_vnr_offset >= 0 &&
            arm64_verify_pid_vnr(info, img, imglen, pid_vnr_offset, 0)) {
            tools_logw("pid_vnr verification failed\n");
        }
    }

    return 0;
}

static int correct_addresses_or_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int rc = 0;
#if 1
    rc = correct_addresses_or_offsets_by_banner(info, img, imglen);
    info->is_kallsysms_all_yes = 1;
#endif
    if (rc) {
        info->is_kallsysms_all_yes = 0;
        tools_logw("no linux_banner, CONFIG_KALLSYMS_ALL=n\n");
    }
    if (rc) rc = correct_addresses_or_offsets_by_vectors(info, img, imglen);
    if (rc) return rc;

    int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);
    int32_t start = info->has_relative_base ? info->kallsyms_offsets_offset : info->kallsyms_addresses_offset;
    int32_t coverage = (info->_approx_addresses_or_offsets_end - start) / elem_size;
    if (coverage < info->kallsyms_num_syms) {
        tools_logw("resolved symbol table only covers 0x%08x entries, but names table has 0x%08x entries\n",
                   coverage, info->kallsyms_num_syms);
        return -1;
    }
    return rc;
}

void init_arm64_kallsym_t(kallsym_t *info)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = 1;
    info->asm_long_size = 4;
    info->asm_PTR_size = 8;
    info->try_relo = 1;
}

void init_not_tested_arch_kallsym_t(kallsym_t *info, int32_t is_64)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    info->try_relo = 0;
    if (is_64) info->asm_PTR_size = 8;
}

static int retry_relo(kallsym_t *info, char *img, int32_t imglen)
{
    int rc = -1;
    static int32_t (*funcs[])(kallsym_t *, char *, int32_t) = {
        try_find_arm64_relo_table,   find_markers, find_approx_addresses_or_offset, find_names, find_num_syms,
        correct_addresses_or_offsets
    };

    for (int i = 0; i < (int)(sizeof(funcs) / sizeof(funcs[0])); i++) {
        if ((rc = funcs[i](info, img, imglen))) break;
    }

    return rc;
}

/*
R kallsyms_offsets
R kallsyms_relative_base
R kallsyms_num_syms
R kallsyms_names
R kallsyms_markers
R kallsyms_token_table
R kallsyms_token_index
*/
int analyze_kallsym_info(kallsym_t *info, char *img, int32_t imglen, enum arch_type arch, int32_t is_64)
{
    if (!info || !img || imglen <= 0) return -1;
    memset(info, 0, sizeof(kallsym_t));
    info->image_size = imglen;
    info->arch = arch;
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    if (arch == ARM64) info->try_relo = 1;
    if (is_64) info->asm_PTR_size = 8;

    int rc = -1;
    static int32_t (*base_funcs[])(kallsym_t *, char *, int32_t, void *) = {
        find_linux_banner,
        find_token_table,
        find_token_index,
    };
    for (int i = 0; i < (int)(sizeof(base_funcs) / sizeof(base_funcs[0])); i++) {
        if ((rc = base_funcs[i](info, img, imglen, NULL))) return rc;
    }

    kallsym_t raw_layout = *info;
    int raw_layout_ready = 0;
    if (!find_markers(&raw_layout, img, imglen) && !find_names(&raw_layout, img, imglen)) {
        raw_layout_ready = 1;
    }

    char *copied_img = (char *)malloc((size_t)imglen);
    if (!copied_img) {
        tools_loge("failed to allocate kallsyms analysis image\n");
        return -1;
    }
    memcpy(copied_img, img, (size_t)imglen);

    // 1st
    rc = retry_relo(info, copied_img, imglen);
    if (!rc) goto out;

    if (raw_layout_ready) {
        memcpy(copied_img, img, imglen);
        *info = raw_layout;
        rc = try_find_arm64_relo_table(info, copied_img, imglen);
        if (!rc) {
            int32_t restore_start = info->kallsyms_names_offset;
            int32_t restore_end = info->kallsyms_token_index_offset + KSYM_TOKEN_NUMS * 2;
            if (restore_start < 0) restore_start = 0;
            if (restore_end > imglen) restore_end = imglen;
            if (restore_start < restore_end) {
                memcpy(copied_img + restore_start, img + restore_start, restore_end - restore_start);
            }

            rc = find_approx_addresses_or_offset(info, copied_img, imglen);
            if (!rc) rc = find_num_syms(info, copied_img, imglen);
            if (!rc) rc = correct_addresses_or_offsets(info, copied_img, imglen);
            if (!rc) goto out;
        }
    }

    // 2nd
    if (!info->try_relo) {
        memcpy(copied_img, img, imglen);
        rc = retry_relo(info, copied_img, imglen);
        if (!rc) goto out;
    }

    // 3rd
    if (info->kernel_base != ELF64_KERNEL_MIN_VA) {
        info->kernel_base = ELF64_KERNEL_MIN_VA;
        memcpy(copied_img, img, imglen);
        rc = retry_relo(info, copied_img, imglen);
    }

out:
    memcpy(img, copied_img, imglen);
    free(copied_img);
    return rc;
}

int32_t get_symbol_index_offset(kallsym_t *info, char *img, int32_t index)
{
    if (!info || !img || info->image_size <= 0 || index < 0 ||
        index >= info->kallsyms_num_syms) return -1;

    int32_t elem_size;
    int32_t pos;
    if (info->has_relative_base) {
        elem_size = get_offsets_elem_size(info);
        pos = info->kallsyms_offsets_offset;
    } else {
        elem_size = get_addresses_elem_size(info);
        pos = info->kallsyms_addresses_offset;
    }
    if ((elem_size != 4 && elem_size != 8) || pos < 0 ||
        pos > info->image_size - elem_size ||
        (uint64_t)index > ((uint64_t)(info->image_size - elem_size - pos) / (uint32_t)elem_size))
        return -1;

    const char *entry = img + pos + (size_t)index * (size_t)elem_size;
    if (info->has_relative_base)
        return decode_relative_symbol_offset(info, entry);

    uint64_t target = uint_unpack((void *)entry, elem_size, info->is_be);
    if (target < info->kernel_base || target - info->kernel_base > INT32_MAX)
        return -1;
    return (int32_t)(target - info->kernel_base);
}
int is_symbol_exists(kallsym_t *info, char *img, const char *symbol)
{
    if (!info || !img || !symbol) return 0;
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    int32_t pos = info->kallsyms_names_offset;

    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        if (decompress_symbol_name(info, img, &pos, &type, decomp)) return 0;
        if (!strcmp(decomp, symbol)) return 1;
    }
    return 0;
}

int get_symbol_offset_and_size(kallsym_t *info, char *img, char *symbol, int32_t *size)
{
    if (!info || !img || !symbol || !size) return -1;
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    *size = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        if (decompress_symbol_name(info, img, &pos, &type, decomp)) return -1;
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            if (offset < 0) return -1;
            int32_t next_offset = offset;
            for (int32_t j = i + 1; j < info->kallsyms_num_syms; j++) {
                next_offset = get_symbol_index_offset(info, img, j);
                if (next_offset < 0 || next_offset < offset) return -1;
                if (next_offset > offset) {
                    *size = next_offset - offset;
                    break;
                }
            }
            tools_logi("%s: type: %c, offset: 0x%08x, size: 0x%x\n", symbol, type, offset, *size);
            return offset;
        }
    }
    tools_logw("no symbol: %s\n", symbol);
    return -1;
}

int get_symbol_offset(kallsym_t *info, char *img, char *symbol)
{
    if (!info || !img || !symbol) return -1;
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        if (decompress_symbol_name(info, img, &pos, &type, decomp)) return -1;
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            if (offset < 0) return -1;
            tools_logi("%s: type: %c, offset: 0x%08x\n", symbol, type, offset);
            return offset;
        }
    }
    tools_logw("no symbol: %s\n", symbol);
    return -1;
}

int dump_all_symbols(kallsym_t *info, char *img)
{
    if (!info || !img) return -1;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        if (decompress_symbol_name(info, img, &pos, &type, symbol)) return -1;
        int32_t offset = get_symbol_index_offset(info, img, i);
        if (offset < 0) return -1;
        fprintf(stdout, "0x%08x %c %s\n", offset, type, symbol);
    }
    return 0;
}
int decompress_data(const unsigned char *compressed_data, size_t compressed_size)
{
    FILE *temp = fopen("temp.gz", "wb");
    if (!temp) {
        fprintf(stderr, "Failed to create temp file\n");
        return -1;
    }

    fwrite(compressed_data, 1, compressed_size, temp);
    fclose(temp);

    gzFile gz = gzopen("temp.gz", "rb");
    if (!gz) {
        fprintf(stderr, "Failed to open temp file for decompression\n");
        return -1;
    }

    char buffer[1024];
    int bytes_read;
    while ((bytes_read = gzread(gz, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    gzclose(gz);
    return 0;
}

int dump_all_ikconfig(char *img, int32_t imglen)
{
    size_t kcfg_start = 0;
    size_t kcfg_bytes = 0;
    int rc = find_ikconfig_blob(img, imglen, &kcfg_start, &kcfg_bytes);
    if (rc) {
        fprintf(stderr, "Cannot find kernel config blob, rc=%d.\n", rc);
        return 1;
    }

    printf("Kernel config start: %zu, bytes: %zu\n", kcfg_start, kcfg_bytes);

    unsigned char *extracted_data = (unsigned char *)malloc(kcfg_bytes);
    if (!extracted_data) {
        fprintf(stderr, "Memory allocation for extracted data failed.\n");
        return 1;
    }

    memcpy(extracted_data, img + kcfg_start, kcfg_bytes);

    int ret = decompress_data(extracted_data, kcfg_bytes);

    free(extracted_data);

    return 0;
}

int extract_ikconfig(char *img, int32_t imglen, char **out, int32_t *outlen)
{
    size_t kcfg_start = 0;
    size_t kcfg_bytes = 0;
    int rc = find_ikconfig_blob(img, imglen, &kcfg_start, &kcfg_bytes);
    if (rc) return rc;

    uint64_t cap = 256 * 1024;
    uint8_t *buf = NULL;
    int ret = Z_BUF_ERROR;

    while (cap <= 4 * 1024 * 1024) {
        buf = malloc(cap + 1);
        if (!buf) return -100;

        z_stream strm = { 0 };
        strm.next_in = (Bytef *)(img + kcfg_start);
        strm.avail_in = (uInt)kcfg_bytes;
        strm.next_out = buf;
        strm.avail_out = (uInt)cap;

        if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
            free(buf);
            return -101;
        }

        ret = inflate(&strm, Z_FINISH);
        if (ret == Z_STREAM_END) {
            cap = strm.total_out;
            inflateEnd(&strm);
            break;
        }

        inflateEnd(&strm);
        free(buf);
        buf = NULL;

        if (ret != Z_BUF_ERROR) return ret;
        cap *= 2;
    }

    if (!buf) return ret;

    buf[cap] = '\0';
    *outlen = (int32_t)align_ceil((int32_t)cap + 1, EXTRA_ALIGN);
    char *aligned = calloc(1, *outlen);
    if (!aligned) {
        free(buf);
        return -102;
    }
    memcpy(aligned, buf, cap + 1);
    free(buf);

    *out = aligned;
    return 0;
}

int on_each_symbol(kallsym_t *info, char *img, void *userdata,
                   int32_t (*fn)(int32_t index, char type, const char *symbol, int32_t offset, void *userdata))
{
    if (!info || !img || !fn) return -1;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        if (decompress_symbol_name(info, img, &pos, &type, symbol)) return -1;
        int32_t offset = get_symbol_index_offset(info, img, i);
        if (offset < 0) return -1;
        int rc = fn(i, type, symbol, offset, userdata);
        if (rc) return rc;
    }
    return 0;
}
