/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "common.h"
#include "order.h"

bool log_enable = false;

int can_b_imm(uint64_t from, uint64_t to)
{
    /* A64 B uses signed imm26<<2: [-128 MiB, +128 MiB-4], word aligned. */
    if ((from & 3) || (to & 3)) return 0;
    if (to >= from) return to - from <= 0x07fffffcULL;
    return from - to <= 0x08000000ULL;
}

int b(uint32_t *buf, uint64_t from, uint64_t to)
{
    if (can_b_imm(from, to)) {
        buf[0] = 0x14000000u | (((to - from) & 0x0FFFFFFFu) >> 2u);
        return 4;
    }
    return 0;
}

int32_t relo_branch_func(const char *img, int32_t imglen, int32_t func_offset)
{
    if (!img || imglen < 4 || func_offset < 0 || func_offset > imglen - 4 ||
        (func_offset & 3)) {
        tools_loge("invalid function entry offset 0x%x for image size 0x%x\n",
                   func_offset, imglen);
        return -1;
    }

    uint32_t inst;
    memcpy(&inst, img + func_offset, sizeof(inst));
    int64_t target = func_offset;
    if (INSN_IS_B(inst)) {
        uint64_t imm26 = bits32(inst, 25, 0);
        int64_t displacement = (int64_t)sign64_extend(imm26 << 2u, 28u);
        target += displacement;
        if ((target & 3) || target < 0 || target > (int64_t)imglen - 4) {
            tools_loge("function branch target 0x%llx is outside image\n",
                       (unsigned long long)target);
            return -1;
        }
        tools_logi("relocate branch function 0x%x to 0x%llx\n",
                   func_offset, (unsigned long long)target);
    }
    return (int32_t)target;
}

void read_file_align(const char *path, char **con, int *out_len, int align)
{
    if (!path || !con || !out_len || align <= 0 || (align & (align - 1)))
        tools_loge_exit("invalid read_file_align arguments\n");

    FILE *fp = fopen(path, "rb");
    if (!fp) tools_log_errno_exit("open file %s\n", path);
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        tools_log_errno_exit("seek file %s\n", path);
    }
    long file_size = ftell(fp);
    if (file_size < 0 || file_size > 0x7fffffffL || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        tools_loge_exit("invalid or oversized file %s\n", path);
    }

    uint64_t aligned = align_ceil((uint64_t)file_size, (uint64_t)align);
    if (aligned > 0x7fffffffULL) {
        fclose(fp);
        tools_loge_exit("aligned file %s is too large\n", path);
    }
    size_t allocation = aligned ? (size_t)aligned : 1;
    char *buf = (char *)calloc(1, allocation);
    if (!buf) {
        fclose(fp);
        tools_loge_exit("allocate file buffer for %s failed\n", path);
    }
    size_t readlen = fread(buf, 1, (size_t)file_size, fp);
    if (readlen != (size_t)file_size) {
        free(buf);
        fclose(fp);
        tools_loge_exit("short read from file %s\n", path);
    }
    fclose(fp);
    *con = buf;
    *out_len = (int)aligned;
}

void write_file(const char *path, const char *con, int len, bool append)
{
    FILE *fout = fopen(path, append ? "ab" : "wb");
    if (!fout) tools_log_errno_exit("open file %s\n", path);
    int writelen = fwrite(con, 1, len, fout);
    if (writelen != len) tools_log_errno_exit("write file %s\n", path);
    fclose(fout);
}

int64_t int_unpack(void *ptr, int32_t size, bool is_be)
{
    bool swp = is_be ^ is_be();
    int64_t res64;
    int32_t res32;
    int16_t res16;
    switch (size) {
    case 8:
        res64 = *(int64_t *)ptr;
        return swp ? i64swp(res64) : res64;
    case 4:
        res32 = *(int32_t *)ptr;
        return swp ? i32swp(res32) : res32;
    case 2:
        res16 = *(int16_t *)ptr;
        return swp ? i16swp(res16) : res16;
    default:
        return *(int8_t *)ptr;
    }
}

uint64_t uint_unpack(void *ptr, int32_t size, bool is_be)
{
    bool swp = is_be ^ is_be();
    uint64_t res64;
    uint32_t res32;
    uint16_t res16;
    switch (size) {
    case 8:
        res64 = *(uint64_t *)ptr;
        return swp ? u64swp(res64) : res64;
    case 4:
        res32 = *(uint32_t *)ptr;
        return swp ? u32swp(res32) : res32;
    case 2:
        res16 = *(uint16_t *)ptr;
        return swp ? u16swp(res16) : res16;
    default:
        return *(uint8_t *)ptr;
    }
}
