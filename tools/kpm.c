/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "kpm.h"

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

static bool elf_range_valid(uint64_t offset, uint64_t size, uint64_t total)
{
    return offset <= total && size <= total - offset;
}

static bool elf_string_valid(const char *table, uint64_t table_size, uint32_t offset)
{
    return offset < table_size && memchr(table + offset, '\0', table_size - offset) != NULL;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    uint64_t remaining = infosec->sh_size;
    char *cursor = (char *)info->hdr + infosec->sh_offset;
    uint32_t taglen = strlen(tag);

    if (prev) {
        if (prev < cursor || (uint64_t)(prev - cursor) >= remaining) return NULL;
        remaining -= (uint64_t)(prev - cursor);
        cursor = prev;
        char *end = memchr(cursor, '\0', remaining);
        if (!end) return NULL;
        uint64_t consumed = (uint64_t)(end - cursor) + 1;
        cursor = end + 1;
        remaining -= consumed;
    }

    while (remaining) {
        while (remaining && !*cursor) {
            cursor++;
            remaining--;
        }
        if (!remaining) break;
        char *end = memchr(cursor, '\0', remaining);
        if (!end) return NULL;
        size_t entry_len = (size_t)(end - cursor);
        if (entry_len > taglen && !memcmp(cursor, tag, taglen) && cursor[taglen] == '=')
            return cursor + taglen + 1;
        uint64_t consumed = entry_len + 1;
        cursor = end + 1;
        remaining -= consumed;
    }
    return NULL;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct load_info *info, const char *name)
{
    Elf_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC) || !elf_string_valid(info->secstrings, shstr->sh_size, shdr->sh_name))
            continue;
        if (!strcmp(info->secstrings + shdr->sh_name, name)) return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static uint64_t get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_size;
}

int get_kpm_info(const char *kpm, int len, kpm_info_t *out_info)
{
    struct load_info load_info = { .len = len, .hdr = (Elf_Ehdr *)kpm };
    struct load_info *info = &load_info;

    if (!kpm || !out_info || info->len <= sizeof(*(info->hdr))) return -ENOEXEC;
    memset(out_info, 0, sizeof(*out_info));
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) ||
        info->hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        info->hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        info->hdr->e_ident[EI_VERSION] != EV_CURRENT ||
        info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_version != EV_CURRENT ||
        info->hdr->e_ehsize != sizeof(Elf_Ehdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr) ||
        !info->hdr->e_shnum || info->hdr->e_shstrndx >= info->hdr->e_shnum ||
        !elf_range_valid(info->hdr->e_shoff,
                         (uint64_t)info->hdr->e_shnum * sizeof(Elf_Shdr), info->len))
        return -ENOEXEC;

    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    Elf_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB ||
        !elf_range_valid(shstr->sh_offset, shstr->sh_size, info->len) ||
        !shstr->sh_size)
        return -ENOEXEC;
    info->secstrings = (void *)info->hdr + shstr->sh_offset;

    for (int i = 0; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (i && shdr->sh_type != SHT_NOBITS &&
            !elf_range_valid(shdr->sh_offset, shdr->sh_size, info->len))
            return -ENOEXEC;
        if (i && shdr->sh_addralign > 1 &&
            (shdr->sh_addralign & (shdr->sh_addralign - 1)))
            return -ENOEXEC;
        if (!elf_string_valid(info->secstrings, shstr->sh_size, shdr->sh_name))
            return -ENOEXEC;
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    info->sechdrs[0].sh_addr = 0;
    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        tools_loge("no .kpm.info section\n");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    out_info->name = get_modinfo(info, "name");
    out_info->version = get_modinfo(info, "version");
    out_info->license = get_modinfo(info, "license");
    out_info->author = get_modinfo(info, "author");
    out_info->description = get_modinfo(info, "description");

    if (!out_info->name || !out_info->version) return -ENOEXEC;
    return 0;
}

void print_kpm_info(kpm_info_t *info)
{
    fprintf(stdout, "name=%s\n", info->name);
    fprintf(stdout, "version=%s\n", info->version);
    fprintf(stdout, "license=%s\n", info->license ? info->license : "");
    fprintf(stdout, "author=%s\n", info->author ? info->author : "");
    fprintf(stdout, "description=%s\n", info->description ? info->description : "");
}

int print_kpm_info_path(const char *kpm_path)
{
    char *img;
    int len = 0;
    read_file(kpm_path, &img, &len);
    fprintf(stdout, INFO_EXTRA_KPM_SESSION "\n");
    kpm_info_t kpm_info = { 0 };
    int rc = get_kpm_info(img, len, &kpm_info);
    if (!rc) {
        print_kpm_info(&kpm_info);
    }
    free(img);
    return rc;
}
