/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <uapi/asm-generic/errno.h>
#include <pgtable.h>
#include <kpmalloc.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/string.h>
#include <symbol.h>
#include <kallsyms.h>
#include <cache.h>
#include <common.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <hotpatch.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* The freestanding KPIMG header subset does not expose UINT_MAX. */
#ifndef UINT_MAX
#define UINT_MAX (~0U)
#endif
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <kp_spinlock.h>

#include "module.h"
#include "relo.h"

/* Values match the stable Linux GFP_KERNEL mask used by the target kernels.
 * The freestanding KPIMG header subset leaves these convenience macros out. */
#ifndef GFP_KERNEL
#define GFP_KERNEL 0x0cc0u
#endif

#define SZ_128M 0x08000000

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define align(X) ALIGN(X, page_size)

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

#define ARCH_SHF_SMALL 0

/* The minimal KPIMG Linux headers intentionally expose only a subset of the
 * slab helpers. Keep these wrappers local and overflow-safe. */
static char *kp_module_strdup(const char *src, gfp_t flags)
{
    size_t len;
    char *copy;

    if (!src) return NULL;
    len = strlen(src) + 1;
    copy = kmalloc(len, flags);
    if (copy) memcpy(copy, src, len);
    return copy;
}

static void *kp_module_kcalloc(size_t count, size_t size, gfp_t flags)
{
    void *ptr;

    if (size && count > (~0UL / size)) return NULL;
    ptr = kmalloc(count * size, flags);
    if (ptr) memset(ptr, 0, count * size);
    return ptr;
}

static bool elf_range_valid(unsigned long offset, unsigned long size, unsigned long total)
{
    return offset <= total && size <= total - offset;
}

static bool elf_string_valid(const char *table, unsigned long table_size, unsigned int offset)
{
    return offset < table_size && memchr(table + offset, '\0', table_size - offset) != NULL;
}

static void set_load_error(struct load_info *info, const char *message)
{
    if (!info || !message) return;
    snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", message);
}

static const char *load_error(const struct load_info *info, const char *fallback)
{
    if (info && info->info.error_msg[0]) return info->info.error_msg;
    return fallback;
}

static bool kpm_load_result_enabled(void __user *reserved)
{
    if (!reserved) return false;

    struct kpm_load_result *result = memdup_user(reserved, sizeof(*result));
    if (!result || IS_ERR(result)) return false;

    bool enabled = result->magic == KPM_LOAD_RESULT_MAGIC && result->size >= sizeof(*result);
    kvfree(result);
    return enabled;
}

static void set_kpm_load_result(void __user *reserved, long code, const char *message)
{
    if (!kpm_load_result_enabled(reserved)) return;

    struct kpm_load_result result;
    memset(&result, 0, sizeof(result));
    result.magic = KPM_LOAD_RESULT_MAGIC;
    result.size = sizeof(result);
    result.code = code;
    if (message) snprintf(result.message, sizeof(result.message), "%s", message);
    compat_copy_to_user(reserved, &result, sizeof(result));
}

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/* Update size with this section: return offset, or a negative errno. */
static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    unsigned long alignment = sechdr->sh_addralign ?: 1;
    unsigned long offset = *size;

    if (alignment & (alignment - 1)) return -ENOEXEC;
    if (offset > (~0UL - (alignment - 1))) return -EOVERFLOW;
    offset = (offset + alignment - 1) & ~(alignment - 1);
    if (offset > ~0U || sechdr->sh_size > ~0U - offset) return -EOVERFLOW;
    *size = (unsigned int)(offset + sechdr->sh_size);
    return (long)offset;
}

static int align_module_size(unsigned int *size)
{
    unsigned long alignment = page_size;
    unsigned long value = *size;

    if (!alignment || (alignment & (alignment - 1)) ||
        value > (~0UL - (alignment - 1))) return -EOVERFLOW;
    value = (value + alignment - 1) & ~(alignment - 1);
    if (value > ~0U) return -EOVERFLOW;
    *size = (unsigned int)value;
    return 0;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long remaining = infosec->sh_size;
    char *cursor = (char *)info->hdr + infosec->sh_offset;
    unsigned int taglen = strlen(tag);

    if (prev) {
        if (prev < cursor || (unsigned long)(prev - cursor) >= remaining) return NULL;
        remaining -= (unsigned long)(prev - cursor);
        cursor = prev;
        char *end = memchr(cursor, '\0', remaining);
        if (!end) return NULL;
        unsigned long consumed = (unsigned long)(end - cursor) + 1;
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
        unsigned long entry_len = (unsigned long)(end - cursor);
        if (entry_len > taglen && !memcmp(cursor, tag, taglen) && cursor[taglen] == '=')
            return cursor + taglen + 1;
        unsigned long consumed = entry_len + 1;
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
        if (!(shdr->sh_flags & SHF_ALLOC) ||
            !elf_string_valid(info->secstrings, shstr->sh_size, shdr->sh_name))
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

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_size;
}

static int layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    // todo: tslf alloc all rwx and not page aligned
    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            long offset = get_offset(mod, &mod->size, s, i);
            if (offset < 0) return (int)offset;
            s->sh_entsize = (unsigned long)offset;
            // const char *sname = info->secstrings + s->sh_name;
        }
        switch (m) {
        case 0: /* executable */
            if (align_module_size(&mod->size)) return -EOVERFLOW;
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            if (align_module_size(&mod->size)) return -EOVERFLOW;
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            if (align_module_size(&mod->size)) return -EOVERFLOW;
            break;
        }
    }
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *section = &info->sechdrs[i];
        if ((section->sh_flags & SHF_ALLOC) && section->sh_entsize == ~0UL)
            return -ENOEXEC;
    }
    return 0;
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name) return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR)) return false;
    return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            /* No common-symbol allocator exists in this loader. */
            logkd("unsupported SHN_COMMON symbol %s; compile with -fno-common\n", name);
            if (!info->info.error_msg[0])
                snprintf(info->info.error_msg, sizeof(info->info.error_msg),
                         "unsupported common symbol: %s", name);
            ret = -ENOEXEC;
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF:
            unsigned long addr = symbol_lookup_name(name);
            // kernel symbol cause overflow in relocation
            // if (!addr) addr = kallsyms_lookup_name(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                if (!info->info.error_msg[0])
                    snprintf(info->info.error_msg, sizeof(info->info.error_msg), "unknown symbol: %s", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
        default: {
            Elf_Shdr *symsh;

            /* setup_load_info() validates indices before layout, but keep
             * this conversion safe when called with malformed load metadata. */
            if (sym[i].st_shndx >= info->hdr->e_shnum) {
                set_load_error(info, "invalid ELF symbol section index");
                return -ENOEXEC;
            }
            symsh = &info->sechdrs[sym[i].st_shndx];

            /* ET_REL st_value is an offset, not a runtime address. */
            if (sym[i].st_value > symsh->sh_size ||
                sym[i].st_size > symsh->sh_size - sym[i].st_value) {
                set_load_error(info, "ELF symbol extent exceeds its defining section");
                return -ENOEXEC;
            }
            secbase = symsh->sh_addr;
            if (sym[i].st_value > ~0UL - secbase) {
                set_load_error(info, "ELF symbol runtime address overflows");
                return -ENOEXEC;
            }
            sym[i].st_value += secbase;
            break;
        }
        }
    }
    return ret;
}

static int apply_relocations(struct module *mod, const struct load_info *info)
{
    unsigned int i;

    for (i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *relsec = &info->sechdrs[i];
        unsigned int target = relsec->sh_info;

        if (relsec->sh_type != SHT_REL && relsec->sh_type != SHT_RELA) continue;
        if (target == 0 || target >= info->hdr->e_shnum) return -ENOEXEC;
        if (relsec->sh_link != info->index.sym) return -ENOEXEC;

        /* Non-allocatable debug sections are not part of the loaded image. */
        if (!(info->sechdrs[target].sh_flags & SHF_ALLOC)) continue;

        /* AArch64 REL entries are not implemented: never report a no-op as success. */
        if (relsec->sh_type == SHT_REL) return -ENOEXEC;
        if (relsec->sh_entsize != sizeof(Elf64_Rela) ||
            relsec->sh_size % sizeof(Elf64_Rela)) return -ENOEXEC;

        int rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        if (rc < 0) return rc;
    }
    return 0;
}

// todo: free .strtab and .symtab after relocation
static int layout_symtab(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    long sym_offset = get_offset(mod, &mod->size, symsect, info->index.sym);
    if (sym_offset < 0) return (int)sym_offset;
    symsect->sh_entsize = (unsigned long)sym_offset;

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            unsigned long name_size = strlen(&info->strtab[src[i].st_name]) + 1;
            if (name_size > ~0U - strtab_size || ndst == ~0U) return -EOVERFLOW;
            strtab_size += (unsigned int)name_size;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    unsigned long sym_alignment = symsect->sh_addralign ?: 1;
    unsigned long symoffs = mod->size;
    if ((sym_alignment & (sym_alignment - 1)) ||
        symoffs > (~0UL - (sym_alignment - 1))) return -EOVERFLOW;
    symoffs = (symoffs + sym_alignment - 1) & ~(sym_alignment - 1);
    if (symoffs > ~0U || ndst > (~0U - symoffs) / sizeof(Elf_Sym)) return -EOVERFLOW;
    info->symoffs = (unsigned int)symoffs;
    info->stroffs = mod->size = (unsigned int)(symoffs + ndst * sizeof(Elf_Sym));
    if (strtab_size > ~0U - mod->size) return -EOVERFLOW;
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    long str_offset = get_offset(mod, &mod->size, strsect, info->index.str);
    if (str_offset < 0) return (int)str_offset;
    strsect->sh_entsize = (unsigned long)str_offset;
    return 0;
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS &&
            !elf_range_valid(shdr->sh_offset, shdr->sh_size, info->len)) {
            return -ENOEXEC;
        }
        /* SHT_NOBITS has no file-backed address. */
        shdr->sh_addr = shdr->sh_type == SHT_NOBITS ? 0 :
                        (unsigned long)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct module *mod, struct load_info *info)
{
    // todo:
    logki("alloc module size: %llx\n", mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
    logkd("final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        if (shdr->sh_entsize > mod->size ||
            shdr->sh_size > mod->size - shdr->sh_entsize) return -ENOEXEC;
        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        logkd("    %s %llx %llx\n", sname, dest, shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS) memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname)) mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;
        if (!mod->event && !strcmp(".kpm.event", sname)) mod->event = (mod_eventcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;

    if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    Elf_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB ||
        !elf_range_valid(shstr->sh_offset, shstr->sh_size, info->len) ||
        !shstr->sh_size) {
        set_load_error(info, "invalid ELF section-name string table");
        return -ENOEXEC;
    }
    info->secstrings = (void *)info->hdr + shstr->sh_offset;

    for (int i = 0; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!elf_string_valid(info->secstrings, shstr->sh_size, shdr->sh_name)) {
            set_load_error(info, "invalid ELF section name");
            return -ENOEXEC;
        }
        if (i && shdr->sh_type != SHT_NOBITS &&
            !elf_range_valid(shdr->sh_offset, shdr->sh_size, info->len)) {
            set_load_error(info, "ELF section data outside input");
            return -ENOEXEC;
        }
        if (shdr->sh_addralign > 1 &&
            (shdr->sh_addralign & (shdr->sh_addralign - 1))) {
            set_load_error(info, "invalid ELF section alignment");
            return -ENOEXEC;
        }
    }

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        set_load_error(info, "rewrite section headers failed");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        logke("no .kpm.init or .kpm.exit section\n");
        set_load_error(info, "no .kpm.init or .kpm.exit section");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        logke("no .kpm.info section\n");
        set_load_error(info, "no .kpm.info section");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        set_load_error(info, "module name not found");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module: \n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        set_load_error(info, "module version not found");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            Elf_Shdr *symsec = &info->sechdrs[i];
            if (symsec->sh_link >= info->hdr->e_shnum ||
                info->sechdrs[symsec->sh_link].sh_type != SHT_STRTAB ||
                symsec->sh_entsize != sizeof(Elf_Sym) ||
                symsec->sh_size % sizeof(Elf_Sym)) {
                set_load_error(info, "invalid ELF symbol table");
                return -ENOEXEC;
            }
            info->index.sym = i;
            info->index.str = symsec->sh_link;
            Elf_Shdr *strsec = &info->sechdrs[info->index.str];
            if (!strsec->sh_size) {
                set_load_error(info, "empty ELF symbol string table");
                return -ENOEXEC;
            }
            info->strtab = (char *)info->hdr + strsec->sh_offset;
            Elf_Sym *symbols = (void *)symsec->sh_addr;
            for (unsigned int n = 0; n < symsec->sh_size / sizeof(Elf_Sym); n++) {
                if (symbols[n].st_name >= strsec->sh_size ||
                    !memchr(info->strtab + symbols[n].st_name, '\0',
                            strsec->sh_size - symbols[n].st_name)) {
                    set_load_error(info, "invalid ELF symbol name");
                    return -ENOEXEC;
                }
                if (symbols[n].st_shndx != SHN_UNDEF &&
                    symbols[n].st_shndx != SHN_ABS &&
                    symbols[n].st_shndx != SHN_COMMON &&
                    symbols[n].st_shndx >= info->hdr->e_shnum) {
                    set_load_error(info, "invalid ELF symbol section index");
                    return -ENOEXEC;
                }
            }
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        set_load_error(info, "module has no symbols (stripped?)");
        return -ENOEXEC;
    }
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (!info || !info->hdr || info->len <= sizeof(*(info->hdr))) {
        set_load_error(info, "ELF header is truncated");
        return -ENOEXEC;
    }
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) ||
        info->hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        info->hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        info->hdr->e_ident[EI_VERSION] != EV_CURRENT ||
        info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_version != EV_CURRENT ||
        info->hdr->e_ehsize != sizeof(Elf_Ehdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr) ||
        !info->hdr->e_shnum || info->hdr->e_shstrndx >= info->hdr->e_shnum) {
        set_load_error(info, "ELF header is not a supported AArch64 relocatable module");
        return -ENOEXEC;
    }
    if (!elf_range_valid(info->hdr->e_shoff,
                         (unsigned long)info->hdr->e_shnum * sizeof(Elf_Shdr), info->len)) {
        set_load_error(info, "ELF section headers are invalid");
        return -ENOEXEC;
    }
    return 0;
}

struct module modules = { 0 };
static spinlock_t module_lock;
static unsigned long module_lock_acquire(void) { return kp_private_spin_lock(&module_lock); }
static void module_lock_release(unsigned long flags) { kp_private_spin_unlock(&module_lock, flags); }
static struct module *find_module_locked(const char *name)
{
    struct module *pos;
    if (!name) return NULL;
    list_for_each_entry(pos, &modules.list, list)
        if (!strcmp(name, pos->info.name)) return pos;
    return NULL;
}
int kp_hook_owner_register(unsigned long addr, void **owner)
{
    struct module *pos;
    unsigned long flags;
    int rc = 0;

    if (!owner)
        return -EINVAL;
    *owner = NULL;
    flags = module_lock_acquire();
    list_for_each_entry(pos, &modules.list, list) {
        unsigned long start = (unsigned long)pos->start;
        unsigned long image_end = start + pos->size;
        unsigned long text_end = start + pos->text_size;
        if (image_end < start || text_end < start ||
            addr < start || addr >= image_end) continue;
        /* Never mistake a pointer into KPM data/rodata for a kernel callback. */
        if (addr >= text_end) { rc = -EINVAL; break; }
        if (pos->state != KP_MODULE_LOADING && pos->state != KP_MODULE_LIVE) { rc = -EBUSY; break; }
        if (pos->hook_refs == UINT_MAX) { rc = -EOVERFLOW; break; }
        pos->hook_refs++; *owner = pos; rc = 1; break;
    }
    module_lock_release(flags); return rc;
}
void kp_hook_owner_unregister(void *owner)
{
    struct module *mod = owner;
    unsigned long flags;

    if (!mod)
        return;
    flags = module_lock_acquire();
    if (mod->hook_refs)
        mod->hook_refs--;
    module_lock_release(flags);
}
int kp_hook_owner_call_get(void *owner)
{
    struct module *mod = owner; unsigned long flags; int rc = 0;
    if (!mod)
        return 0;
    flags = module_lock_acquire();
    if ((mod->state == KP_MODULE_LIVE || mod->state == KP_MODULE_LOADING) &&
        mod->active_calls != UINT_MAX) { mod->active_calls++; rc = 1; }
    else if (mod->active_calls == UINT_MAX) rc = -EOVERFLOW;
    else rc = -EBUSY;
    module_lock_release(flags); return rc;
}
void kp_hook_owner_call_put(void *owner)
{
    struct module *mod = owner;
    unsigned long flags;

    if (!mod)
        return;
    flags = module_lock_acquire();
    if (mod->active_calls)
        mod->active_calls--;
    module_lock_release(flags);
}

/* Public KPM lifetime API for work items and callbacks outside Hook chains. */
int kp_kpm_owner_pin(unsigned long callback_addr, void **owner)
{
    return kp_hook_owner_register(callback_addr, owner);
}
KP_EXPORT_SYMBOL(kp_kpm_owner_pin);

void kp_kpm_owner_unpin(void *owner)
{
    kp_hook_owner_unregister(owner);
}
KP_EXPORT_SYMBOL(kp_kpm_owner_unpin);

int kp_kpm_owner_call_get(void *owner)
{
    return kp_hook_owner_call_get(owner);
}
KP_EXPORT_SYMBOL(kp_kpm_owner_call_get);

void kp_kpm_owner_call_put(void *owner)
{
    kp_hook_owner_call_put(owner);
}
KP_EXPORT_SYMBOL(kp_kpm_owner_call_put);

long load_module_ex(const void *data, int len, const char *args, const char *event, const char *source,
                    void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    struct module *mod = NULL;
    unsigned long flags;
    long rc = 0;
    if (!data || len <= 0) { rc = -EINVAL; set_load_error(info, "invalid module input"); goto out; }
    if ((rc = elf_header_check(info)) || (rc = setup_load_info(info))) goto out;
    mod = vmalloc(sizeof(*mod));
    if (!mod) { set_load_error(info, "allocate module state failed"); rc = -ENOMEM; goto out; }
    memset(mod, 0, sizeof(*mod)); INIT_LIST_HEAD(&mod->list);
    snprintf(mod->load_event, sizeof(mod->load_event), "%s", event ? event : "");
    snprintf(mod->load_source, sizeof(mod->load_source), "%s", source ? source : "embedded");
    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) { set_load_error(info, "allocate module args failed"); rc = -ENOMEM; goto free_mod; }
        strcpy(mod->args, args);
    }
    if ((rc = layout_sections(mod, info)) || (rc = layout_symtab(mod, info))) {
        set_load_error(info, "module layout failed"); goto free_mod;
    }
    if ((rc = move_module(mod, info))) { set_load_error(info, "module allocation failed"); goto free_mod; }
    if ((rc = simplify_symbols(mod, info)) || (rc = apply_relocations(mod, info))) goto free_mod;
    flush_icache_all();

    flags = module_lock_acquire();
    if (find_module_locked(mod->info.name)) {
        module_lock_release(flags); set_load_error(info, "module already exists or is loading");
        rc = -EEXIST; goto free_mod;
    }
    mod->state = KP_MODULE_LOADING; list_add_tail(&mod->list, &modules.list);
    module_lock_release(flags);

    rc = (*mod->init)(mod->args, event, reserved);
    flags = module_lock_acquire();
    if (!rc) {
        mod->state = KP_MODULE_LIVE; module_lock_release(flags);
        logkfi("[%s] succeed with [%s]\n", mod->info.name, args ? args : ""); goto out;
    }
    mod->state = KP_MODULE_UNLOADING;
    if (mod->active_calls) {
        module_lock_release(flags);
        rc = -EBUSY;
        goto out;
    }
    mod->state = KP_MODULE_EXITING;
    module_lock_release(flags);
    if (mod->exit) {
        long exit_rc = (*mod->exit)(reserved);
        if (exit_rc == -EBUSY) {
            flags = module_lock_acquire();
            mod->state = KP_MODULE_UNLOADING;
            mod->exit_called = false;
            module_lock_release(flags);
            rc = -EBUSY;
            goto out;
        }
    }
    flags = module_lock_acquire();
    mod->exit_called = true;
    if (mod->hook_refs || mod->active_calls) {
        module_lock_release(flags);
        logke("[%s] init failed; retaining image with hook_refs=%u active=%u\n",
              mod->info.name, mod->hook_refs, mod->active_calls);
        rc = -EBUSY; goto out;
    }
    list_del_init(&mod->list); mod->state = KP_MODULE_DEAD;
    module_lock_release(flags);
free_mod:
    if (mod) {
        if (mod->args) kvfree(mod->args);
        if (mod->start) kp_free_exec(mod->start);
        kvfree(mod);
    }
out:
    set_kpm_load_result(reserved, rc, rc ? load_error(info, "load module failed") : "module loaded");
    return rc;
}

/* Retryable unload: no callback can start after UNLOADING. The exit callback
 * runs outside the registry lock; hook registrations pin the image until
 * their chain readers drain and their slots are retired. */
long unload_module(const char *name, void *__user reserved)
{
    struct module *mod; unsigned long flags; long rc = 0;
    if (!name) return -EINVAL;
    flags = module_lock_acquire(); mod = find_module_locked(name);
    if (!mod) { module_lock_release(flags); return -ENOENT; }
    if (mod->state == KP_MODULE_LOADING) { module_lock_release(flags); return -EBUSY; }
    if (mod->state == KP_MODULE_LIVE) mod->state = KP_MODULE_UNLOADING;
    if (mod->state != KP_MODULE_UNLOADING && mod->state != KP_MODULE_EXITING) {
        module_lock_release(flags); return -ENOENT;
    }
    /* EXITING with exit_called=false is owned by the thread currently
     * executing the exit callback outside module_lock. */
    if (mod->state == KP_MODULE_EXITING && !mod->exit_called) {
        module_lock_release(flags); return -EBUSY;
    }
    if (mod->active_calls) { module_lock_release(flags); return -EBUSY; }
    if (!mod->exit_called) {
        mod->state = KP_MODULE_EXITING;
        module_lock_release(flags);
        if (mod->exit) rc = (*mod->exit)(reserved);
        flags = module_lock_acquire();
        if (rc == -EBUSY) {
            mod->state = KP_MODULE_UNLOADING;
            mod->exit_called = false;
            module_lock_release(flags);
            return -EBUSY;
        }
        mod->exit_called = true;
    }
    if (mod->active_calls || mod->hook_refs) {
        module_lock_release(flags);
        logkw("KPM %s retained: active=%u hook_refs=%u; retry after hook removal\n",
              name, mod->active_calls, mod->hook_refs);
        return -EBUSY;
    }
    list_del_init(&mod->list); mod->state = KP_MODULE_DEAD;
    module_lock_release(flags);
    if (mod->args) kvfree(mod->args);
    if (mod->start) kp_free_exec(mod->start);
    kvfree(mod);
    logkfi("name: %s, rc: %ld\n", name, rc);
    return rc;
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    return load_module_ex(data, len, args, event, "embedded", reserved);
}

long load_module_path_event(const char *path, const char *args, const char *event, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) {
        rc = -EINVAL;
        set_kpm_load_result(reserved, rc, "module path is null");
        return rc;
    }

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        set_kpm_load_result(reserved, rc, "open module file failed");
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    logkfd("module size: %llx\n", len);
    if (len <= 0 || len > 0x7fffffffLL) {
        rc = -EFBIG;
        set_kpm_load_result(reserved, rc, "module file size is invalid");
        goto close;
    }
    if (vfs_llseek(filp, 0, SEEK_SET) < 0) {
        rc = -EIO;
        set_kpm_load_result(reserved, rc, "seek module file failed");
        goto close;
    }

    void *data = vmalloc((unsigned long)len);
    if (!data) {
        rc = -ENOMEM;
        set_kpm_load_result(reserved, rc, "allocate module file buffer failed");
        goto close;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    ssize_t read_len = kernel_read(filp, data, len, &pos);
    filp_close(filp, 0);
    filp = 0;

    if (read_len != len || pos != len) {
        logkfe("read module: %s error\n", path);
        rc = -EIO;
        set_kpm_load_result(reserved, rc, "read module file failed");
        goto free;
    }

    rc = load_module_ex(data, len, args, event ? event : "load-file", "file", reserved);
free:
    kvfree(data);
close:
    if (filp) filp_close(filp, 0);
out:
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    return load_module_path_event(path, args, "load-file", reserved);
}

static struct module *module_get_live(const char *name)
{
    struct module *mod; unsigned long flags;
    if (!name) return NULL;
    flags = module_lock_acquire();
    mod = find_module_locked(name);
    if (!mod || mod->state != KP_MODULE_LIVE) mod = NULL;
    else if (mod->active_calls == UINT_MAX) mod = NULL;
    else mod->active_calls++;
    module_lock_release(flags);
    return mod;
}

static void module_put_live(struct module *mod)
{
    unsigned long flags;
    if (!mod) return;
    flags = module_lock_acquire();
    if (mod->active_calls) mod->active_calls--;
    module_lock_release(flags);
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    struct module *mod; char *args_copy; long rc;
    if (!name || !ctl_args || !*ctl_args) return -EINVAL;
    if (outlen < 0 || (outlen && !out_msg)) return -EINVAL;
    args_copy = kp_module_strdup(ctl_args, GFP_KERNEL);
    if (!args_copy) return -ENOMEM;
    mod = module_get_live(name);
    if (!mod) { kfree(args_copy); return -ENOENT; }
    if (!mod->ctl0 || !*mod->ctl0) rc = -ENOSYS;
    else rc = (*mod->ctl0)(args_copy, out_msg, outlen);
    kfree(args_copy);
    module_put_live(mod);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    struct module *mod; long rc;
    if (!name) return -EINVAL;
    mod = module_get_live(name);
    if (!mod) return -ENOENT;
    if (!mod->ctl1 || !*mod->ctl1) rc = -ENOSYS;
    else rc = (*mod->ctl1)(a1, a2, a3);
    module_put_live(mod);
    return rc;
}

long notify_modules_event(const char *event, const char *args, void *__user reserved)
{
    struct module **snapshot; struct module *pos;
    unsigned int capacity, n, i; unsigned long flags;
    long result = 0; int count = 0;
    if (!event) return -EINVAL;
    for (;;) {
        capacity = 0;
        flags = module_lock_acquire();
        list_for_each_entry(pos, &modules.list, list)
            if (pos->state == KP_MODULE_LIVE && pos->event && *pos->event) capacity++;
        module_lock_release(flags);
        snapshot = kp_module_kcalloc(capacity ? capacity : 1, sizeof(*snapshot), GFP_KERNEL);
        if (!snapshot) return -ENOMEM;
        flags = module_lock_acquire();
        n = 0;
        list_for_each_entry(pos, &modules.list, list)
            if (pos->state == KP_MODULE_LIVE && pos->event && *pos->event) n++;
        if (n > capacity) {
            module_lock_release(flags); kfree(snapshot); continue;
        }
        n = 0;
        {
            bool overflow = false;
            list_for_each_entry(pos, &modules.list, list) {
                if (pos->state != KP_MODULE_LIVE || !pos->event || !*pos->event) continue;
                if (pos->active_calls == UINT_MAX) { overflow = true; break; }
                pos->active_calls++; snapshot[n++] = pos;
            }
            if (overflow) {
                for (i = 0; i < n; i++) snapshot[i]->active_calls--;
                module_lock_release(flags); kfree(snapshot); return -EOVERFLOW;
            }
        }
        module_lock_release(flags);
        break;
    }
    for (i = 0; i < n; i++) {
        long rc = (*snapshot[i]->event)(event, args, reserved);
        if (rc < 0 && !result) result = rc;
        count++;
        module_put_live(snapshot[i]);
    }
    kfree(snapshot);
    return result ? result : count;
}
KP_EXPORT_SYMBOL(notify_modules_event);


int get_module_nums(void)
{
    struct module *pos; unsigned long flags; int n = 0;
    flags = module_lock_acquire();
    list_for_each_entry(pos, &modules.list, list)
        if (pos->state == KP_MODULE_LIVE) n++;
    module_lock_release(flags);
    return n;
}

int list_modules(char *out_names, int size)
{
    struct module *pos; unsigned long flags; int off = 0;
    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';
    flags = module_lock_acquire();
    list_for_each_entry(pos, &modules.list, list) {
        int written;
        if (pos->state != KP_MODULE_LIVE || off >= size - 1) continue;
        written = snprintf(out_names + off, size - off, "%s\n", pos->info.name);
        if (written > 0) off += (size_t)written < size - off - 1 ? (size_t)written : size - off - 1;
    }
    module_lock_release(flags);
    if (off > 0 && out_names[off - 1] == '\n') off--;
    out_names[off] = '\0';
    return off;
}

int get_module_info(const char *name, char *out_info, int size)
{
    struct module *mod; int sz;
    if (!name || !out_info || size <= 0) return -EINVAL;
    mod = module_get_live(name);
    if (!mod) return -ENOENT;
    sz = snprintf(out_info, size,
                  "name=%s\nversion=%s\nlicense=%s\nauthor=%s\ndescription=%s\nargs=%s\nload_event=%s\nload_source=%s\n",
                  mod->info.name, mod->info.version, mod->info.license, mod->info.author,
                  mod->info.description, mod->args ? mod->args : "", mod->load_event, mod->load_source);
    if (sz < 0) sz = 0;
    out_info[size - 1] = '\0';
    module_put_live(mod);
    return sz;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);
}
