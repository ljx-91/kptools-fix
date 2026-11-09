// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch Module (KPM) loader for the LKM framework. Ported from
 * kernel/patch/module/module.c. The KPM is a relocatable ELF; undefined
 * symbols resolve against the running kernel via kallsyms (KP uses its own
 * symbol_lookup_name there). Executable memory comes from module_alloc()
 * (module_memfree() to release), both resolved at runtime since they are not
 * exported to modules on GKI.
 */
#include "module.h"
#include "relo.h"
#include "symbols.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

/* The freestanding KPIMG header subset does not expose UINT_MAX. */
#ifndef UINT_MAX
#define UINT_MAX (~0U)
#endif
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "../include/kp_lkm.h"

#define SZ_128M 0x08000000

#define ARCH_SHF_SMALL 0

/* arm64 PTE permission bits. PXN (bit53) / UXN (bit54) gate execution;
 * GP (bit50) enables BTI. KPM pages must have them all clear. */
#ifndef PTE_PXN
#define KP_LKM_PTE_PXN (1UL << 53)
#define KP_LKM_PTE_UXN (1UL << 54)
#define KP_LKM_PTE_GP  (1UL << 50)
#else
#define KP_LKM_PTE_PXN PTE_PXN
#define KP_LKM_PTE_UXN PTE_UXN
#define KP_LKM_PTE_GP  PTE_GP
#endif

/* Runtime-resolved kernel symbols (not exported on GKI 5.15). */
static void *(*kp_module_alloc)(unsigned long size);
static void (*kp_module_memfree)(void *module_region);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#include <linux/execmem.h>
static void *(*kp_execmem_alloc)(enum execmem_type type, size_t size);
static void (*kp_execmem_free)(void *ptr);
#else
static void *(*kp_execmem_alloc)(int type, size_t size);
static void (*kp_execmem_free)(void *ptr);
#endif
static void (*kp_flush_icache_all_fn)(void);
static int (*kp_set_memory_x)(unsigned long addr, int numpages);
static int (*kp_set_memory_nx)(unsigned long addr, int numpages);

/* init_mm (resolved at runtime, not exported on GKI). */
static struct mm_struct *kp_kpm_init_mm;

enum kp_exec_backend {
	KP_EXEC_BACKEND_NONE,
	KP_EXEC_BACKEND_MODULE,
	KP_EXEC_BACKEND_EXECMEM,
	KP_EXEC_BACKEND_VMALLOC,
};
static enum kp_exec_backend kp_exec_backend;

/* Clear the Guarded-Page bit (BTI enable), Privileged-eXecute-Never and
 * User-eXecute-Never. Fail closed if any page cannot be inspected or made
 * executable: the KPM must never enter init on an NX/BTI-incompatible image. */
static int kp_update_bti_gp(unsigned long base, unsigned long size, bool executable)
{
	unsigned long addr, end;

	if (!kp_kpm_init_mm || !base || !size || size > ULONG_MAX - base)
		return -ENOSYS;
	end = base + size;
	for (addr = base; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgd = pgd_offset(kp_kpm_init_mm, addr);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		spinlock_t *ptl;
		pteval_t v;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			return -EFAULT;
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			return -EFAULT;
		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud) || pud_sect(*pud))
			return -EFAULT;
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_sect(*pmd))
			return -EFAULT;
		ptl = pte_lockptr(kp_kpm_init_mm, pmd);
		spin_lock(ptl);
		pte = pte_offset_kernel(pmd, addr);
		if (!pte || !pte_present(*pte)) {
			spin_unlock(ptl);
			return -EFAULT;
		}
		v = pte_val(*pte);
		if (executable)
			v &= ~(KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP);
		else
			v |= KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP;
		set_pte_at(kp_kpm_init_mm, addr, pte, __pte(v));
		if (executable ?
		    (pte_val(*pte) & (KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP)) :
		    ((pte_val(*pte) & (KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP)) !=
		     (KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP))) {
			spin_unlock(ptl);
			return -EACCES;
		}
		spin_unlock(ptl);
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	}
	return 0;
}

static int kp_clear_bti_gp(unsigned long base, unsigned long size)
{
	return kp_update_bti_gp(base, size, true);
}

__attribute__((no_sanitize("cfi"), __noinline__))
static int kp_restore_nx_gp(unsigned long base, unsigned long size)
{
	if (kp_set_memory_nx)
		kp_set_memory_nx(base, (size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	return kp_update_bti_gp(base, size, false);
}

/* Runtime-resolved kernel functions and raw KPM callbacks cannot participate
 * in this LKM's CFI jump table. Keep CFI enabled everywhere else and exempt
 * only these indirect-call boundaries. noinline: if inlined into a
 * CFI-instrumented caller, the kCFI type-hash load of [fnptr - 4] dereferences
 * NULL when the allocator is absent (6.10+ has no module_alloc). */
__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_malloc_exec(unsigned long size)
{
	if (!size || size > ULONG_MAX - (PAGE_SIZE - 1))
		return NULL;
	switch (kp_exec_backend) {
	case KP_EXEC_BACKEND_MODULE:
		return kp_module_alloc(size);
	case KP_EXEC_BACKEND_EXECMEM:
		return kp_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
	case KP_EXEC_BACKEND_VMALLOC:
		return vmalloc(size);
	default:
		return NULL;
	}
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_free_exec(void *region, unsigned long size)
{
	if (!region)
		return;
	/* Never return executable pages to a general allocator. If NX/BTI
	 * restoration cannot be verified, deliberately leak the region. */
	if (kp_restore_nx_gp((unsigned long)region, size)) {
		logke("KPM executable memory permission restore failed; leaking %px\n", region);
		return;
	}
	switch (kp_exec_backend) {
	case KP_EXEC_BACKEND_MODULE:
		kp_module_memfree(region);
		break;
	case KP_EXEC_BACKEND_EXECMEM:
		kp_execmem_free(region);
		break;
	case KP_EXEC_BACKEND_VMALLOC:
		vfree(region);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}

__attribute__((no_sanitize("cfi")))
static void kp_flush_kpm_icache(void *start, size_t size)
{
	(void)start; (void)size; (void)kp_flush_icache_all_fn;
	dsb(ishst);
	asm volatile("ic iallu");
	dsb(ish);
	isb();
}

__attribute__((no_sanitize("cfi")))
static long kp_call_init(mod_initcall_t *fn, const char *args, const char *event,
			 void __user *reserved)
{
	return (*fn)(args, event, reserved);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_exit(mod_exitcall_t *fn, void __user *reserved)
{
	/* KPM exit callbacks are optional. */
	return fn ? (*fn)(reserved) : 0;
}

__attribute__((no_sanitize("cfi")))
static int kp_do_set_memory_x(unsigned long addr, int npages)
{
	return kp_set_memory_x(addr, npages);
}

__attribute__((no_sanitize("cfi")))
static int kp_do_set_memory_nx(unsigned long addr, int npages)
{
	return kp_set_memory_nx(addr, npages);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_ctl0(mod_ctl0call_t *fn, const char *args, char __user *out, int outlen)
{
	return (*fn)(args, out, outlen);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_ctl1(mod_ctl1call_t *fn, void *a1, void *a2, void *a3)
{
	return (*fn)(a1, a2, a3);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_event(mod_eventcall_t *fn, const char *event, const char *args,
			  void __user *reserved)
{
	return (*fn)(event, args, reserved);
}

static void set_load_error(struct kp_load_info *info, const char *message)
{
	if (!info || !message)
		return;
	snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", message);
}

static const char *load_error(const struct kp_load_info *info, const char *fallback)
{
	if (info && info->info.error_msg[0])
		return info->info.error_msg;
	return fallback;
}

static bool kpm_load_result_enabled(void __user *reserved)
{
	if (!reserved)
		return false;

	struct kpm_load_result *result = memdup_user(reserved, sizeof(*result));
	if (IS_ERR(result))
		return false;

	bool enabled = result->magic == KPM_LOAD_RESULT_MAGIC && result->size >= sizeof(*result);
	kvfree(result);
	return enabled;
}

static void set_kpm_load_result(void __user *reserved, long code, const char *message)
{
	if (!kpm_load_result_enabled(reserved))
		return;

	struct kpm_load_result result;
	memset(&result, 0, sizeof(result));
	result.magic = KPM_LOAD_RESULT_MAGIC;
	result.size = sizeof(result);
	result.code = code;
	if (message)
		snprintf(result.message, sizeof(result.message), "%s", message);
	if (copy_to_user(reserved, &result, sizeof(result)))
		logkd("kpm load result: copy_to_user failed\n");
}

static char *next_string(char *string, unsigned long *secsize)
{
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return 0;
	}
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return 0;
	}
	return string;
}

/* Reserve a section extent without allowing alignment/addition overflow. */
static int get_offset(unsigned int *size, Elf_Shdr *sechdr, unsigned int *offset)
{
	unsigned long align = sechdr->sh_addralign ?: 1;
	unsigned long start;

	if (!size || !sechdr || !offset || align > UINT_MAX ||
	    (align > 1 && (align & (align - 1))))
		return -ENOEXEC;
	if (*size > UINT_MAX - (align - 1))
		return -EOVERFLOW;
	start = (*size + align - 1) & ~(align - 1);
	if (sechdr->sh_size > UINT_MAX - start)
		return -EOVERFLOW;
	*offset = start;
	*size = start + sechdr->sh_size;
	return 0;
}

static int kp_align_module_size(unsigned int *size, unsigned int align)
{
	unsigned long aligned;

	if (!size || !align || (align & (align - 1)) ||
	    *size > UINT_MAX - (align - 1))
		return -EOVERFLOW;
	aligned = (*size + align - 1) & ~(align - 1);
	if (aligned > UINT_MAX)
		return -EOVERFLOW;
	*size = aligned;
	return 0;
}

static char *get_next_modinfo(const struct kp_load_info *info, const char *tag, char *prev)
{
	char *p;
	unsigned int taglen = strlen(tag);
	Elf_Shdr *infosec = &info->sechdrs[info->index.info];
	unsigned long size = infosec->sh_size;
	char *modinfo = (char *)info->hdr + infosec->sh_offset;
	if (prev) {
		size -= prev - modinfo;
		modinfo = next_string(prev, &size);
	}
	for (p = modinfo; p; p = next_string(p, &size)) {
		if (strlen(p) >= taglen && strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
			return p + taglen + 1;
	}
	return 0;
}

static char *get_modinfo(const struct kp_load_info *info, const char *tag)
{
	return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct kp_load_info *info, const char *name)
{
	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &info->sechdrs[i];
		if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static void *get_sh_base(struct kp_load_info *info, const char *secname)
{
	int idx = find_sec(info, secname);
	if (!idx)
		return 0;
	Elf_Shdr *infosec = &info->sechdrs[idx];
	void *addr = (void *)info->hdr + infosec->sh_offset;
	return addr;
}

static unsigned long get_sh_size(struct kp_load_info *info, const char *secname)
{
	int idx = find_sec(info, secname);
	if (!idx)
		return 0;
	Elf_Shdr *infosec = &info->sechdrs[idx];
	return infosec->sh_size;
}

static int layout_sections(struct kp_module *mod, struct kp_load_info *info)
{
	static unsigned long const masks[][2] = {
		/* executable code must be first; text_size finder relies on it */
		{ SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
		{ SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
		{ ARCH_SHF_SMALL | SHF_ALLOC, 0 },
	};

	for (int i = 0; i < info->hdr->e_shnum; i++)
		info->sechdrs[i].sh_entsize = ~0UL;

	for (int m = 0; m < (int)(sizeof(masks) / sizeof(masks[0])); ++m) {
		for (int i = 0; i < info->hdr->e_shnum; ++i) {
			unsigned int offset;
			Elf_Shdr *s = &info->sechdrs[i];
			if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) ||
			    s->sh_entsize != ~0UL)
				continue;
			if (get_offset(&mod->size, s, &offset))
				return -EOVERFLOW;
			s->sh_entsize = offset;
		}
		switch (m) {
		case 0: /* executable */
			if (kp_align_module_size(&mod->size, PAGE_SIZE))
				return -EOVERFLOW;
			mod->text_size = mod->size;
			break;
		case 1: /* RO: text and ro-data */
			if (kp_align_module_size(&mod->size, PAGE_SIZE))
				return -EOVERFLOW;
			mod->ro_size = mod->size;
			break;
		case 2:
			break;
		case 3: /* whole */
			if (kp_align_module_size(&mod->size, PAGE_SIZE))
				return -EOVERFLOW;
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
	if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
		return false;
	sec = sechdrs + src->st_shndx;
	if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR))
		return false;
	return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct kp_module *mod, struct kp_load_info *info)
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
			/* The loader has no common-symbol allocator. Treat every
			 * SHN_COMMON entry as unsupported rather than interpreting
			 * its alignment-valued st_value as a runtime address. */
			logkd("unsupported SHN_COMMON symbol %s; compile with -fno-common\n", name);
			if (!info->info.error_msg[0])
				snprintf(info->info.error_msg, sizeof(info->info.error_msg),
					 "unsupported common symbol: %s", name);
			ret = -ENOEXEC;
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF:
		{
			unsigned long addr = kp_kpm_symbol_lookup(name);
			if (!addr)
				addr = kallsyms_lookup_name(name);
			if (!addr) {
				logke("unknown symbol: %s\n", name);
				if (!info->info.error_msg[0])
					snprintf(info->info.error_msg, sizeof(info->info.error_msg),
						 "unknown symbol: %s", name);
				ret = -ENOENT;
				break;
			}
			sym[i].st_value = addr;
			break;
		}
		default:
			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
	}
	return ret;
}

static int apply_relocations(struct kp_module *mod, const struct kp_load_info *info)
{
	int rc = 0;
	unsigned int i;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		unsigned int infosec = info->sechdrs[i].sh_info;
		if (info->sechdrs[i].sh_type != SHT_REL &&
		    info->sechdrs[i].sh_type != SHT_RELA)
			continue;
		if (infosec == 0 || infosec >= info->hdr->e_shnum ||
		    !(info->sechdrs[infosec].sh_flags & SHF_ALLOC) ||
		    info->sechdrs[i].sh_link != info->index.sym)
			return -ENOEXEC;
		if (info->sechdrs[i].sh_type == SHT_REL) {
			rc = kp_apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
		} else if (info->sechdrs[i].sh_type == SHT_RELA) {
			rc = kp_apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
		}
		if (rc < 0)
			break;
	}
	return rc;
}

static int layout_symtab(struct kp_module *mod, struct kp_load_info *info)
{
	Elf_Shdr *symsect = info->sechdrs + info->index.sym;
	Elf_Shdr *strsect = info->sechdrs + info->index.str;
	const Elf_Sym *src;
	unsigned int i, nsrc, ndst;
	unsigned long strtab_size = 0;
	unsigned int sym_offset;

	/* Put symbol section at end of module. */
	symsect->sh_flags |= SHF_ALLOC;
	if (get_offset(&mod->size, symsect, &sym_offset))
		return -EOVERFLOW;
	symsect->sh_entsize = sym_offset;

	src = (void *)info->hdr + symsect->sh_offset;
	nsrc = symsect->sh_size / sizeof(*src);

	/* strtab always starts with a nul, so offset 0 is the empty string. */
	strtab_size = 1;
	for (ndst = i = 0; i < nsrc; i++) {
		if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
			unsigned long name_size = strlen(&info->strtab[src[i].st_name]) + 1;
			if (name_size > UINT_MAX - strtab_size)
				return -EOVERFLOW;
			strtab_size += name_size;
			ndst++;
		}
	}

	/* Append room for core symbols at end. */
	{
		unsigned int aligned;
		unsigned long align = symsect->sh_addralign ?: 1;
		if (align > UINT_MAX || mod->size > UINT_MAX - (align - 1))
			return -EOVERFLOW;
		aligned = (mod->size + align - 1) & ~(align - 1);
		info->symoffs = aligned;
	}
	if (ndst > (UINT_MAX - info->symoffs) / sizeof(Elf_Sym))
		return -EOVERFLOW;
	info->stroffs = info->symoffs + ndst * sizeof(Elf_Sym);
	if (strtab_size > UINT_MAX - info->stroffs)
		return -EOVERFLOW;
	mod->size = info->stroffs + strtab_size;

	/* Put string table section at end of module. */
	strsect->sh_flags |= SHF_ALLOC;
	{
		unsigned int offset;
		if (get_offset(&mod->size, strsect, &offset))
			return -EOVERFLOW;
		strsect->sh_entsize = offset;
	}
	return 0;
}

static bool kp_elf_range_valid(unsigned long total, unsigned long offset,
				 unsigned long size)
{
	return offset <= total && size <= total - offset;
}

static bool kp_elf_string_valid(const char *table, unsigned long table_size,
				unsigned long offset)
{
	return table && offset < table_size &&
		memchr(table + offset, '\0', table_size - offset) != NULL;
}

static int rewrite_section_headers(struct kp_load_info *info)
{
	Elf_Shdr *shstr;
	unsigned int i;

	if (!info || !info->hdr || !info->sechdrs ||
	    info->hdr->e_shstrndx == SHN_UNDEF ||
	    info->hdr->e_shstrndx >= info->hdr->e_shnum)
		return -ENOEXEC;

	shstr = &info->sechdrs[info->hdr->e_shstrndx];
	if (shstr->sh_type != SHT_STRTAB || !shstr->sh_size ||
	    !kp_elf_range_valid(info->len, shstr->sh_offset, shstr->sh_size) ||
	    *((const char *)info->hdr + shstr->sh_offset) != '\0')
		return -ENOEXEC;
	info->secstrings = (char *)info->hdr + shstr->sh_offset;

	info->sechdrs[0].sh_addr = 0;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &info->sechdrs[i];

		if (shdr->sh_type != SHT_NOBITS &&
		    !kp_elf_range_valid(info->len, shdr->sh_offset, shdr->sh_size))
			return -ENOEXEC;
		if (shdr->sh_addralign > 1 &&
		    (shdr->sh_addralign & (shdr->sh_addralign - 1)))
			return -ENOEXEC;
		if (!kp_elf_string_valid(info->secstrings, shstr->sh_size, shdr->sh_name))
			return -ENOEXEC;

		/* NOBITS has no file-backed address; alloc NOBITS gets its
		 * destination address later in move_module(). */
		shdr->sh_addr = shdr->sh_type == SHT_NOBITS ? 0 :
			(unsigned long)info->hdr + shdr->sh_offset;
	}
	return 0;
}

static int move_module(struct kp_module *mod, struct kp_load_info *info)
{
	logki("kpm alloc module size: %x\n", mod->size);
	mod->start = kp_malloc_exec(mod->size);
	if (!mod->start)
		return -ENOMEM;
	memset(mod->start, 0, mod->size);

	for (int i = 1; i < info->hdr->e_shnum; i++) {
		void *dest;
		Elf_Shdr *shdr = &info->sechdrs[i];
		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;
		if (shdr->sh_entsize > mod->size ||
		    shdr->sh_size > mod->size - shdr->sh_entsize)
			return -ENOEXEC;

		dest = mod->start + shdr->sh_entsize;
		const char *sname = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

		shdr->sh_addr = (unsigned long)dest;

		if (!mod->init && !strcmp(".kpm.init", sname))
			mod->init = (mod_initcall_t *)dest;
		if (!strcmp(".kpm.ctl0", sname))
			mod->ctl0 = (mod_ctl0call_t *)dest;
		if (!strcmp(".kpm.ctl1", sname))
			mod->ctl1 = (mod_ctl1call_t *)dest;
		if (!mod->exit && !strcmp(".kpm.exit", sname))
			mod->exit = (mod_exitcall_t *)dest;
		if (!mod->event && !strcmp(".kpm.event", sname))
			mod->event = (mod_eventcall_t *)dest;
		if (!mod->info.base && !strcmp(".kpm.info", sname))
			mod->info.base = (const char *)dest;
	}
	mod->info.name = info->info.name - info->info.base + mod->info.base;
	mod->info.version = info->info.version - info->info.base + mod->info.base;

	if (info->info.license)
		mod->info.license = info->info.license - info->info.base + mod->info.base;
	if (info->info.author)
		mod->info.author = info->info.author - info->info.base + mod->info.base;
	if (info->info.description)
		mod->info.description = info->info.description - info->info.base + mod->info.base;

	return 0;
}

static int setup_load_info(struct kp_load_info *info)
{
	int rc = 0;
	/* elf_header_check() has already range-checked and assigned sechdrs. */
	if (!info->sechdrs)
		return -ENOEXEC;

	if ((rc = rewrite_section_headers(info))) {
		logke("rewrite section error\n");
		set_load_error(info, "rewrite section headers failed");
		return rc;
	}

	{
		int init_idx = find_sec(info, ".kpm.init");
		int exit_idx = find_sec(info, ".kpm.exit");
		if (!init_idx || !exit_idx ||
		    !(info->sechdrs[init_idx].sh_flags & SHF_EXECINSTR) ||
		    !(info->sechdrs[exit_idx].sh_flags & SHF_EXECINSTR) ||
		    !info->sechdrs[init_idx].sh_size ||
		    !info->sechdrs[exit_idx].sh_size) {
			logke("missing or invalid .kpm.init/.kpm.exit executable sections\n");
			set_load_error(info, "missing or invalid .kpm.init/.kpm.exit sections");
			return -ENOEXEC;
		}
	}

	info->index.info = find_sec(info, ".kpm.info");
	if (!info->index.info) {
		logke("no .kpm.info section\n");
		set_load_error(info, "no .kpm.info section");
		return -ENOEXEC;
	}
	if (info->sechdrs[info->index.info].sh_type != SHT_PROGBITS ||
	    !info->sechdrs[info->index.info].sh_size) {
		set_load_error(info, ".kpm.info must be a non-empty PROGBITS section");
		return -ENOEXEC;
	}
	info->info.base = get_sh_base(info, ".kpm.info");
	info->info.size = get_sh_size(info, ".kpm.info");
	if (!info->info.base || !info->info.size ||
	    info->info.base[info->info.size - 1] != '\0') {
		set_load_error(info, "invalid .kpm.info string table");
		return -ENOEXEC;
	}

	const char *name = get_modinfo(info, "name");
	if (!name) {
		logke("module name not found\n");
		set_load_error(info, "module name not found");
		return -ENOEXEC;
	}
	info->info.name = name;
	logkd("loading module:\n");
	logkd("    name: %s\n", name);

	const char *version = get_modinfo(info, "version");
	if (!version) {
		logkd("module version not found\n");
		set_load_error(info, "module version not found");
		return -ENOEXEC;
	}
	info->info.version = version;
	logkd("    version: %s\n", version);

	info->info.license = get_modinfo(info, "license");
	info->info.author = get_modinfo(info, "author");
	info->info.description = get_modinfo(info, "description");

	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *symsec = &info->sechdrs[i];
		Elf_Shdr *strsec;

		if (symsec->sh_type != SHT_SYMTAB)
			continue;
		if (info->index.sym) {
			set_load_error(info, "multiple symbol tables are unsupported");
			return -ENOEXEC;
		}
		if (symsec->sh_entsize != sizeof(Elf_Sym) ||
		    symsec->sh_size % sizeof(Elf_Sym) ||
		    symsec->sh_link >= info->hdr->e_shnum) {
			set_load_error(info, "invalid ELF symbol table metadata");
			return -ENOEXEC;
		}
		strsec = &info->sechdrs[symsec->sh_link];
		if (strsec->sh_type != SHT_STRTAB ||
		    !kp_elf_range_valid(info->len, strsec->sh_offset, strsec->sh_size) ||
		    !strsec->sh_size || *((const char *)info->hdr + strsec->sh_offset) != '\0') {
			set_load_error(info, "invalid ELF symbol string table");
			return -ENOEXEC;
		}
		info->index.sym = i;
		info->index.str = symsec->sh_link;
		info->strtab = (char *)info->hdr + strsec->sh_offset;
	}

	if (!info->index.sym) {
		logkd("module has no symbols (stripped?)\n");
		set_load_error(info, "module has no symbols (stripped?)");
		return -ENOEXEC;
	}
	{
		Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
		Elf_Shdr *strsec = &info->sechdrs[info->index.str];
		Elf_Sym *syms = (Elf_Sym *)((char *)info->hdr + symsec->sh_offset);
		unsigned int nsyms = symsec->sh_size / sizeof(*syms);
		unsigned int n;

		for (n = 0; n < nsyms; n++) {
			if (!kp_elf_string_valid(info->strtab, strsec->sh_size, syms[n].st_name)) {
				set_load_error(info, "ELF symbol name is outside its string table");
				return -ENOEXEC;
			}
			if (syms[n].st_shndx < SHN_LORESERVE &&
			    syms[n].st_shndx >= info->hdr->e_shnum) {
				set_load_error(info, "ELF symbol section index is invalid");
				return -ENOEXEC;
			}
			if (syms[n].st_shndx == SHN_XINDEX ||
			    (syms[n].st_shndx >= SHN_LORESERVE &&
			     syms[n].st_shndx != SHN_UNDEF &&
			     syms[n].st_shndx != SHN_ABS &&
			     syms[n].st_shndx != SHN_COMMON)) {
				set_load_error(info, "reserved ELF symbol section index is unsupported");
				return -ENOEXEC;
			}
		}
	}
	return 0;
}

static int elf_header_check(struct kp_load_info *info)
{
	const Elf_Ehdr *ehdr;
	unsigned long shdr_bytes;

	if (!info || !info->hdr || info->len < sizeof(*info->hdr)) {
		set_load_error(info, "ELF header is truncated");
		return -ENOEXEC;
	}
	ehdr = info->hdr;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_version != EV_CURRENT || ehdr->e_ehsize != sizeof(*ehdr) ||
	    ehdr->e_type != ET_REL || ehdr->e_machine != EM_AARCH64 ||
	    ehdr->e_shentsize != sizeof(Elf_Shdr) || ehdr->e_shnum < 2 ||
	    ehdr->e_shstrndx == SHN_UNDEF || ehdr->e_shstrndx >= ehdr->e_shnum) {
		set_load_error(info, "ELF header is not a supported AArch64 ELF64 relocatable module");
		return -ENOEXEC;
	}
	if (ehdr->e_shnum > (~0UL / sizeof(Elf_Shdr))) {
		set_load_error(info, "ELF section header count overflows");
		return -ENOEXEC;
	}
	shdr_bytes = (unsigned long)ehdr->e_shnum * sizeof(Elf_Shdr);
	if (!kp_elf_range_valid(info->len, ehdr->e_shoff, shdr_bytes)) {
		set_load_error(info, "ELF section headers are outside the input image");
		return -ENOEXEC;
	}
	info->sechdrs = (Elf_Shdr *)((char *)info->hdr + ehdr->e_shoff);
	return 0;
}

struct kp_module modules = { 0 };
static spinlock_t module_lock;
static bool kp_kpm_ready;

/* state and active_calls are protected by module_lock. */
static struct kp_module *kp_find_module_locked(const char *name)
{
	struct kp_module *pos;
	list_for_each_entry(pos, &modules.list, list) {
		if (!strcmp(name, pos->info.name))
			return pos;
	}
	return NULL;
}

static struct kp_module *kp_module_get(const char *name)
{
	struct kp_module *mod;
	unsigned long flags;

	if (!name || !READ_ONCE(kp_kpm_ready))
		return NULL;
	spin_lock_irqsave(&module_lock, flags);
	mod = kp_find_module_locked(name);
	if (!mod || mod->state != KP_MODULE_LIVE)
		mod = NULL;
	else if (mod->active_calls == UINT_MAX)
		mod = NULL;
	else
		mod->active_calls++;
	spin_unlock_irqrestore(&module_lock, flags);
	return mod;
}

static void kp_module_put(struct kp_module *mod)
{
	unsigned long flags;

	if (!mod)
		return;
	spin_lock_irqsave(&module_lock, flags);
	if (WARN_ON_ONCE(!mod->active_calls)) {
		spin_unlock_irqrestore(&module_lock, flags);
		return;
	}
	mod->active_calls--;
	spin_unlock_irqrestore(&module_lock, flags);
}

/* Persistent hook references pin a KPM image while any published chain slot
 * can still name its callback. Transient call refs protect actual execution. */
int kp_hook_owner_register(unsigned long addr, void **owner)
{
	struct kp_module *pos;
	unsigned long flags;
	int rc = 0;

	if (!owner)
		return -EINVAL;
	*owner = NULL;
	spin_lock_irqsave(&module_lock, flags);
	list_for_each_entry(pos, &modules.list, list) {
		unsigned long start = (unsigned long)pos->start;
		unsigned long image_end = start + pos->size;
		unsigned long text_end = start + pos->text_size;

		if (image_end < start || text_end < start ||
		    addr < start || addr >= image_end)
			continue;
		/* An address inside a KPM image but outside executable text is
		 * never a kernel-resident callback and must not be treated as
		 * ownerless. */
		if (addr >= text_end) {
			rc = -EINVAL;
			break;
		}
		if (pos->state != KP_MODULE_LOADING && pos->state != KP_MODULE_LIVE) {
			rc = -EBUSY;
			break;
		}
		if (pos->hook_refs == UINT_MAX) {
			rc = -EOVERFLOW;
			break;
		}
		pos->hook_refs++;
		*owner = pos;
		rc = 1;
		break;
	}
	spin_unlock_irqrestore(&module_lock, flags);
	return rc;
}

void kp_hook_owner_unregister(void *owner)
{
	struct kp_module *mod = owner;
	unsigned long flags;

	if (!mod)
		return;
	spin_lock_irqsave(&module_lock, flags);
	if (mod->hook_refs)
		mod->hook_refs--;
	spin_unlock_irqrestore(&module_lock, flags);
}

int kp_hook_owner_call_get(void *owner)
{
	struct kp_module *mod = owner;
	unsigned long flags;
	int rc = 0;

	if (!mod)
		return 0;
	spin_lock_irqsave(&module_lock, flags);
	if ((mod->state == KP_MODULE_LIVE || mod->state == KP_MODULE_LOADING) &&
	    mod->active_calls != UINT_MAX) {
		mod->active_calls++;
		rc = 1;
	} else if (mod->active_calls == UINT_MAX) {
		rc = -EOVERFLOW;
	} else {
		rc = -EBUSY;
	}
	spin_unlock_irqrestore(&module_lock, flags);
	return rc;
}

void kp_hook_owner_call_put(void *owner)
{
	kp_module_put(owner);
}

/* Public KPM lifetime API for work items and callbacks outside Hook chains. */
int kp_kpm_owner_pin(unsigned long callback_addr, void **owner)
{
	return kp_hook_owner_register(callback_addr, owner);
}

void kp_kpm_owner_unpin(void *owner)
{
	kp_hook_owner_unregister(owner);
}

int kp_kpm_owner_call_get(void *owner)
{
	return kp_hook_owner_call_get(owner);
}

void kp_kpm_owner_call_put(void *owner)
{
	kp_hook_owner_call_put(owner);
}

/* Hold the owning KPM alive for the complete kernel kallsyms iteration.
 * LOADING is permitted because init may itself iterate kallsyms. UNLOADING
 * is permitted only while an existing active call keeps teardown pending;
 * EXITING is rejected so no new callback can race the exit/free sequence. */
static struct kp_module *kp_module_get_by_addr(unsigned long addr)
{
	struct kp_module *pos;
	unsigned long flags;
	unsigned long start, end;

	spin_lock_irqsave(&module_lock, flags);
	list_for_each_entry(pos, &modules.list, list) {
		/* UNLOADING is retained only while an existing active call
		 * prevents teardown; nested callbacks may safely pin it. */
		if (pos->state != KP_MODULE_LOADING &&
		    pos->state != KP_MODULE_LIVE &&
		    !(pos->state == KP_MODULE_UNLOADING && pos->active_calls))
			continue;
		start = (unsigned long)pos->start;
		end = start + pos->text_size;
		if (end >= start && addr >= start && addr < end) {
			if (pos->active_calls == UINT_MAX)
				break;
			pos->active_calls++;
			spin_unlock_irqrestore(&module_lock, flags);
			return pos;
		}
	}
	spin_unlock_irqrestore(&module_lock, flags);
	return NULL;
}

/* One PAGE_SIZE module_alloc'd RWX page. The safe kallsyms_on_each_symbol()
 * stand-in assigns a distinct 16-byte slot to each active KPM callback:
 * two zero words satisfy the KCFI [target-4] read, followed by bti c and a
 * direct branch into the bare-metal (non-BTI) KPM callback. */
static void *kp_callback_tramp;
static unsigned long kp_callback_tramp_size;
#define KP_CALLBACK_TRAMP_SLOT_SIZE 16
#define KP_CALLBACK_TRAMP_SLOT_COUNT (PAGE_SIZE / KP_CALLBACK_TRAMP_SLOT_SIZE)
static unsigned long kp_callback_tramp_slots[(KP_CALLBACK_TRAMP_SLOT_COUNT + BITS_PER_LONG - 1) / BITS_PER_LONG];

typedef int (*kp_kallsyms_on_each_symbol_t)(kp_kallsyms_cb_t fn, void *data);
static kp_kallsyms_on_each_symbol_t kp_real_kallsyms_on_each_symbol;

/* modules.list / module_lock / trampoline initialized */

/* Address-in-KPM-range check used by the find_check_fn CFI bypass and by the
 * safe kallsyms wrapper. Callable from any (including atomic) context. */
bool kp_kpm_cfi_allowed_addr(unsigned long addr)
{
	struct kp_module *pos;
	unsigned long start, end;
	bool ok = false;

	if (!READ_ONCE(kp_kpm_ready))
		return false;

	{
		unsigned long flags;
		/* No module pointer escapes this locked range check. */
		spin_lock_irqsave(&module_lock, flags);
		list_for_each_entry(pos, &modules.list, list) {
			start = (unsigned long)pos->start;
			end = start + pos->text_size;
			if (end >= start && addr >= start && addr < end) {
				ok = true;
				break;
			}
		}
		spin_unlock_irqrestore(&module_lock, flags);
	}
	if (ok)
		return true;

	if (kp_callback_tramp) {
		start = (unsigned long)kp_callback_tramp;
		end = start + kp_callback_tramp_size;
		if (addr >= start && addr < end)
			return true;
	}
	return false;
}

/* The kernel's own kallsyms_on_each_symbol() is exported to KPMs through a
 * function-pointer slot in the LKM (see symbols.c). We install this stand-in
 * instead: for a KPM callback it writes a "bti c; b <fn>" trampoline into the
 * RWX trampoline page and hands the trampoline address to the real kernel
 * iterator. find_check_fn() then validates the trampoline page (covered by
 * kp_kpm_cfi_allowed_addr, noop check fn) and the BLR lands on bti c, which
 * direct-branches into the non-BTI KPM callback with the call args intact. */
static int kp_callback_tramp_slot_alloc(unsigned long *slot)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&module_lock, flags);
	for (i = 0; i < KP_CALLBACK_TRAMP_SLOT_COUNT; i++) {
		unsigned long mask = 1UL << (i % BITS_PER_LONG);
		unsigned int word = i / BITS_PER_LONG;
		if (!(kp_callback_tramp_slots[word] & mask)) {
			kp_callback_tramp_slots[word] |= mask;
			*slot = i;
			spin_unlock_irqrestore(&module_lock, flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&module_lock, flags);
	return -EBUSY;
}

static void kp_callback_tramp_slot_free(unsigned long slot)
{
	unsigned long flags;
	if (slot >= KP_CALLBACK_TRAMP_SLOT_COUNT)
		return;
	spin_lock_irqsave(&module_lock, flags);
	kp_callback_tramp_slots[slot / BITS_PER_LONG] &=
		~(1UL << (slot % BITS_PER_LONG));
	spin_unlock_irqrestore(&module_lock, flags);
}

/* Concurrent KPM iterators use separate slots, so another CPU cannot
 * overwrite a trampoline while the kernel is invoking its callback. */
__attribute__((no_sanitize("cfi")))
int kp_kpm_safe_kallsyms_on_each_symbol(kp_kallsyms_cb_t fn, void *data)
{
	unsigned long slot, offset;
	long branch_off;
	u32 *words;
	struct kp_module *owner = NULL;
	int rc;

	if (!kp_real_kallsyms_on_each_symbol)
		return -EOPNOTSUPP;
	/* Acquire the owner before making any CFI-range decision. This closes
	 * the check-then-unload gap for ordinary KPM callbacks. */
	owner = kp_module_get_by_addr((unsigned long)fn);
	if (!owner) {
		if (kp_kpm_cfi_allowed_addr((unsigned long)fn))
			return -EBUSY;
		return kp_real_kallsyms_on_each_symbol(fn, data);
	}
	if (!kp_callback_tramp) {
		kp_module_put(owner);
		return -EOPNOTSUPP;
	}

	rc = kp_callback_tramp_slot_alloc(&slot);
	if (rc) {
		kp_module_put(owner);
		return rc;
	}
	offset = slot * KP_CALLBACK_TRAMP_SLOT_SIZE;
	words = (u32 *)((char *)kp_callback_tramp + offset);
	branch_off = (long)((unsigned long)fn -
			    ((unsigned long)kp_callback_tramp + offset + 12));
	/* B imm26 is signed, word-scaled, and reaches +/-128 MiB. */
	if ((branch_off & 3) || branch_off < -(1L << 27) ||
	    branch_off >= (1L << 27)) {
		kp_callback_tramp_slot_free(slot);
		kp_module_put(owner);
		return -ERANGE;
	}

	words[0] = 0;
	words[1] = 0;
	words[2] = 0xd503245f; /* bti c */
	words[3] = 0x14000000 | (((unsigned long)branch_off >> 2) & 0x03ffffff);
	dsb(ishst);
	asm volatile("ic iallu");
	dsb(ish);
	isb();

	rc = kp_real_kallsyms_on_each_symbol(
		(kp_kallsyms_cb_t)((char *)kp_callback_tramp + offset + 8), data);
	kp_callback_tramp_slot_free(slot);
	kp_module_put(owner);
	return rc;
}

long kp_load_module(const void *data, int len, const char *args, const char *event,
		    void __user *reserved)
{
	struct kp_load_info load_info = { .len = len, .hdr = data };
	struct kp_load_info *info = &load_info;
	long rc = 0;

	if (!data || len <= 0) {
		set_load_error(info, "module image is empty or invalid");
		rc = -EINVAL;
		goto out;
	}
	if (kp_exec_backend == KP_EXEC_BACKEND_NONE || !kp_kpm_init_mm) {
		set_load_error(info, "verified executable memory backend unavailable");
		rc = -ENOSYS;
		goto out;
	}

	if ((rc = elf_header_check(info)))
		goto out;
	if ((rc = setup_load_info(info)))
		goto out;

	struct kp_module *mod = (struct kp_module *)kzalloc(sizeof(struct kp_module), GFP_KERNEL);
	if (!mod) {
		set_load_error(info, "allocate module state failed");
		rc = -ENOMEM;
		goto out;
	}

	if (args) {
		mod->args = kstrdup(args, GFP_KERNEL);
		if (!mod->args) {
			set_load_error(info, "allocate module args failed");
			rc = -ENOMEM;
			goto free1;
		}
	}

	if ((rc = layout_sections(mod, info)) || (rc = layout_symtab(mod, info))) {
		set_load_error(info, "module section layout overflow");
		goto free;
	}
	logkfe("KPM [%s] layout done size=0x%x\n", info->info.name, mod->size);

	if ((rc = move_module(mod, info))) {
		set_load_error(info, "allocate executable module memory failed");
		goto free;
	}
	logkfe("KPM [%s] moved to %px init=%px\n", info->info.name, mod->start, mod->init);
	if ((rc = simplify_symbols(mod, info)))
		goto free;
	logkfe("KPM [%s] symbols resolved\n", info->info.name);
	if ((rc = apply_relocations(mod, info))) {
		set_load_error(info, "apply relocations failed");
		goto free;
	}
	logkfe("KPM [%s] relocations applied\n", info->info.name);

	/* GKI module_alloc pages may be NX/BTI-guarded. set_memory_x is
	 * attempted when available; the PTE walk below is authoritative. */
	if (kp_set_memory_x) {
		int npages = (mod->size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		int xret = kp_do_set_memory_x((unsigned long)mod->start, npages);
		if (xret)
			logkw("KPM [%s] set_memory_x returned %d; verifying PTE permissions directly\n",
			      info->info.name, xret);
	}

	/* Disable PXN/UXN/GP and verify every page before entering module code. */
	rc = kp_clear_bti_gp((unsigned long)mod->start, mod->size);
	if (rc) {
		set_load_error(info, "KPM executable/BTI page permissions could not be verified");
		logke("KPM [%s] executable page verification failed: %ld\n", info->info.name, rc);
		goto free;
	}
	kp_flush_kpm_icache(mod->start, mod->size);
	logkfe("KPM [%s] icache flushed\n", info->info.name);

	pr_emerg(KPLKM_TAG ": KPM [%s] entering init=%px image=%px size=%u\n",
		 mod->info.name, mod->init, mod->start, mod->size);

	/* Reserve the name before init: concurrent loads cannot both enter
	 * init. LOADING entries are visible to the CFI range check only. */
	{
		unsigned long flags;
		spin_lock_irqsave(&module_lock, flags);
		if (kp_find_module_locked(mod->info.name)) {
			spin_unlock_irqrestore(&module_lock, flags);
			set_load_error(info, "module already exists or is loading");
			rc = -EEXIST;
			goto free;
		}
		mod->state = KP_MODULE_LOADING;
		list_add_tail(&mod->list, &modules.list);
		spin_unlock_irqrestore(&module_lock, flags);
	}
	pr_emerg(KPLKM_TAG ": KPM [%s] call init fn=%px (*fn)=%px args=%px args0='%s' event='%s'\n",
		 mod->info.name, mod->init,
		 mod->init ? *(mod_initcall_t *)mod->init : 0,
		 mod->args, mod->args ? mod->args : "(null)",
		 event ? event : "(null)");
	rc = kp_call_init(mod->init, mod->args, event, reserved);
	pr_emerg(KPLKM_TAG ": KPM [%s] init returned %ld\n", mod->info.name, rc);

	if (!rc) {
		unsigned long flags;
		spin_lock_irqsave(&module_lock, flags);
		mod->state = KP_MODULE_LIVE;
		spin_unlock_irqrestore(&module_lock, flags);
		logkfi("[%s] succeed with [%s]\n", mod->info.name, args ? args : "");
		goto out;
	}
	{
		unsigned long flags;
		/* Keep the image registered while failure cleanup runs. */
		spin_lock_irqsave(&module_lock, flags);
		mod->state = KP_MODULE_UNLOADING;
		if (mod->active_calls) {
			spin_unlock_irqrestore(&module_lock, flags);
			rc = -EBUSY;
			goto out;
		}
		mod->state = KP_MODULE_EXITING;
		spin_unlock_irqrestore(&module_lock, flags);
	}
	set_load_error(info, "module init failed");
	logkfi("[%s] failed with [%s] error: %ld, try exit ...\n", mod->info.name,
	       args ? args : "", rc);
	if (mod->exit) {
		long exit_rc = kp_call_exit(mod->exit, reserved);
		if (exit_rc == -EBUSY) {
			unsigned long flags;
			spin_lock_irqsave(&module_lock, flags);
			mod->state = KP_MODULE_UNLOADING;
			mod->exit_called = false;
			spin_unlock_irqrestore(&module_lock, flags);
			rc = -EBUSY;
			goto out;
		}
	}
	{
		unsigned long flags;
		spin_lock_irqsave(&module_lock, flags);
		mod->exit_called = true;
		if (mod->hook_refs || mod->active_calls) {
			spin_unlock_irqrestore(&module_lock, flags);
			logke("failed KPM init left hook refs; retaining image %s\n", mod->info.name);
			rc = -EBUSY;
			goto out;
		}
		list_del_init(&mod->list);
		mod->state = KP_MODULE_DEAD;
		spin_unlock_irqrestore(&module_lock, flags);
	}

free:
	if (mod->args)
		kvfree(mod->args);
	if (mod->start)
		kp_free_exec(mod->start, mod->size);
free1:
	kfree(mod);
out:
	set_kpm_load_result(reserved, rc, rc ? load_error(info, "load module failed") : "module loaded");
	return rc;
}

long kp_unload_module(const char *name, void __user *reserved)
{
	struct kp_module *mod;
	unsigned long flags;
	long rc = 0;

	if (!name)
		return -EINVAL;
	logkfe("name: %s\n", name);

	spin_lock_irqsave(&module_lock, flags);
	mod = kp_find_module_locked(name);
	if (!mod) {
		spin_unlock_irqrestore(&module_lock, flags);
		return -ENOENT;
	}
	if (mod->state == KP_MODULE_LOADING) {
		spin_unlock_irqrestore(&module_lock, flags);
		return -EBUSY;
	}
	if (mod->state == KP_MODULE_LIVE)
		mod->state = KP_MODULE_UNLOADING;
	if (mod->state != KP_MODULE_UNLOADING && mod->state != KP_MODULE_EXITING) {
		spin_unlock_irqrestore(&module_lock, flags);
		return -ENOENT;
	}
	/* EXITING with exit_called=false means another thread is currently
	 * executing the exit callback outside module_lock. Never run it twice. */
	if (mod->state == KP_MODULE_EXITING && !mod->exit_called) {
		spin_unlock_irqrestore(&module_lock, flags);
		return -EBUSY;
	}
	if (mod->active_calls) {
		spin_unlock_irqrestore(&module_lock, flags);
		return -EBUSY;
	}
	if (!mod->exit_called) {
		mod->state = KP_MODULE_EXITING;
		spin_unlock_irqrestore(&module_lock, flags);
		rc = kp_call_exit(mod->exit, reserved);
		spin_lock_irqsave(&module_lock, flags);
		if (rc == -EBUSY) {
			mod->state = KP_MODULE_UNLOADING;
			mod->exit_called = false;
			spin_unlock_irqrestore(&module_lock, flags);
			return -EBUSY;
		}
		mod->exit_called = true;
	}
	if (mod->active_calls || mod->hook_refs) {
		spin_unlock_irqrestore(&module_lock, flags);
		logkw("KPM %s retained: active=%u hook_refs=%u; retry after hook removal\n",
		      name, mod->active_calls, mod->hook_refs);
		return -EBUSY;
	}
	list_del_init(&mod->list);
	mod->state = KP_MODULE_DEAD;
	spin_unlock_irqrestore(&module_lock, flags);

	if (mod->args)
		kvfree(mod->args);
	if (kp_set_memory_nx && mod->start) {
		int npages = (mod->size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		kp_do_set_memory_nx((unsigned long)mod->start, npages);
	}
	if (mod->start)
		kp_free_exec(mod->start, mod->size);
	kfree(mod);
	logkfi("name: %s, rc: %ld\n", name, rc);
	return rc;
}

long kp_load_module_path(const char *path, const char *args, void __user *reserved)
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
	if (len <= 0 || len > INT_MAX) {
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

	rc = kp_load_module(data, len, args, "load-file", reserved);
free:
	kvfree(data);
close:
	if (filp)
		filp_close(filp, 0);
out:
	return rc;
}

long kp_module_control0(const char *name, const char *ctl_args, char __user *out_msg, int outlen)
{
	struct kp_module *mod;
	char *args_copy;
	long rc;

	if (!name || !ctl_args || !*ctl_args)
		return -EINVAL;
	if (outlen < 0 || (outlen && !out_msg))
		return -EINVAL;
	args_copy = kstrdup(ctl_args, GFP_KERNEL);
	if (!args_copy)
		return -ENOMEM;
	mod = kp_module_get(name);
	if (!mod) {
		kfree(args_copy);
		return -ENOENT;
	}
	if (!mod->ctl0 || !*mod->ctl0)
		rc = -ENOSYS;
	else
		rc = kp_call_ctl0(mod->ctl0, args_copy, out_msg, outlen);
	kfree(args_copy);
	kp_module_put(mod);
	logkfi("name: %s, rc: %ld\n", name, rc);
	return rc;
}

long kp_module_control1(const char *name, void *a1, void *a2, void *a3)
{
	struct kp_module *mod;
	long rc;

	if (!name)
		return -EINVAL;
	logkfi("name %s, a1: %px, a2: %px, a3: %px\n", name, a1, a2, a3);
	mod = kp_module_get(name);
	if (!mod)
		return -ENOENT;
	if (!mod->ctl1 || !*mod->ctl1)
		rc = -ENOSYS;
	else
		rc = kp_call_ctl1(mod->ctl1, a1, a2, a3);
	kp_module_put(mod);
	logkfi("name: %s, rc: %ld\n", name, rc);
	return rc;
}

long kp_notify_modules_event(const char *event, const char *args, void __user *reserved)
{
	struct kp_module **snapshot;
	struct kp_module *pos;
	unsigned long flags;
	unsigned int capacity, n, i;
	bool overflow;
	long result = 0;
	int count = 0;

	if (!event)
		return -EINVAL;

	/* Count, allocate outside the spinlock, then recheck capacity while
	 * taking references. Retry if concurrent loads grew the live set. */
	for (;;) {
		capacity = 0;
		spin_lock_irqsave(&module_lock, flags);
		list_for_each_entry(pos, &modules.list, list)
			if (pos->state == KP_MODULE_LIVE && pos->event && *pos->event)
				capacity++;
		spin_unlock_irqrestore(&module_lock, flags);

		snapshot = kcalloc(capacity ? capacity : 1, sizeof(*snapshot), GFP_KERNEL);
		if (!snapshot)
			return -ENOMEM;

		spin_lock_irqsave(&module_lock, flags);
		n = 0;
		list_for_each_entry(pos, &modules.list, list)
			if (pos->state == KP_MODULE_LIVE && pos->event && *pos->event)
				n++;
		if (n > capacity) {
			spin_unlock_irqrestore(&module_lock, flags);
			kfree(snapshot);
			continue;
		}
		n = 0;
		overflow = false;
		list_for_each_entry(pos, &modules.list, list) {
			if (pos->state != KP_MODULE_LIVE || !pos->event || !*pos->event)
				continue;
			if (pos->active_calls == UINT_MAX) {
				overflow = true;
				break;
			}
			pos->active_calls++;
			snapshot[n++] = pos;
		}
		if (overflow) {
			for (i = 0; i < n; i++)
				snapshot[i]->active_calls--;
			spin_unlock_irqrestore(&module_lock, flags);
			kfree(snapshot);
			return -EOVERFLOW;
		}
		spin_unlock_irqrestore(&module_lock, flags);
		break;
	}

	for (i = 0; i < n; i++) {
		pos = snapshot[i];
		{
			long rc = kp_call_event(pos->event, event, args, reserved);
			logkfi("event: %s, module: %s, rc: %ld\n",
			       event, pos->info.name, rc);
			if (rc < 0 && !result)
				result = rc;
		}
		count++;
		kp_module_put(pos);
	}
	kfree(snapshot);
	return result ?: count;
}

int kp_get_module_nums(void)
{
	struct kp_module *pos;
	unsigned long flags;
	int n = 0;

	spin_lock_irqsave(&module_lock, flags);
	list_for_each_entry(pos, &modules.list, list)
		if (pos->state == KP_MODULE_LIVE)
			n++;
	spin_unlock_irqrestore(&module_lock, flags);
	logkfd("%d\n", n);
	return n;
}

int kp_list_modules(char *out_names, int size)
{
	struct kp_module *pos;
	unsigned long flags;
	int off = 0;

	if (!out_names || size <= 0)
		return -EINVAL;
	out_names[0] = '\0';

	spin_lock_irqsave(&module_lock, flags);
	list_for_each_entry(pos, &modules.list, list) {
		int written;
		if (pos->state != KP_MODULE_LIVE)
			continue;
		if (off >= size - 1)
			break;
		written = scnprintf(out_names + off, size - off, "%s\n", pos->info.name);
		off += written;
	}
	spin_unlock_irqrestore(&module_lock, flags);
	if (off > 0)
		out_names[off - 1] = '\0';
	return off;
}

int kp_get_module_info(const char *name, char *out_info, int size)
{
	struct kp_module *mod;
	int sz;

	if (!name || !out_info || size <= 0)
		return -EINVAL;
	mod = kp_module_get(name);
	if (!mod)
		return -ENOENT;

	sz = scnprintf(out_info, size,
		       "name=%s\n"
		       "version=%s\n"
		       "license=%s\n"
		       "author=%s\n"
		       "description=%s\n"
		       "args=%s\n",
		       mod->info.name, mod->info.version, mod->info.license,
		       mod->info.author, mod->info.description,
		       mod->args ? mod->args : "");
	logkfd("%s", out_info);
	kp_module_put(mod);
	return sz;
}

int kp_kpm_init(void)
{
	INIT_LIST_HEAD(&modules.list);
	spin_lock_init(&module_lock);
	kp_kpm_symbols_init();

	/* Resolve matched allocator/free pairs. Never free through a different
	 * backend, and require init_mm to verify executable and BTI PTE state. */
	kp_module_alloc = (void *(*)(unsigned long))kallsyms_lookup_name("module_alloc");
	kp_module_memfree = (void (*)(void *))kallsyms_lookup_name("module_memfree");
	kp_execmem_alloc = (void *)kallsyms_lookup_name("execmem_alloc");
	kp_execmem_free = (void (*)(void *))kallsyms_lookup_name("execmem_free");
	kp_flush_icache_all_fn = (void (*)(void))kallsyms_lookup_name("flush_icache_all");
	kp_set_memory_x = (int (*)(unsigned long, int))kallsyms_lookup_name("set_memory_x");
	kp_set_memory_nx = (int (*)(unsigned long, int))kallsyms_lookup_name("set_memory_nx");
	kp_kpm_init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	logki("kpm runtime: module_alloc=%px execmem_alloc=%px set_memory_x=%px init_mm=%px\n",
	      kp_module_alloc, kp_execmem_alloc, kp_set_memory_x, kp_kpm_init_mm);

	if (!kp_kpm_init_mm) {
		logke("init_mm unavailable; cannot verify KPM executable permissions\n");
		return -ENOSYS;
	}
	if (kp_module_alloc && kp_module_memfree)
		kp_exec_backend = KP_EXEC_BACKEND_MODULE;
	else if (kp_execmem_alloc && kp_execmem_free)
		kp_exec_backend = KP_EXEC_BACKEND_EXECMEM;
	else if (kp_set_memory_x)
		kp_exec_backend = KP_EXEC_BACKEND_VMALLOC;
	else {
		logke("no matched executable-memory allocator/free backend\n");
		return -ENOSYS;
	}

	/* One executable page holds per-call BTI-C trampolines. If its PTEs
	 * cannot be verified, keep kallsyms callbacks disabled rather than
	 * exposing an NX or BTI-incompatible entry point. */
	kp_callback_tramp = kp_malloc_exec(PAGE_SIZE);
	if (kp_callback_tramp) {
		int perm_rc;
		if (kp_set_memory_x)
			kp_do_set_memory_x((unsigned long)kp_callback_tramp, 1);
		perm_rc = kp_clear_bti_gp((unsigned long)kp_callback_tramp, PAGE_SIZE);
		if (perm_rc) {
			logke("callback trampoline permissions unverifiable: %d\n", perm_rc);
			kp_free_exec(kp_callback_tramp, PAGE_SIZE);
			kp_callback_tramp = NULL;
			kp_callback_tramp_size = 0;
		} else {
			kp_callback_tramp_size = PAGE_SIZE;
			memset(kp_callback_tramp, 0, PAGE_SIZE);
			kp_flush_kpm_icache(kp_callback_tramp, PAGE_SIZE);
		}
	} else {
		logkw("callback trampoline alloc failed; KPM kallsyms iteration disabled\n");
	}

	kp_real_kallsyms_on_each_symbol =
		(kp_kallsyms_on_each_symbol_t)kallsyms_lookup_name("kallsyms_on_each_symbol");
	WRITE_ONCE(kp_kpm_ready, true);

	logki("kpm loader ready (module_alloc=%px flush_icache_all=%px tramp=%px)\n", kp_module_alloc,
	      kp_flush_icache_all_fn, kp_callback_tramp);
	return 0;
}
