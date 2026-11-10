// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * arm64 read-only memory patching through a serialized FIX_TEXT_POKE0 alias.
 * Function-pointer slots use atomic 64-bit compare/exchange. Multi-instruction
 * text changes are preflighted, snapshotted, and applied/rolled back inside
 * stop_machine so another CPU cannot execute a partially-patched prologue.
 * If init_mm or stop_machine cannot be resolved, the corresponding patch path
 * fails closed instead of attempting an unsafe direct write.
 */
#ifdef __aarch64__

#include "patch_memory.h"
#include "symbol_resolver.h"

#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/preempt.h>
#include <asm/irqflags.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/barrier.h>
#include <asm/cmpxchg.h>

#include "../include/kp_lkm.h"

/* Detect the dcache flush API: android13-5.10 backported dcache_clean_inval_poc,
 * android12-5.10 still has __flush_dcache_area. Kbuild sets KP_NEW_DCACHE_FLUSH. */
#ifndef KP_NEW_DCACHE_FLUSH
#define KP_NEW_DCACHE_FLUSH 0
#endif
#if KP_NEW_DCACHE_FLUSH
#define kp_flush_dcache(start, sz)                                                    \
	({                                                                               \
		unsigned long __start = (start);                                         \
		dcache_clean_inval_poc(__start, __start + (sz));                         \
	})
#define kp_flush_icache(start, end)                                                    \
	({                                                                               \
		unsigned long __start = (start);                                         \
		caches_clean_inval_pou(__start, (end));                                  \
	})
#else
/*
 * Linux 4.14 declares __flush_dcache_area() but does not EXPORT_SYMBOL it.
 * Resolve it at runtime so an out-of-tree LKM has no undefined modpost
 * dependency. flush_icache_range() is the exported ARM64 API on 4.14 and
 * remains available on the older cache-maintenance path.
 */
static void (*kp_flush_dcache_area_fn)(void *addr, size_t len);
#define kp_flush_dcache(start, sz) kp_flush_dcache_area_fn((void *)(start), (sz))
#define kp_flush_icache(start, end) flush_icache_range((start), (end))
#endif

struct cpumask;
typedef int (*kp_stop_machine_fn_t)(int (*fn)(void *), void *data,
				      const struct cpumask *cpus);
static kp_stop_machine_fn_t kp_patch_stop_machine;

/* Resolve the physical address of a kernel VA through init_mm's page tables.
 * Used for the data patch path (sys_call_table is rodata, not mapped via the
 * direct kernel text alias, so we poke it through a fixmap). init_mm is cached
 * at init (not exported to modules on GKI). */
static struct mm_struct *kp_patch_init_mm;

/* FIX_TEXT_POKE0 is a single global fixmap slot. Serialize every user so
 * concurrent text/data/function-pointer patches cannot remap it underneath
 * another CPU. */
static DEFINE_RAW_SPINLOCK(kp_fixmap_patch_lock);

__attribute__((no_sanitize("cfi")))
static unsigned long kp_phys_from_virt(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct mm_struct *mm = kp_patch_init_mm;

	if (!mm)
		return 0;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return 0;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return (pud_page_paddr(*pud) & PUD_MASK) + (addr & ~PUD_MASK);
#elif defined(pud_sect)
	/* Linux 4.14 exposes pud_sect(), not the newer pud_leaf() helper. */
	if (pud_sect(*pud))
		return (pud_page_paddr(*pud) & PUD_MASK) + (addr & ~PUD_MASK);
#endif
	if (pud_bad(*pud))
		return 0;
	pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return (pmd_page_paddr(*pmd) & PMD_MASK) + (addr & ~PMD_MASK);
#elif defined(pmd_sect)
	/* Linux 4.14 uses pmd_sect() for valid block descriptors. */
	if (pmd_sect(*pmd))
		return (pmd_page_paddr(*pmd) & PMD_MASK) + (addr & ~PMD_MASK);
#endif
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 0;
	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		return 0;
	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);
}

/* Data (rodata) poke through a fixmap; page-align the phys for set_fixmap_offset
 * and add the offset back. The caller supplies a single-page write. */
__attribute__((no_sanitize("cfi")))
static int kp_patch_data(void *dst, const void *src, size_t len)
{
	unsigned long phy, phy_off, flags;
	void *map;

	/* This primitive is deliberately one aligned instruction word only.
	 * Batch callers provide CPU quiescence; WRITE_ONCE prevents torn stores. */
	if (!dst || !src || len != sizeof(u32) || ((unsigned long)dst & 3))
		return -EINVAL;
	phy = kp_phys_from_virt((unsigned long)dst);
	if (!phy) {
		logke("no phys for data patch dst 0x%lx\\n", (unsigned long)dst);
		return -ENOENT;
	}
	phy_off = phy & ~PAGE_MASK;
	if (phy_off > PAGE_SIZE - sizeof(u32))
		return -E2BIG;

	raw_spin_lock_irqsave(&kp_fixmap_patch_lock, flags);
	map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phy & PAGE_MASK) + phy_off;
	WRITE_ONCE(*(volatile u32 *)map, READ_ONCE(*(const u32 *)src));
	clear_fixmap(FIX_TEXT_POKE0);
	kp_flush_dcache((unsigned long)dst, sizeof(u32));
	raw_spin_unlock_irqrestore(&kp_fixmap_patch_lock, flags);
	return 0;
}

int kp_patch_memory_init(void)
{
	kp_patch_init_mm = (struct mm_struct *)kp_resolve_symbol("init_mm");
	kp_patch_stop_machine = (kp_stop_machine_fn_t)kp_resolve_symbol("stop_machine");
#if !KP_NEW_DCACHE_FLUSH
	kp_flush_dcache_area_fn =
		(void (*)(void *, size_t))kp_resolve_symbol("__flush_dcache_area");
	if (!kp_flush_dcache_area_fn) {
		logke("__flush_dcache_area unavailable; refusing unsafe memory patching\\n");
		return -ENOSYS;
	}
#endif
	if (!kp_patch_init_mm)
		logkw("failed to resolve init_mm; data (sys_call_table) patch disabled\\n");
	if (!kp_patch_stop_machine)
		logkw("stop_machine unavailable; executable text patching disabled\\n");
	logki("patch memory ready (serialized fixmap; stop_machine=%px)\\n",
	      kp_patch_stop_machine);
	return 0;
}

/* Atomic 64-bit pointer patching for function-pointer hooks. The fixmap
 * alias is normal cacheable memory; arm64 cmpxchg keeps the two halves from
 * being observed as a torn pointer by concurrent CPUs. */
int kp_patch_exchange64(void *dst, u64 desired, u64 *original)
{
	unsigned long phy, phy_off, flags;
	void *map;
	u64 old, seen;

	if (!dst || !original || ((unsigned long)dst & 7))
		return -EINVAL;
	phy = kp_phys_from_virt((unsigned long)dst);
	if (!phy)
		return -ENOENT;
	phy_off = phy & ~PAGE_MASK;
	if (sizeof(u64) > PAGE_SIZE - phy_off)
		return -E2BIG;
	raw_spin_lock_irqsave(&kp_fixmap_patch_lock, flags);
	map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phy & PAGE_MASK) + phy_off;
	old = READ_ONCE(*(volatile u64 *)map);
	for (;;) {
		seen = cmpxchg((volatile u64 *)map, old, desired);
		if (seen == old)
			break;
		old = seen;
	}
	clear_fixmap(FIX_TEXT_POKE0);
	kp_flush_dcache((unsigned long)dst, sizeof(u64));
	dsb(ishst);
	raw_spin_unlock_irqrestore(&kp_fixmap_patch_lock, flags);
	*original = old;
	return 0;
}

int kp_patch_cmpxchg64(void *dst, u64 expected, u64 desired)
{
	unsigned long phy, phy_off, flags;
	void *map;
	u64 seen;

	if (!dst || ((unsigned long)dst & 7))
		return -EINVAL;
	phy = kp_phys_from_virt((unsigned long)dst);
	if (!phy)
		return -ENOENT;
	phy_off = phy & ~PAGE_MASK;
	if (sizeof(u64) > PAGE_SIZE - phy_off)
		return -E2BIG;
	raw_spin_lock_irqsave(&kp_fixmap_patch_lock, flags);
	map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phy & PAGE_MASK) + phy_off;
	seen = cmpxchg((volatile u64 *)map, expected, desired);
	clear_fixmap(FIX_TEXT_POKE0);
	if (seen == expected) {
		kp_flush_dcache((unsigned long)dst, sizeof(u64));
		dsb(ishst);
	}
	raw_spin_unlock_irqrestore(&kp_fixmap_patch_lock, flags);
	return seen == expected ? 0 : -EAGAIN;
}

#define KP_PATCH_MAX_TEXT_WORDS 64

struct kp_text_patch_batch {
	void **addrs;
	const u32 *values;
	u32 original[KP_PATCH_MAX_TEXT_WORDS];
	int count;
};

__attribute__((no_sanitize("cfi")))
static int kp_patch_text_batch_stop(void *arg)
{
	struct kp_text_patch_batch *patch = arg;
	int applied = 0;
	int ret = 0;
	bool rollback_failed = false;

	if (!patch || !patch->addrs || !patch->values ||
	    patch->count <= 0 || patch->count > KP_PATCH_MAX_TEXT_WORDS)
		return -EINVAL;

	/* Validate and snapshot every target before modifying the first word. */
	for (int i = 0; i < patch->count; i++) {
		unsigned long addr = (unsigned long)patch->addrs[i];
		unsigned long phy;

		if (!addr || (addr & 3) || addr > ~0UL - sizeof(u32))
			return -EINVAL;
		for (int j = 0; j < i; j++)
			if (patch->addrs[j] == patch->addrs[i])
				return -EINVAL;
		phy = kp_phys_from_virt(addr);
		if (!phy || (phy & ~PAGE_MASK) > PAGE_SIZE - sizeof(u32))
			return -EFAULT;
		patch->original[i] = READ_ONCE(*(volatile u32 *)addr);
	}

	for (int i = 0; i < patch->count; i++) {
		applied = i + 1; /* Include the current word in rollback on error. */
		ret = kp_patch_data(patch->addrs[i], &patch->values[i], sizeof(u32));
		if (ret)
			break;
	}
	if (ret) {
		while (applied > 0) {
			--applied;
			if (kp_patch_data(patch->addrs[applied],
					  &patch->original[applied], sizeof(u32)))
				rollback_failed = true;
		}
		for (int i = 0; i < patch->count; i++) {
			unsigned long addr = (unsigned long)patch->addrs[i];
			kp_flush_icache(addr, addr + sizeof(u32));
		}
		return rollback_failed ? -EUCLEAN : ret;
	}

	for (int i = 0; i < patch->count; i++) {
		unsigned long addr = (unsigned long)patch->addrs[i];
		kp_flush_icache(addr, addr + sizeof(u32));
	}
	return 0;
}

__attribute__((no_sanitize("cfi")))
int kp_patch_text_batch(void *addrs[], const u32 values[], int count)
{
	struct kp_text_patch_batch patch = {
		.addrs = addrs,
		.values = values,
		.count = count,
	};

	if (!addrs || !values || count <= 0 || count > KP_PATCH_MAX_TEXT_WORDS)
		return -EINVAL;
	if (!kp_patch_stop_machine)
		return -EOPNOTSUPP;
	/* stop_machine may sleep and must not be entered with preemption or IRQs
	 * disabled; fail closed for KPM callers in atomic/interrupt context. */
	if (in_atomic() || irqs_disabled())
		return -EWOULDBLOCK;
	return kp_patch_stop_machine(kp_patch_text_batch_stop, &patch, NULL);
}

__attribute__((no_sanitize("cfi")))
int kp_patch_text(void *dst, const void *src, size_t len, int flags)
{
	void *addrs[KP_PATCH_MAX_TEXT_WORDS];
	u32 values[KP_PATCH_MAX_TEXT_WORDS];
	int count;

	(void)flags; /* Text writes always flush D-cache and I-cache. */
	if (!dst || !src || !len || (len & (sizeof(u32) - 1)) ||
	    len / sizeof(u32) > KP_PATCH_MAX_TEXT_WORDS)
		return -EINVAL;
	count = len / sizeof(u32);
	memcpy(values, src, len);
	for (int i = 0; i < count; i++)
		addrs[i] = (char *)dst + i * sizeof(u32);
	return kp_patch_text_batch(addrs, values, count);
}

#endif /* __aarch64__ */
