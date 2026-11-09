// SPDX-License-Identifier: GPL-2.0-or-later
/* LKM backends required by kernel/base/hook.c. */
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "../include/kp_lkm.h"
#include <hook.h>
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"

struct kp_hook_mem {
	struct list_head list;
	uintptr_t origin;
	enum hook_type type;
	bool ready;
	bool retiring;
	void *region;
	unsigned long region_size;
	union {
		hook_t hook;
		hook_chain_t chain;
		fp_hook_chain_t fp_chain;
	} *payload;
};

static LIST_HEAD(kp_hook_mems);
static DEFINE_RAW_SPINLOCK(kp_hook_lock);
static DEFINE_RAW_SPINLOCK(kp_hook_engine_lock);

unsigned long hook_engine_lock(void)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&kp_hook_engine_lock, flags);
	return flags;
}

void hook_engine_unlock(unsigned long flags)
{
	raw_spin_unlock_irqrestore(&kp_hook_engine_lock, flags);
}
/* Executable-memory allocators. module_alloc exists through 6.10 (__weak in
 * 6.6); 6.11+ replaced it with execmem_alloc() (EXECMEM_MODULE_TEXT).
 * vmalloc is the universal last resort (still needs set_memory_x to be
 * executable on arm64). On 6.11+ the execmem typedef must use the kernel's
 * enum execmem_type so the kCFI type-hash at the indirect call matches. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#include <linux/execmem.h>
static void *(*kp_hook_execmem_alloc)(enum execmem_type type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#else
static void *(*kp_hook_execmem_alloc)(int type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#endif
static void *(*kp_hook_module_alloc)(unsigned long size);
static void (*kp_hook_module_memfree)(void *region);
static void (*kp_hook_flush_icache_all)(void);
static int (*kp_hook_set_memory_x)(unsigned long addr, int numpages);
static int (*kp_hook_set_memory_nx)(unsigned long addr, int numpages);

static struct mm_struct *kp_hook_init_mm;

#ifndef PTE_PXN
#define KP_HOOK_PTE_PXN (1UL << 53)
#define KP_HOOK_PTE_UXN (1UL << 54)
#define KP_HOOK_PTE_GP  (1UL << 50)
#else
#define KP_HOOK_PTE_PXN PTE_PXN
#define KP_HOOK_PTE_UXN PTE_UXN
#define KP_HOOK_PTE_GP  PTE_GP
#endif

enum kp_hook_alloc_backend {
	KP_HOOK_ALLOC_NONE = 0,
	KP_HOOK_ALLOC_MODULE,
	KP_HOOK_ALLOC_EXECMEM,
	KP_HOOK_ALLOC_VMALLOC,
};
static enum kp_hook_alloc_backend kp_hook_alloc_backend;

/* Raw resolved allocator calls are no_sanitize/noinline to avoid an invalid
 * CFI type-hash read when optional kernel symbols are absent. */
/* Normalize executable hook pages before publishing any trampoline.
 * Clearing GP is required because KPM-generated relocated code has no BTI
 * landing pads; PTE updates are serialized by the kernel page-table lock. */
__attribute__((no_sanitize("cfi"), __noinline__))
static int kp_hook_update_exec(void *region, unsigned long size, bool executable)
{
	unsigned long base = (unsigned long)region;
	unsigned long end, addr;

	if (!kp_hook_init_mm || !region || !size ||
	    (base & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)) ||
	    size > ULONG_MAX - base)
		return -EINVAL;
	end = base + size;
	if (executable && kp_hook_set_memory_x &&
	    kp_hook_set_memory_x(base, size >> PAGE_SHIFT))
		return -EACCES;
	if (!executable && kp_hook_set_memory_nx)
		kp_hook_set_memory_nx(base, size >> PAGE_SHIFT);

	for (addr = base; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgd = pgd_offset(kp_hook_init_mm, addr);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		spinlock_t *ptl;
		pteval_t v;
		unsigned long mask = KP_HOOK_PTE_PXN | KP_HOOK_PTE_UXN | KP_HOOK_PTE_GP;

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
		ptl = pte_lockptr(kp_hook_init_mm, pmd);
		spin_lock(ptl);
		pte = pte_offset_kernel(pmd, addr);
		if (!pte || !pte_present(*pte)) {
			spin_unlock(ptl);
			return -EFAULT;
		}
		v = pte_val(*pte);
		if (executable)
			v &= ~mask;
		else
			v |= mask;
		set_pte_at(kp_hook_init_mm, addr, pte, __pte(v));
		if (executable ? (pte_val(*pte) & mask) : ((pte_val(*pte) & mask) != mask)) {
			spin_unlock(ptl);
			return -EACCES;
		}
		spin_unlock(ptl);
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	}
	return 0;
}

__attribute__((no_sanitize("cfi")))
static int kp_hook_make_exec(void *region, unsigned long size)
{
	return kp_hook_update_exec(region, size, true);
}

__attribute__((no_sanitize("cfi"), __noinline__))
static int kp_hook_make_nx(void *region, unsigned long size)
{
	return kp_hook_update_exec(region, size, false);
}

static void kp_hook_exec_free(void *region, unsigned long size);

__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = NULL;
	unsigned long alloc_size;

	if (!size || size > ULONG_MAX - (PAGE_SIZE - 1))
		return NULL;
	alloc_size = PAGE_ALIGN(size);
	switch (kp_hook_alloc_backend) {
	case KP_HOOK_ALLOC_MODULE:
		p = kp_hook_module_alloc(alloc_size);
		break;
	case KP_HOOK_ALLOC_EXECMEM:
		p = kp_hook_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, alloc_size);
		break;
	case KP_HOOK_ALLOC_VMALLOC:
		p = vmalloc(alloc_size);
		break;
	default:
		break;
	}
	if (p && kp_hook_make_exec(p, alloc_size)) {
		kp_hook_exec_free(p, alloc_size);
		p = NULL;
	}
	return p;
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_hook_exec_free(void *region, unsigned long size)
{
	if (!region)
		return;
	/* Do not return executable pages to the allocator unless NX/BTI
	 * restoration is verified; leaking is safer than executable reuse. */
	if (kp_hook_make_nx(region, size)) {
		logke("Hook executable memory permission restore failed; leaking %px\\n", region);
		return;
	}
	switch (kp_hook_alloc_backend) {
	case KP_HOOK_ALLOC_MODULE:
		kp_hook_module_memfree(region);
		break;
	case KP_HOOK_ALLOC_EXECMEM:
		kp_hook_execmem_free(region);
		break;
	case KP_HOOK_ALLOC_VMALLOC:
		vfree(region);
		break;
	default:
		break;
	}
}

__attribute__((no_sanitize("cfi")))
static void kp_hook_flush_all(void)
{
	if (kp_hook_flush_icache_all)
		kp_hook_flush_icache_all();
}

int kp_hook_runtime_init(void)
{
	kp_hook_module_alloc = (void *)kp_resolve_symbol("module_alloc");
	kp_hook_module_memfree = (void *)kp_resolve_symbol("module_memfree");
	kp_hook_execmem_alloc = (void *)kp_resolve_symbol("execmem_alloc");
	kp_hook_execmem_free = (void *)kp_resolve_symbol("execmem_free");
	kp_hook_flush_icache_all = (void *)kp_resolve_symbol("flush_icache_all");
	kp_hook_set_memory_x = (int (*)(unsigned long, int))kp_resolve_symbol("set_memory_x");
	kp_hook_set_memory_nx = (int (*)(unsigned long, int))kp_resolve_symbol("set_memory_nx");
	kp_hook_init_mm = (struct mm_struct *)kp_resolve_symbol("init_mm");
	if (!kp_hook_init_mm) {
		logke("init_mm unavailable; cannot verify executable Hook memory permissions\n");
		return -ENOSYS;
	}
	if (!kp_hook_flush_icache_all) {
		logke("flush_icache_all unavailable; cannot publish executable Hook trampolines\n");
		return -ENOSYS;
	}
	/* Select a matched allocator/free pair. Never pass memory from one
	 * executable allocator to another backend's free routine. */
	if (kp_hook_module_alloc && kp_hook_module_memfree && kp_hook_set_memory_x)
		kp_hook_alloc_backend = KP_HOOK_ALLOC_MODULE;
	else if (kp_hook_execmem_alloc && kp_hook_execmem_free)
		kp_hook_alloc_backend = KP_HOOK_ALLOC_EXECMEM;
	else
		kp_hook_alloc_backend = KP_HOOK_ALLOC_VMALLOC;
	logki("KPM hook runtime ready backend=%d module_alloc=%px execmem_alloc=%px set_memory_x=%px\\n",
	      kp_hook_alloc_backend, kp_hook_module_alloc, kp_hook_execmem_alloc, kp_hook_set_memory_x);
	return 0;
}

void *hook_mem_zalloc(uintptr_t origin, enum hook_type type)
{
	struct kp_hook_mem *mem;
	size_t size;
	unsigned long flags;

	switch (type) {
	case INLINE:
		size = sizeof(hook_t);
		break;
	case INLINE_CHAIN:
		size = sizeof(hook_chain_t);
		break;
	case FUNCTION_POINTER_CHAIN:
		size = sizeof(fp_hook_chain_t);
		break;
	default:
		return NULL;
	}

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return NULL;
	mem->region_size = PAGE_ALIGN(size);
	mem->region = kp_hook_exec_alloc(mem->region_size);
	if (!mem->region) {
		kfree(mem);
		return NULL;
	}
	memset(mem->region, 0, mem->region_size);
	mem->payload = mem->region;
	mem->origin = origin;
	mem->type = type;
	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	/* Two first-wrap callers can both miss hook_get_mem_from_origin().
	 * Recheck under the insertion lock so only one chain owns an origin. */
	{
		struct kp_hook_mem *pos;
		list_for_each_entry(pos, &kp_hook_mems, list) {
			if (pos->origin == origin) {
				raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
				kp_hook_exec_free(mem->region, mem->region_size);
				kfree(mem);
				return NULL;
			}
		}
	}
	list_add_tail(&mem->list, &kp_hook_mems);
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
	return mem->payload;
}

void *hook_get_mem_from_origin(uint64_t origin)
{
	struct kp_hook_mem *mem;
	unsigned long flags;
	void *result = NULL;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->origin == origin && mem->ready && !mem->retiring) {
			result = mem->payload;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
	return result;
}

void hook_mem_publish(void *payload)
{
	struct kp_hook_mem *mem;
	unsigned long flags;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->payload == payload) {
			mem->ready = true;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
}

void *hook_get_mem_from_origin_type(uint64_t origin, enum hook_type type)
{
	struct kp_hook_mem *mem;
	unsigned long flags;
	void *result = NULL;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->origin == origin && mem->type == type && mem->ready && !mem->retiring) {
			result = mem->payload;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
	return result;
}

int hook_mem_claim_retire(void *payload)
{
	struct kp_hook_mem *mem;
	unsigned long flags;
	int rc = -ENOENT;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->payload != payload)
			continue;
		if (!mem->ready || mem->retiring)
			rc = -EBUSY;
		else {
			mem->retiring = true;
			rc = 0;
		}
		break;
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
	return rc;
}

void hook_mem_cancel_retire(void *payload)
{
	struct kp_hook_mem *mem;
	unsigned long flags;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->payload == payload) {
			mem->retiring = false;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
}

/* A successfully restored hook may still have CPUs that entered its old
 * trampoline. Remove the lookup record but deliberately retain executable
 * storage; recycling it would turn an in-flight chain pointer into UAF. */
void hook_mem_retire(void *payload)
{
	struct kp_hook_mem *mem, *tmp;
	unsigned long flags;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry_safe(mem, tmp, &kp_hook_mems, list) {
		if (mem->payload == payload) {
			list_del(&mem->list);
			raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
			kfree(mem);
			return;
		}
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
}

void hook_mem_free(void *payload)
{
	struct kp_hook_mem *mem, *tmp;
	unsigned long flags;

	raw_spin_lock_irqsave(&kp_hook_lock, flags);
	list_for_each_entry_safe(mem, tmp, &kp_hook_mems, list) {
			if (mem->payload == payload && !mem->ready) {
			list_del(&mem->list);
			raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
			kp_hook_exec_free(mem->region);
			kfree(mem);
			return;
		}
	}
	raw_spin_unlock_irqrestore(&kp_hook_lock, flags);
}

int hotpatch(void *addrs[], uint32_t values[], int count)
{
	if (!addrs || !values || count <= 0 || count > 64)
		return -EINVAL;
	return kp_patch_text_batch(addrs, values, count);
}

int hotpatch_exchange64(void *addr, uint64_t desired, uint64_t *original)
{
	return kp_patch_exchange64(addr, desired, original);
}

int hotpatch_cmpxchg64(void *addr, uint64_t expected, uint64_t desired)
{
	return kp_patch_cmpxchg64(addr, expected, desired);
}

void flush_icache_all(void)
{
	kp_hook_flush_all();
}
