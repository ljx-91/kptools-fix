// SPDX-License-Identifier: GPL-2.0-or-later
/* LKM backends required by kernel/base/hook.c. */
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

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

enum kp_hook_alloc_backend {
	KP_HOOK_ALLOC_NONE = 0,
	KP_HOOK_ALLOC_MODULE,
	KP_HOOK_ALLOC_EXECMEM,
	KP_HOOK_ALLOC_VMALLOC,
};
static enum kp_hook_alloc_backend kp_hook_alloc_backend;

/* Raw resolved allocator calls are no_sanitize/noinline to avoid an invalid
 * CFI type-hash read when optional kernel symbols are absent. */
__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = NULL;
	unsigned long pages;

	if (!size || size > ULONG_MAX - (PAGE_SIZE - 1))
		return NULL;
	pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	switch (kp_hook_alloc_backend) {
	case KP_HOOK_ALLOC_MODULE:
		p = kp_hook_module_alloc(size);
		if (p && kp_hook_set_memory_x((unsigned long)p, pages)) {
			kp_hook_module_memfree(p);
			p = NULL;
		}
		break;
	case KP_HOOK_ALLOC_EXECMEM:
		p = kp_hook_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
		break;
	case KP_HOOK_ALLOC_VMALLOC:
		p = vmalloc(size);
		if (p && kp_hook_set_memory_x((unsigned long)p, pages)) {
			vfree(p);
			p = NULL;
		}
		break;
	default:
		break;
	}
	return p;
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_hook_exec_free(void *region)
{
	if (!region)
		return;
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
	/* Select a matched allocator/free pair. Never pass memory from one
	 * executable allocator to another backend's free routine. */
	if (kp_hook_module_alloc && kp_hook_module_memfree && kp_hook_set_memory_x)
		kp_hook_alloc_backend = KP_HOOK_ALLOC_MODULE;
	else if (kp_hook_execmem_alloc && kp_hook_execmem_free)
		kp_hook_alloc_backend = KP_HOOK_ALLOC_EXECMEM;
	else if (kp_hook_set_memory_x)
		kp_hook_alloc_backend = KP_HOOK_ALLOC_VMALLOC;
	else {
		logke("no matched executable-memory allocator/free backend\\n");
		return -ENOSYS;
	}
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
	mem->region = kp_hook_exec_alloc(PAGE_ALIGN(size));
	if (!mem->region) {
		kfree(mem);
		return NULL;
	}
	memset(mem->region, 0, PAGE_ALIGN(size));
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
				kp_hook_exec_free(mem->region);
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
