/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Page-run allocator for the executable KPM image arena.
 *
 * The arena is deliberately not managed by TLSF: TLSF stores free-list and
 * block headers inside its pool, which prevents safely making module pages
 * read-only/executable independently. Allocator metadata lives in kp_rw_mem.
 */

#include <kpmalloc.h>
#include <kp_spinlock.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#define KP_EXEC_MAX_PAGES 1024U
#define KP_EXEC_PAGE_INTERIOR 0xffffU

extern int64_t page_size;
extern tlsf_t kp_rw_mem;

struct kp_exec_allocator {
    uint64_t base;
    size_t page_bytes;
    unsigned int page_count;
    /* 0 = free, 0xffff = continuation, otherwise run length at allocation head. */
    uint16_t runs[KP_EXEC_MAX_PAGES];
};

static struct kp_exec_allocator *exec_allocator;
static spinlock_t exec_allocator_lock;

static bool is_power_of_two(size_t value)
{
    return value && !(value & (value - 1));
}

static void *exec_alloc_locked(size_t bytes, size_t alignment)
{
    struct kp_exec_allocator *a = exec_allocator;
    size_t rounded, pages;
    unsigned int i, j;

    if (!a || !bytes) return NULL;
    if (!alignment) alignment = a->page_bytes;
    if (!is_power_of_two(alignment)) return NULL;
    if (alignment < a->page_bytes) alignment = a->page_bytes;
    if (bytes > (size_t)-1 - (a->page_bytes - 1)) return NULL;

    rounded = (bytes + a->page_bytes - 1) / a->page_bytes;
    pages = rounded;
    if (!pages || pages > a->page_count || pages > 0xfffeU) return NULL;

    for (i = 0; i <= a->page_count - pages; ++i) {
        uint64_t address = a->base + (uint64_t)i * a->page_bytes;
        if (address & (alignment - 1)) continue;
        for (j = 0; j < pages && a->runs[i + j] == 0; ++j) {}
        if (j != pages) {
            i += j;
            continue;
        }
        a->runs[i] = (uint16_t)pages;
        for (j = 1; j < pages; ++j)
            a->runs[i + j] = KP_EXEC_PAGE_INTERIOR;
        return (void *)(unsigned long)address;
    }
    return NULL;
}

/* Returns the run length only for an exact, live allocation base. */
static unsigned int exec_validate_head_locked(void *ptr)
{
    struct kp_exec_allocator *a = exec_allocator;
    uint64_t address = (uint64_t)(unsigned long)ptr;
    uint64_t offset;
    unsigned int index, pages, i;

    if (!a || !ptr || address < a->base) return 0;
    offset = address - a->base;
    if (offset >= (uint64_t)a->page_count * a->page_bytes ||
        offset % a->page_bytes) return 0;
    index = (unsigned int)(offset / a->page_bytes);
    pages = a->runs[index];
    if (!pages || pages == KP_EXEC_PAGE_INTERIOR ||
        pages > a->page_count - index) return 0;
    for (i = 1; i < pages; ++i)
        if (a->runs[index + i] != KP_EXEC_PAGE_INTERIOR) return 0;
    return pages;
}

static bool exec_free_locked(void *ptr)
{
    struct kp_exec_allocator *a = exec_allocator;
    uint64_t offset;
    unsigned int index, pages, i;

    pages = exec_validate_head_locked(ptr);
    if (!pages) return false;
    offset = (uint64_t)(unsigned long)ptr - a->base;
    index = (unsigned int)(offset / a->page_bytes);
    for (i = 0; i < pages; ++i)
        a->runs[index + i] = 0;
    return true;
}

int kp_exec_allocator_init(void *base, size_t bytes, size_t runtime_page_size)
{
    struct kp_exec_allocator *a;

    if (exec_allocator) return -EBUSY;
    if (!kp_rw_mem || !base || !runtime_page_size ||
        !is_power_of_two(runtime_page_size) ||
        ((uint64_t)(unsigned long)base & (runtime_page_size - 1)) ||
        !bytes || bytes % runtime_page_size) return -EINVAL;

    if (bytes / runtime_page_size > KP_EXEC_MAX_PAGES ||
        bytes / runtime_page_size > 0xfffeU) return -EOVERFLOW;

    a = tlsf_malloc(kp_rw_mem, sizeof(*a));
    if (!a) return -ENOMEM;
    memset(a, 0, sizeof(*a));
    a->base = (uint64_t)(unsigned long)base;
    a->page_bytes = runtime_page_size;
    a->page_count = (unsigned int)(bytes / runtime_page_size);
    exec_allocator = a;
    return 0;
}

void *kp_exec_malloc(size_t bytes)
{
    void *ptr;
    unsigned long flags = kp_private_spin_lock(&exec_allocator_lock);
    ptr = exec_alloc_locked(bytes, 0);
    kp_private_spin_unlock(&exec_allocator_lock, flags);
    return ptr;
}

void *kp_exec_memalign(size_t alignment, size_t bytes)
{
    void *ptr;
    unsigned long flags = kp_private_spin_lock(&exec_allocator_lock);
    ptr = exec_alloc_locked(bytes, alignment);
    kp_private_spin_unlock(&exec_allocator_lock, flags);
    return ptr;
}

void kp_exec_free(void *ptr)
{
    unsigned long flags;
    if (!ptr) return;
    flags = kp_private_spin_lock(&exec_allocator_lock);
    (void)exec_free_locked(ptr);
    kp_private_spin_unlock(&exec_allocator_lock, flags);
}

void *kp_exec_realloc(void *ptr, size_t bytes)
{
    struct kp_exec_allocator *a;
    unsigned long flags;
    unsigned int old_pages, new_pages, index, i;
    size_t copy_bytes;
    void *replacement;

    if (!ptr) return kp_exec_malloc(bytes);
    if (!bytes) {
        kp_exec_free(ptr);
        return NULL;
    }

    flags = kp_private_spin_lock(&exec_allocator_lock);
    a = exec_allocator;
    old_pages = exec_validate_head_locked(ptr);
    if (!old_pages || !a ||
        bytes > (size_t)-1 - (a->page_bytes - 1)) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return NULL;
    }
    new_pages = (unsigned int)((bytes + a->page_bytes - 1) / a->page_bytes);
    if (!new_pages || new_pages > a->page_count || new_pages > 0xfffeU) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return NULL;
    }
    index = (unsigned int)(((uint64_t)(unsigned long)ptr - a->base) / a->page_bytes);

    if (new_pages <= old_pages) {
        for (i = new_pages; i < old_pages; ++i)
            a->runs[index + i] = 0;
        a->runs[index] = (uint16_t)new_pages;
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return ptr;
    }

    if (new_pages - old_pages <= a->page_count - index - old_pages) {
        for (i = old_pages; i < new_pages &&
             a->runs[index + i] == 0; ++i) {}
        if (i == new_pages) {
            for (i = old_pages; i < new_pages; ++i)
                a->runs[index + i] = KP_EXEC_PAGE_INTERIOR;
            a->runs[index] = (uint16_t)new_pages;
            kp_private_spin_unlock(&exec_allocator_lock, flags);
            return ptr;
        }
    }

    replacement = exec_alloc_locked(bytes, a->page_bytes);
    if (!replacement) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return NULL;
    }
    copy_bytes = (size_t)old_pages * a->page_bytes;
    if (copy_bytes > bytes) copy_bytes = bytes;
    memcpy(replacement, ptr, copy_bytes);
    (void)exec_free_locked(ptr);
    kp_private_spin_unlock(&exec_allocator_lock, flags);
    return replacement;
}
