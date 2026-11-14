/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Page-run allocator and W^X permission manager for executable KPM images.
 *
 * TLSF metadata is kept in kp_rw_mem. The executable arena itself contains
 * only page-aligned module allocations; allocator metadata is never written
 * into pages that may become read-only or executable.
 */

#include <kpmalloc.h>
#include <kp_spinlock.h>
#include <pgtable.h>
#include <cache.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#define KP_EXEC_MAX_PAGES 1024U
#define KP_EXEC_PAGE_BUSY 0xfffeU
#define KP_EXEC_PAGE_INTERIOR 0xffffU
#define KP_EXEC_FLAG_FINALIZED 0x01U
#define KP_EXEC_PA_MASK 0x0000FFFFFFFFF000ull
#define KP_EXEC_TABLE_RESTRICT_MASK ((1ull << 62) | (1ull << 59))

enum kp_exec_protection {
    KP_EXEC_RW_NX,
    KP_EXEC_RO_NX,
    KP_EXEC_RX,
};

extern int64_t page_size;
extern int64_t page_shift;
extern int64_t page_level;
extern uint64_t pgd_pa;
extern uint64_t pgd_va;
extern uint64_t kernel_stext_va;
extern tlsf_t kp_rw_mem;

struct kp_exec_allocator {
    uint64_t base;
    size_t page_bytes;
    unsigned int page_count;
    /* 0 = free, 0xfffe = transition, 0xffff = continuation, else run head. */
    uint16_t runs[KP_EXEC_MAX_PAGES];
    uint8_t flags[KP_EXEC_MAX_PAGES];
    /* Scratch is serialized by exec_prot_lock; it lives in the RW pool. */
    volatile uint64_t *kimg_ptes[KP_EXEC_MAX_PAGES];
    volatile uint64_t *linear_ptes[KP_EXEC_MAX_PAGES];
};

static struct kp_exec_allocator *exec_allocator;
static spinlock_t exec_allocator_lock;
static spinlock_t exec_prot_lock;

static bool is_power_of_two(size_t value)
{
    return value && !(value & (value - 1));
}

/*
 * Walk only 4-KiB, 39-bit TTBR1 page mappings. Reject block descriptors,
 * invalid levels, and ancestor APTable/PXNTable restrictions. This stricter
 * walker is intentionally local to executable permission changes.
 */
static volatile uint64_t *exec_walk_leaf(uint64_t va)
{
    uint64_t table_va;
    uint64_t table_pa;

    if (page_shift != 12 || page_size != 4096 || page_level != 3 ||
        (va >> 39) != 0x1ffffffull || !pgd_pa ||
        !pgd_va || (pgd_va & (page_size - 1)))
        return NULL;

    table_va = pgd_va;
    for (int64_t level = 4 - page_level; level < 4; ++level) {
        uint64_t shift = (page_shift - 3) * (4 - level) + 3;
        uint64_t index = (va >> shift) & ((1ull << (page_shift - 3)) - 1);
        volatile uint64_t *entry = (volatile uint64_t *)(unsigned long)
                                   (table_va + index * sizeof(uint64_t));
        uint64_t desc = *entry;

        if (level == 3)
            return (desc & 0x3ull) == 0x3ull ? entry : NULL;

        if ((desc & 0x3ull) != 0x3ull ||
            (desc & KP_EXEC_TABLE_RESTRICT_MASK))
            return NULL;

        table_pa = desc & KP_EXEC_PA_MASK;
        if (!table_pa || table_pa > (uint64_t)-1 - linear_voffset)
            return NULL;
        table_va = table_pa + linear_voffset;
        if ((table_va & (page_size - 1)) ||
            table_va > (uint64_t)-1 - page_size)
            return NULL;
    }
    return NULL;
}

static bool exec_leaf_valid(volatile uint64_t *pte, uint64_t expected_pa,
                            uint64_t attr_index, bool reject_contiguous)
{
    uint64_t desc;

    if (!pte) return false;
    desc = *pte;
    if ((desc & 0x3ull) != 0x3ull ||
        (desc & KP_EXEC_PA_MASK) != expected_pa ||
        (desc & 0x1cull) != attr_index ||
        (desc & 0x300ull) != 0x300ull ||
        !(desc & (1ull << 10)))
        return false;
    if (reject_contiguous && (desc & (1ull << 52)))
        return false;
    return true;
}

/*
 * The linear-map alias may use an ARM64 block descriptor (commonly 2-MiB).
 * We do not split or rewrite such a block: it is acceptable only when it is
 * already privileged-XN and maps the exact physical page. Page aliases are
 * returned for synchronized permission updates.
 */
static int exec_walk_linear_alias(uint64_t va, uint64_t expected_pa,
                                  uint64_t attr_index,
                                  volatile uint64_t **leaf)
{
    uint64_t table_va;

    *leaf = NULL;
    if (page_shift != 12 || page_size != 4096 || page_level != 3 ||
        (va >> 39) != 0x1ffffffull || !pgd_pa ||
        !pgd_va || (pgd_va & (page_size - 1)))
        return -EFAULT;

    table_va = pgd_va;
    for (int64_t level = 4 - page_level; level < 4; ++level) {
        uint64_t shift = (page_shift - 3) * (4 - level) + 3;
        uint64_t index = (va >> shift) & ((1ull << (page_shift - 3)) - 1);
        volatile uint64_t *entry = (volatile uint64_t *)(unsigned long)
                                   (table_va + index * sizeof(uint64_t));
        uint64_t desc = *entry;
        uint64_t type = desc & 0x3ull;

        if (level == 3) {
            if (type != 0x3ull ||
                !exec_leaf_valid(entry, expected_pa, attr_index, true))
                return -EFAULT;
            *leaf = entry;
            return 0;
        }

        if (type == 0x1ull) {
            unsigned int block_shift =
                (unsigned int)((3 - level) * (page_shift - 3) + page_shift);
            uint64_t block_size = 1ull << block_shift;
            uint64_t block_mask =
                ((1ull << (48 - block_shift)) - 1) << block_shift;
            uint64_t mapped_pa = (desc & block_mask) | (va & (block_size - 1));

            if (mapped_pa != expected_pa ||
                (desc & 0x1cull) != attr_index ||
                (desc & 0x300ull) != 0x300ull ||
                !(desc & (1ull << 10)) ||
                !(desc & PTE_PXN))
                return -EFAULT;
            return 0;
        }

        if (type != 0x3ull || (desc & KP_EXEC_TABLE_RESTRICT_MASK))
            return -EFAULT;

        uint64_t table_pa = desc & KP_EXEC_PA_MASK;
        if (!table_pa || table_pa > (uint64_t)-1 - linear_voffset)
            return -EFAULT;
        table_va = table_pa + linear_voffset;
        if ((table_va & (page_size - 1)) ||
            table_va > (uint64_t)-1 - page_size)
            return -EFAULT;
    }
    return -EFAULT;
}

/* Preflight both KIMG and linear aliases and cache their leaf-PTE addresses. */
static int exec_prepare_pages(struct kp_exec_allocator *a, uint64_t base,
                              size_t bytes, uint64_t *linear_base)
{
    volatile uint64_t *text_pte;
    uint64_t text_desc, attr_index, base_pa;
    unsigned int pages;

    if (!a || !base || !bytes || bytes % a->page_bytes ||
        (base & (a->page_bytes - 1)) ||
        base > (uint64_t)-1 - bytes ||
        base < kimage_voffset)
        return -EINVAL;

    pages = (unsigned int)(bytes / a->page_bytes);
    if (!pages || pages > a->page_count || pages > KP_EXEC_MAX_PAGES)
        return -EOVERFLOW;

    base_pa = base - kimage_voffset;
    if (!base_pa || base_pa > KP_EXEC_PA_MASK ||
        base_pa > (uint64_t)-1 - linear_voffset)
        return -EOVERFLOW;
    *linear_base = base_pa + linear_voffset;
    if (*linear_base > (uint64_t)-1 - bytes)
        return -EOVERFLOW;

    text_pte = exec_walk_leaf(kernel_stext_va);
    if (!text_pte) return -EFAULT;
    text_desc = *text_pte;
    if ((text_desc & 0x3ull) != 0x3ull ||
        !(text_desc & (1ull << 10)) ||
        (text_desc & 0x300ull) != 0x300ull)
        return -EFAULT;
    attr_index = text_desc & 0x1cull;

    for (unsigned int i = 0; i < pages; ++i) {
        uint64_t kimg_va = base + (uint64_t)i * a->page_bytes;
        uint64_t expected_pa = base_pa + (uint64_t)i * a->page_bytes;
        uint64_t linear_va = *linear_base + (uint64_t)i * a->page_bytes;
        volatile uint64_t *kimg_pte = exec_walk_leaf(kimg_va);
        volatile uint64_t *linear_pte = NULL;

        if (expected_pa > KP_EXEC_PA_MASK ||
            !exec_leaf_valid(kimg_pte, expected_pa, attr_index, true))
            return -EFAULT;

        if (linear_va != kimg_va) {
            if (exec_walk_linear_alias(linear_va, expected_pa,
                                       attr_index, &linear_pte))
                return -EFAULT;
        }

        a->kimg_ptes[i] = kimg_pte;
        a->linear_ptes[i] = linear_pte;
    }
    return 0;
}

static uint64_t exec_apply_protection(uint64_t desc,
                                      enum kp_exec_protection protection)
{
    desc |= PTE_SHARED;
    desc &= ~PTE_GP;

    switch (protection) {
    case KP_EXEC_RX:
        desc = (desc | PTE_RDONLY) & ~(PTE_DBM | PTE_PXN);
        break;
    case KP_EXEC_RO_NX:
        desc = (desc | PTE_RDONLY | PTE_PXN) & ~PTE_DBM;
        break;
    case KP_EXEC_RW_NX:
    default:
        desc = (desc | PTE_DBM | PTE_PXN) & ~PTE_RDONLY;
        break;
    }
    return desc;
}

static void exec_flush_alias_ranges(uint64_t base, uint64_t linear_base,
                                    size_t bytes)
{
    flush_tlb_kernel_range(base, base + bytes);
    if (linear_base != base)
        flush_tlb_kernel_range(linear_base, linear_base + bytes);
}

static int exec_set_uniform_protection(struct kp_exec_allocator *a,
                                       uint64_t base, size_t bytes,
                                       enum kp_exec_protection protection)
{
    unsigned long flags;
    uint64_t linear_base = 0;
    unsigned int pages;
    int rc;

    flags = kp_private_spin_lock(&exec_prot_lock);
    rc = exec_prepare_pages(a, base, bytes, &linear_base);
    if (!rc) {
        pages = (unsigned int)(bytes / a->page_bytes);
        for (unsigned int i = 0; i < pages; ++i) {
            uint64_t desc = exec_apply_protection(*a->kimg_ptes[i], protection);
            *a->kimg_ptes[i] = desc;
            if (a->linear_ptes[i])
                *a->linear_ptes[i] =
                    exec_apply_protection(*a->linear_ptes[i], protection);
        }
    }
    kp_private_spin_unlock(&exec_prot_lock, flags);

    if (!rc)
        exec_flush_alias_ranges(base, linear_base, bytes);
    return rc;
}

static int exec_set_module_protection(struct kp_exec_allocator *a,
                                      uint64_t base, size_t allocation_bytes,
                                      size_t module_size, size_t text_size,
                                      size_t ro_size, size_t symtab_start)
{
    unsigned long flags;
    uint64_t linear_base = 0;
    unsigned int pages;
    int rc;

    if (!module_size || module_size > allocation_bytes ||
        !text_size || text_size > ro_size || ro_size > symtab_start ||
        symtab_start > module_size ||
        (text_size & (a->page_bytes - 1)) ||
        (ro_size & (a->page_bytes - 1)) ||
        (symtab_start & (a->page_bytes - 1)))
        return -EINVAL;

    flags = kp_private_spin_lock(&exec_prot_lock);
    rc = exec_prepare_pages(a, base, allocation_bytes, &linear_base);
    if (!rc) {
        pages = (unsigned int)(allocation_bytes / a->page_bytes);
        for (unsigned int i = 0; i < pages; ++i) {
            size_t offset = (size_t)i * a->page_bytes;
            enum kp_exec_protection protection;

            if (offset < text_size)
                protection = KP_EXEC_RX;
            else if (offset < ro_size || offset >= symtab_start)
                protection = KP_EXEC_RO_NX;
            else
                protection = KP_EXEC_RW_NX;

            *a->kimg_ptes[i] =
                exec_apply_protection(*a->kimg_ptes[i], protection);
            if (a->linear_ptes[i])
                *a->linear_ptes[i] =
                    exec_apply_protection(*a->linear_ptes[i], protection);
        }
    }
    kp_private_spin_unlock(&exec_prot_lock, flags);

    if (!rc)
        exec_flush_alias_ranges(base, linear_base, allocation_bytes);
    return rc;
}

static void *exec_alloc_locked(size_t bytes, size_t alignment)
{
    struct kp_exec_allocator *a = exec_allocator;
    size_t pages;
    unsigned int i, j;

    if (!a || !bytes) return NULL;
    if (!alignment) alignment = a->page_bytes;
    if (!is_power_of_two(alignment)) return NULL;
    if (alignment < a->page_bytes) alignment = a->page_bytes;
    if (bytes > (size_t)-1 - (a->page_bytes - 1)) return NULL;

    pages = (bytes + a->page_bytes - 1) / a->page_bytes;
    if (!pages || pages > a->page_count || pages > 0xfffdU) return NULL;

    for (i = 0; i <= a->page_count - pages; ++i) {
        uint64_t address = a->base + (uint64_t)i * a->page_bytes;
        if (address & (alignment - 1)) continue;
        for (j = 0; j < pages && a->runs[i + j] == 0; ++j) {}
        if (j != pages) {
            i += j;
            continue;
        }
        a->runs[i] = (uint16_t)pages;
        a->flags[i] = 0;
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
    if (!pages || pages >= KP_EXEC_PAGE_BUSY ||
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
    a->flags[index] = 0;
    return true;
}

int kp_exec_allocator_init(void *base, size_t bytes, size_t runtime_page_size)
{
    struct kp_exec_allocator *a;
    int rc;

    if (exec_allocator) return -EBUSY;
    if (!kp_rw_mem || !base || !runtime_page_size ||
        !is_power_of_two(runtime_page_size) ||
        ((uint64_t)(unsigned long)base & (runtime_page_size - 1)) ||
        !bytes || bytes % runtime_page_size) return -EINVAL;
    if ((uint64_t)(unsigned long)base > (uint64_t)-1 - (uint64_t)bytes)
        return -EOVERFLOW;
    if (bytes / runtime_page_size > KP_EXEC_MAX_PAGES ||
        bytes / runtime_page_size > 0xfffdU) return -EOVERFLOW;

    a = tlsf_malloc(kp_rw_mem, sizeof(*a));
    if (!a) return -ENOMEM;
    memset(a, 0, sizeof(*a));
    a->base = (uint64_t)(unsigned long)base;
    a->page_bytes = runtime_page_size;
    a->page_count = (unsigned int)(bytes / runtime_page_size);

    /* Free executable-arena pages are writable but never executable. */
    rc = exec_set_uniform_protection(a, a->base, bytes, KP_EXEC_RW_NX);
    if (rc) {
        tlsf_free(kp_rw_mem, a);
        return rc;
    }
    exec_allocator = a;
    return 0;
}

static void *exec_alloc(size_t bytes, size_t alignment)
{
    struct kp_exec_allocator *a;
    unsigned long flags;
    void *ptr;
    unsigned int pages;
    uint64_t address;

    flags = kp_private_spin_lock(&exec_allocator_lock);
    a = exec_allocator;
    ptr = exec_alloc_locked(bytes, alignment);
    if (ptr) {
        address = (uint64_t)(unsigned long)ptr;
        pages = a->runs[(address - a->base) / a->page_bytes];
    } else {
        pages = 0;
    }
    kp_private_spin_unlock(&exec_allocator_lock, flags);

    if (!ptr) return NULL;
    if (exec_set_uniform_protection(a, address,
                                    (size_t)pages * a->page_bytes,
                                    KP_EXEC_RW_NX)) {
        flags = kp_private_spin_lock(&exec_allocator_lock);
        (void)exec_free_locked(ptr);
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return NULL;
    }
    return ptr;
}

void *kp_exec_malloc(size_t bytes)
{
    return exec_alloc(bytes, 0);
}

void *kp_exec_memalign(size_t alignment, size_t bytes)
{
    return exec_alloc(bytes, alignment);
}

int kp_exec_seal(void *ptr)
{
    struct kp_exec_allocator *a;
    unsigned long flags;
    unsigned int pages, index;
    uint64_t address;
    int rc;

    if (!ptr) return -EINVAL;
    flags = kp_private_spin_lock(&exec_allocator_lock);
    a = exec_allocator;
    pages = exec_validate_head_locked(ptr);
    if (!pages || !a) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return -EINVAL;
    }
    address = (uint64_t)(unsigned long)ptr;
    index = (unsigned int)((address - a->base) / a->page_bytes);
    if (a->flags[index] & KP_EXEC_FLAG_FINALIZED) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return -EBUSY;
    }
    a->runs[index] = KP_EXEC_PAGE_BUSY;
    kp_private_spin_unlock(&exec_allocator_lock, flags);

    rc = exec_set_uniform_protection(a, address,
                                     (size_t)pages * a->page_bytes,
                                     KP_EXEC_RX);

    flags = kp_private_spin_lock(&exec_allocator_lock);
    a->runs[index] = (uint16_t)pages;
    if (!rc)
        a->flags[index] |= KP_EXEC_FLAG_FINALIZED;
    kp_private_spin_unlock(&exec_allocator_lock, flags);
    return rc;
}

int kp_exec_free(void *ptr)
{
    struct kp_exec_allocator *a;
    unsigned long flags;
    unsigned int pages, index;
    uint64_t address;
    int rc;

    if (!ptr) return 0;
    flags = kp_private_spin_lock(&exec_allocator_lock);
    a = exec_allocator;
    pages = exec_validate_head_locked(ptr);
    if (!pages || !a) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return -EINVAL;
    }
    address = (uint64_t)(unsigned long)ptr;
    index = (unsigned int)((address - a->base) / a->page_bytes);
    a->runs[index] = KP_EXEC_PAGE_BUSY;
    kp_private_spin_unlock(&exec_allocator_lock, flags);

    rc = exec_set_uniform_protection(a, address,
                                     (size_t)pages * a->page_bytes,
                                     KP_EXEC_RW_NX);

    flags = kp_private_spin_lock(&exec_allocator_lock);
    if (rc) {
        a->runs[index] = (uint16_t)pages;
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return rc;
    }
    for (unsigned int i = 0; i < pages; ++i)
        a->runs[index + i] = 0;
    a->flags[index] = 0;
    kp_private_spin_unlock(&exec_allocator_lock, flags);
    return 0;
}

void *kp_exec_realloc(void *ptr, size_t bytes)
{
    struct kp_exec_allocator *a;
    unsigned long flags;
    unsigned int old_pages, new_pages, index, i;
    size_t requested_pages, copy_bytes;
    void *replacement;

    if (!ptr) return kp_exec_malloc(bytes);
    if (!bytes) {
        (void)kp_exec_free(ptr);
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
    index = (unsigned int)(((uint64_t)(unsigned long)ptr - a->base) / a->page_bytes);
    if (a->flags[index] & KP_EXEC_FLAG_FINALIZED) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return NULL;
    }
    requested_pages = (bytes + a->page_bytes - 1) / a->page_bytes;
    if (!requested_pages || requested_pages > a->page_count ||
        requested_pages > 0xfffdU) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return NULL;
    }
    new_pages = (unsigned int)requested_pages;

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
    kp_private_spin_unlock(&exec_allocator_lock, flags);

    replacement = kp_exec_malloc(bytes);
    if (!replacement) return NULL;
    copy_bytes = (size_t)old_pages * a->page_bytes;
    if (copy_bytes > bytes) copy_bytes = bytes;
    memcpy(replacement, ptr, copy_bytes);
    if (kp_exec_free(ptr)) {
        (void)kp_exec_free(replacement);
        return NULL;
    }
    return replacement;
}

int kp_exec_protect_module(void *ptr, size_t module_size, size_t text_size,
                           size_t ro_size, size_t symtab_start)
{
    struct kp_exec_allocator *a;
    unsigned long flags;
    unsigned int pages, index;
    uint64_t address;
    int rc;

    flags = kp_private_spin_lock(&exec_allocator_lock);
    a = exec_allocator;
    pages = exec_validate_head_locked(ptr);
    if (!pages || !a) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return -EINVAL;
    }
    address = (uint64_t)(unsigned long)ptr;
    index = (unsigned int)((address - a->base) / a->page_bytes);
    if (a->flags[index] & KP_EXEC_FLAG_FINALIZED) {
        kp_private_spin_unlock(&exec_allocator_lock, flags);
        return -EBUSY;
    }
    a->runs[index] = KP_EXEC_PAGE_BUSY;
    kp_private_spin_unlock(&exec_allocator_lock, flags);

    rc = exec_set_module_protection(a, address,
                                    (size_t)pages * a->page_bytes,
                                    module_size, text_size, ro_size,
                                    symtab_start);

    flags = kp_private_spin_lock(&exec_allocator_lock);
    a->runs[index] = (uint16_t)pages;
    if (!rc)
        a->flags[index] |= KP_EXEC_FLAG_FINALIZED;
    kp_private_spin_unlock(&exec_allocator_lock, flags);
    return rc;
}
