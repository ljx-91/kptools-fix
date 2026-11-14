/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "setup.h"
#define NUMA_NO_NODE (-1)

typedef uint64_t phys_addr_t;
typedef int (*memblock_reserve_f)(phys_addr_t base, phys_addr_t size);
typedef phys_addr_t (*memblock_phys_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, int nid);
typedef phys_addr_t (*memblock_find_in_range_f)(phys_addr_t start, phys_addr_t end, phys_addr_t size,
                                                 phys_addr_t align);
typedef void *(*memblock_virt_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                               phys_addr_t max_addr, int nid);
typedef int (*memblock_free_f)(phys_addr_t base, phys_addr_t size);
typedef int (*memblock_mark_nomap_f)(phys_addr_t base, phys_addr_t size);
typedef int (*printk_f)(const char *fmt, ...);
typedef void (*paging_init_f)(void);

map_data_t map_data __section(.map.data) __aligned(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP: %x-%llx\n",
#endif
};

uint64_t __section(.map.text) __noinline __aligned(MAP_ALIGN) get_myva()
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    return this_va & ~((uint64_t)MAP_ALIGN - 1);
}

map_data_t *__noinline get_data()
{
    uint64_t va = get_myva() - sizeof(map_data_t);
    return (map_data_t *)(va & ~((uint64_t)MAP_ALIGN - 1));
}

static uint64_t get_kva()
{
    map_data_t *data = get_data();
    uint64_t kernel_va = (uint64_t)data - data->map_offset;
    return kernel_va;
}

static inline uint64_t phys_to_lm(map_data_t *data, uint64_t phys)
{
    return phys + data->linear_voffset;
}

static void __noinline copy_map_range(uint64_t dst, uint64_t src, uint64_t size)
{
    uint64_t off = 0;
    if (!((dst | src) & (sizeof(uint64_t) - 1))) {
        for (; size - off >= sizeof(uint64_t); off += sizeof(uint64_t))
            *(uint64_t *)(dst + off) = *(uint64_t *)(src + off);
    }
    for (; off < size; ++off)
        *(uint8_t *)(dst + off) = *(uint8_t *)(src + off);
}

static uint64_t map_phys_alloc(map_data_t *data, uint64_t size, uint64_t align)
{
    if (!size || !align || (align & (align - 1))) return 0;

    if (data->map_symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID) {
        return ((memblock_phys_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo)(size, align,
                                                                                         NUMA_NO_NODE);
    }

    if (data->map_symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_FIND_IN_RANGE) {
        if (!data->map_symbol.memblock_reserve_relo) return 0;

        /*
         * memblock_find_in_range(start, end, size, align) returns a physical
         * address but does not reserve it. Reserve the exact result before
         * exposing it to page-table construction or the relocated image.
         */
        uint64_t pa = ((memblock_find_in_range_f)data->map_symbol.memblock_phys_alloc_relo)(
            0, 0, size, align);
        if (!pa || (pa & (align - 1)) || pa > ~(uint64_t)0 - size) return 0;

        if (((memblock_reserve_f)data->map_symbol.memblock_reserve_relo)(pa, size)) return 0;
        return pa;
    }

    return 0;
}

static void flush_tlb_all()
{
    asm volatile("dsb ishst" : : : "memory");
    asm volatile("tlbi vmalle1is\n"
                 "dsb ish\n"
                 "tlbi vmalle1is\n");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

// The map region is copied to a different kernel address at boot, so it must be
// self-contained: no `bl` may leave the region. GCC 14 lowers the 0xa0-byte
// struct copy `*data = *get_data()` to a memcpy() call; that bl targets the
// kpimg's own memcpy (fixed kpimg offset) and misrelocates once the map code is
// copied into the kernel, jumping into unrelated kernel text (e.g. tcp_done).
// Copy explicitly with a volatile byte loop so no memcpy call is emitted.
static __noinline void copy_map_data(map_data_t *dst)
{
    const map_data_t *src = get_data();
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const volatile unsigned char *s = (const volatile unsigned char *)src;
    for (unsigned int i = 0; i < sizeof(map_data_t); i++) {
        d[i] = s[i];
    }
}

static __noinline void mem_proc(map_data_t *data)
{
    copy_map_data(data);
    if (!data->map_symbol.memblock_reserve_relo || !data->map_symbol.memblock_free_relo ||
        !data->map_symbol.memblock_mark_nomap_relo) __builtin_trap();
    uint64_t kernel_va = get_kva();

    // relocation
    data->kimage_voffset = kernel_va - data->kernel_pa;
    data->paging_init_relo += kernel_va;

#ifdef MAP_DEBUG
    data->printk_relo += kernel_va;
#endif

    if (data->map_symbol.memblock_reserve_relo) data->map_symbol.memblock_reserve_relo += kernel_va;
    if (data->map_symbol.memblock_free_relo) data->map_symbol.memblock_free_relo += kernel_va;
    if (data->map_symbol.memblock_phys_alloc_relo) data->map_symbol.memblock_phys_alloc_relo += kernel_va;
    if (data->map_symbol.memblock_virt_alloc_relo) data->map_symbol.memblock_virt_alloc_relo += kernel_va;
    if (data->map_symbol.memblock_mark_nomap_relo) data->map_symbol.memblock_mark_nomap_relo += kernel_va;

    // pgtable
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t t1sz = tcr_el1 << 42 >> 58; // bits(tcr_el1, 21, 16)
    uint64_t va1_bits = 64 - t1sz;
    data->va1_bits = va1_bits;
    uint64_t tg1 = tcr_el1 << 32 >> 62; // bits(tcr_el1, 31, 30)
    uint64_t page_shift = 12;
    if (tg1 == 1) {
        page_shift = 14;
    } else if (tg1 == 3) {
        page_shift = 16;
    }
    data->page_shift = page_shift;

#ifdef KP_TARGET_Y73S
    /*
     * The supported Y73S V2031A kernel is a 39-bit VA, 4-KiB granule
     * configuration. TCR_EL1.TG1 == 0b10 encodes 4-KiB translation
     * granules; T1SZ == 25 gives 39 address bits. Do not let an
     * unexpected firmware/kernel configuration feed incompatible
     * geometry into the page-table walker.
     */
    if (tg1 != 2 || t1sz != 25 || page_shift != 12 || va1_bits != 39)
        __builtin_trap();
#endif

#ifndef KP_TARGET_Y73S
    // linear
    if (data->map_symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_FIND_IN_RANGE &&
        data->map_symbol.memblock_virt_alloc_relo && data->map_symbol.memblock_free_relo) {
        /*
         * Y73S 4.14.141 has no memblock_phys_alloc_try_nid. Probe a free page
         * with the physical range finder, then ask the 5-argument nopanic
         * virtual allocator to allocate inside that exact one-page interval.
         * The returned pointer and selected PA therefore describe the same
         * page. Release the temporary reservation after deriving the offset.
         */
        uint64_t page_size = 1ull << data->page_shift;
        uint64_t detect_phys = ((memblock_find_in_range_f)data->map_symbol.memblock_phys_alloc_relo)(
            0, 0, page_size, page_size);
        if (!detect_phys || detect_phys > ~(uint64_t)0 - page_size) __builtin_trap();

        uint64_t detect_virt = (uint64_t)((memblock_virt_alloc_try_nid_f)data->map_symbol.memblock_virt_alloc_relo)(
            page_size, page_size, detect_phys, detect_phys + page_size, NUMA_NO_NODE);
        if (!detect_virt || detect_virt <= detect_phys) __builtin_trap();

        data->linear_voffset = detect_virt - detect_phys;
        // A failed free only leaks this one temporary page; it does not
        // invalidate the already verified physical-to-virtual pair.
        ((memblock_free_f)data->map_symbol.memblock_free_relo)(detect_phys, page_size);
    } else if (data->map_symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID &&
               data->map_symbol.memblock_phys_alloc_relo && data->map_symbol.memblock_virt_alloc_relo) {
        uint64_t detect_phys =
            ((memblock_phys_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo)(0, 0x10, NUMA_NO_NODE);
        if (!detect_phys) __builtin_trap();
        uint64_t detect_virt = (uint64_t)((memblock_virt_alloc_try_nid_f)data->map_symbol.memblock_virt_alloc_relo)(
            0, 0x10, detect_phys, detect_phys, NUMA_NO_NODE);
        if (!detect_virt || detect_virt <= detect_phys) __builtin_trap();
        data->linear_voffset = detect_virt - detect_phys;
    } else {
        __builtin_trap();
    }
#endif // !KP_TARGET_Y73S
}


#ifdef KP_TARGET_Y73S
/*
 * Y73S Linux 4.14 calls paging_init() before building the full linear map.
 * memblock_virt_alloc_try_nid_nopanic() zeroes its allocation through
 * phys_to_virt(), so it must not be used as a linear-map probe before
 * paging_init() has completed. Run this probe immediately after paging_init()
 * returns, when map_mem() has established the normal RAM linear mapping.
 */
static void __noinline detect_y73s_linear_voffset(map_data_t *data)
{
    if (data->map_symbol.memblock_phys_alloc_type != MAP_SYM_MEMBLOCK_FIND_IN_RANGE ||
        !data->map_symbol.memblock_phys_alloc_relo ||
        !data->map_symbol.memblock_virt_alloc_relo ||
        !data->map_symbol.memblock_free_relo) {
        __builtin_trap();
    }

    uint64_t page_size = 1ull << data->page_shift;
    uint64_t detect_phys =
        ((memblock_find_in_range_f)data->map_symbol.memblock_phys_alloc_relo)(
            0, 0, page_size, page_size);
    if (!detect_phys || detect_phys > ~(uint64_t)0 - page_size) __builtin_trap();

    uint64_t detect_virt =
        (uint64_t)((memblock_virt_alloc_try_nid_f)data->map_symbol.memblock_virt_alloc_relo)(
            page_size, page_size, detect_phys, detect_phys + page_size, NUMA_NO_NODE);
    if (!detect_virt || detect_virt <= detect_phys || (detect_virt & (page_size - 1)))
        __builtin_trap();

    /*
     * Linux 4.14's memblock_virt_alloc_try_nid_nopanic() treats min_addr as
     * a preference: if the exact interval cannot be allocated it retries
     * from address zero. Verify that the requested PA was actually reserved
     * before deriving a linear offset from this PA/VA pair. A nonzero result
     * means the allocator fell back elsewhere, so the pair is not trustworthy.
     */
    uint64_t still_free =
        ((memblock_find_in_range_f)data->map_symbol.memblock_phys_alloc_relo)(
            detect_phys, detect_phys + page_size, page_size, page_size);
    if (still_free) __builtin_trap();

    data->linear_voffset = detect_virt - detect_phys;

    /* Release the exact probe page; failure invalidates the probe. */
    if (((memblock_free_f)data->map_symbol.memblock_free_relo)(detect_phys, page_size))
        __builtin_trap();
}
#endif // KP_TARGET_Y73S

// todo: 52-bits pa
static uint64_t __noinline get_or_create_pte(map_data_t *data, uint64_t va, uint64_t pa, uint64_t attr_indx)
{
    uint64_t page_shift = data->page_shift;
    uint64_t va_bits = data->va1_bits;
    /*
     * Y73S page-table construction is intentionally limited to its
     * verified 4-KiB / 39-bit TTBR1 geometry. pa == 0 remains a
     * read-only AttrIndx lookup request; it does not relax geometry checks.
     */
#ifdef KP_TARGET_Y73S
    if (page_shift != 12 || va_bits != 39) __builtin_trap();
#else
    if (va_bits <= 4 || va_bits > 48 ||
        (page_shift != 12 && page_shift != 14 && page_shift != 16))
        __builtin_trap();
#endif
    uint64_t page_level = (va_bits - 4) / (page_shift - 3);
    if (!page_level || page_level > 4) __builtin_trap();
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;

#ifdef KP_TARGET_Y73S
    /* Every address handled here must be in the canonical TTBR1 39-bit half. */
    if ((va >> 39) != 0x1FFFFFFull) __builtin_trap();
#endif

    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    uint64_t page_size = 1 << page_shift;
    uint64_t page_size_mask = ~(page_size - 1);
    uint64_t attr_prot = 0x40000000000703 | attr_indx;

    uint64_t pxd_pa = baddr & page_size_mask;
    if (!pxd_pa || pxd_pa > ~(uint64_t)0 - data->linear_voffset)
        __builtin_trap();
    uint64_t pxd_va = phys_to_lm(data, pxd_pa);
    if (pxd_va > ~(uint64_t)0 - page_size) __builtin_trap();
    uint64_t pxd_entry_va = 0;

    for (uint64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t block_flag = 0;

        pxd_entry_va = pxd_va + pxd_index * 8;

        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_flag = 1;
        } else { // invalid, alloc
            /* pa == 0 is the lookup-only mode used for kernel text attributes.
             * A missing descriptor is not a mapping request: never allocate
             * intermediate tables or manufacture a valid mapping to PA 0.
             */
            if (!pa) __builtin_trap();
            if (lv != 3) {
                pxd_pa = map_phys_alloc(data, page_size, page_size);
                if (!pxd_pa || pxd_pa > ~(uint64_t)0 - data->linear_voffset)
                    __builtin_trap();
                pxd_va = phys_to_lm(data, pxd_pa);
                if (pxd_va > ~(uint64_t)0 - page_size) __builtin_trap();

                /*
                 * Initialize the child table completely before publishing
                 * its address in the parent. The store barrier prevents a
                 * hardware table walk from observing a valid descriptor
                 * before the zeroed child-table contents are visible.
                 */
                for (uint64_t i = pxd_va; i < pxd_va + page_size; i += 8)
                    *(volatile uint64_t *)i = 0;
                asm volatile("dsb ishst" : : : "memory");
                pxd_desc = pxd_pa | 0x3ull;
            } else {
                pxd_pa = pa;
                pxd_desc = pxd_pa | attr_prot;
            }
            /*
             * Intermediate levels require a table descriptor, not leaf-page
             * attributes. Keep the descriptor type explicit at each level.
             */
            *(volatile uint64_t *)pxd_entry_va = pxd_desc;
        }
        if (!pxd_pa || pxd_pa > ~(uint64_t)0 - data->linear_voffset)
            __builtin_trap();
        pxd_va = phys_to_lm(data, pxd_pa);
        if (pxd_va > ~(uint64_t)0 - page_size) __builtin_trap();
        if (block_flag) {
            /*
             * The caller updates a leaf page descriptor. Returning a block
             * descriptor here would overwrite a larger mapping with a page
             * descriptor and corrupt neighboring translations. Splitting a
             * block requires preserving its attributes and is not implemented.
             */
            __builtin_trap();
        }
    }

    /*
     * The caller may request a lookup-only PTE by passing pa == 0 (used
     * to read the kernel text AttrIndx). For actual destination mappings,
     * never silently accept an already-valid leaf that points at another
     * physical page: the caller only adjusts permissions and does not
     * rewrite the output address. Verify the final descriptor and its OA.
     */
    uint64_t leaf_desc = *(uint64_t *)pxd_entry_va;
    if ((leaf_desc & 0x3ull) != 0x3ull) __builtin_trap();
    if (pa) {
        uint64_t pa_mask = ((1ull << (48 - page_shift)) - 1) << page_shift;
        if ((pa & (page_size - 1)) || (pa >> 48) ||
            (pa & pa_mask) != (leaf_desc & pa_mask))
            __builtin_trap();
    }
    return pxd_entry_va;
}

#ifndef KP_TARGET_Y73S
// todo: bti
// 6.15+ keeps kernel text read-only and creates the linear map inside
// paging_init(), so while the hook runs there is no usable linear map and
// the memblock probe in mem_proc() yields an incoherent phys_to_virt pair.
// swapper_pg_dir lives in the kernel image, so the top-level table is
// reachable and writable through the image mapping: borrow its unused
// entries to alias arbitrary physical pages through the top table itself.
// The chain re-enters the top table at every intermediate level and ends
// with a page descriptor: for 39-bit VA (3 levels) slots s -> j1 -> j2 map
// top -> next -> leaf, for 48-bit VA (4 levels) one more slot joins the
// chain. This needs no linear map and works on both old and new kernels.

#define SCRATCH_MAX_SLOTS 5

typedef struct
{
    uint64_t pgd_va;
    uint64_t pgd_pa;
    uint64_t window;
    uint64_t slots[SCRATCH_MAX_SLOTS]; // [0] = top entry, last = leaf entry
    int nslots;                        // top entry + intermediate entries + leaf
    uint64_t top_shift;
    uint64_t pxd_bits;
    uint64_t page_shift;
    uint64_t va1_bits;
} scratch_t;

#define SCRATCH_DESC_TABLE (0x3ull)
#define SCRATCH_DESC_PAGE (0x703ull) // V|AF|SH inner|AttrIndx 0|EL1 RW (no contiguous)

static int scratch_prep(map_data_t *data, scratch_t *sc)
{
    uint64_t pxd_bits = data->page_shift - 3;
    uint64_t page_level = (data->va1_bits - 4) / pxd_bits;
    // chain length == number of walk levels: 39-bit VA (3 levels) slots
    // s -> j1 -> j2 map top -> next -> leaf; 42/48-bit (4 levels) add one.
    // The last level of a walk only accepts page descriptors, so the chain
    // must not be deeper than the walk itself.
    int nslots = (int)page_level;
    if (page_level < 3 || nslots > SCRATCH_MAX_SLOTS) return -1;
    uint64_t ttbr1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    uint64_t page_size = 1 << data->page_shift;
    uint64_t pgd_pa = ttbr1 & ~(page_size - 1);
    // the top-level table must live inside the kernel image (.bss) for the
    // image mapping below to reach it
    if (pgd_pa < data->kernel_pa || pgd_pa >= data->kernel_pa + 0x8000000) return -1;
    uint64_t pgd_va = pgd_pa + data->kimage_voffset;
    uint64_t top_shift = 12 + pxd_bits * (page_level - 1);
    // when the walk starts at level 1 (va1_bits <= 39 for 4K pages) every
    // entry of the top table is a TTBR1 kernel entry; only 4-level walks
    // (start level 0) have a user-half that TTBR1 never translates
    uint64_t half = data->va1_bits <= 39 ? 0 : (1 << (data->va1_bits - 1 - top_shift));
    uint64_t n = 1 << (data->va1_bits - top_shift);
    int nf = 0;
    for (uint64_t i = half; i < n && nf < nslots; i++) {
        if (((*(uint64_t *)(pgd_va + i * 8)) & 0x3) == 0) {
            sc->slots[nf++] = i;
        }
    }
    if (nf < nslots) return -1;
    sc->nslots = nslots;
    sc->pgd_va = pgd_va;
    sc->pgd_pa = pgd_pa;
    sc->top_shift = top_shift;
    sc->pxd_bits = pxd_bits;
    sc->page_shift = data->page_shift;
    sc->va1_bits = data->va1_bits;
    sc->window = ((sc->slots[0] << top_shift) | ~((1ull << data->va1_bits) - 1)) & 0xFFFFFFFFFFFFFFFFull;
    return 0;
}

static void scratch_activate(map_data_t *data, scratch_t *sc)
{
    uint64_t ttbr1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    uint64_t pgd_pa = ttbr1 & ~((1ull << sc->page_shift) - 1);
    sc->pgd_va = pgd_pa + data->kimage_voffset;
    // every intermediate slot re-enters the top table itself
    for (int k = 0; k < sc->nslots - 1; k++) {
        *(uint64_t *)(sc->pgd_va + sc->slots[k] * 8) = pgd_pa | SCRATCH_DESC_TABLE;
    }
    flush_tlb_all();
}

// returns the VA through which the first page of `pa` can be accessed
static uint64_t scratch_map_page(map_data_t *data, scratch_t *sc, uint64_t pa)
{
    int last = sc->nslots - 1;
    *(uint64_t *)(sc->pgd_va + sc->slots[last] * 8) = (pa & ~((1ull << sc->page_shift) - 1)) | SCRATCH_DESC_PAGE;
    flush_tlb_all();
    // the leaf slot sits k levels below the top entry
    uint64_t va = sc->window;
    for (int k = 1; k < sc->nslots; k++) {
        va += sc->slots[k] << (sc->top_shift - k * sc->pxd_bits);
    }
    return va;
}

static void scratch_unmap_page(map_data_t *data, scratch_t *sc)
{
    int last = sc->nslots - 1;
    *(uint64_t *)(sc->pgd_va + sc->slots[last] * 8) = 0;
    flush_tlb_all();
}

static void scratch_teardown(map_data_t *data, scratch_t *sc)
{
    for (int k = 0; k < sc->nslots; k++) {
        *(uint64_t *)(sc->pgd_va + sc->slots[k] * 8) = 0;
    }
    flush_tlb_all();
}

#define SCAN_CAND_MAX 16

static void scan_add_cand(uint64_t *cvals, uint64_t *ccnts, int *cn, uint64_t v)
{
    for (int i = 0; i < *cn; i++) {
        if (cvals[i] == v) {
            ccnts[i]++;
            return;
        }
    }
    if (*cn < SCAN_CAND_MAX) {
        cvals[*cn] = v;
        ccnts[*cn] = 1;
        (*cn)++;
    }
}

// scan one table page: leaf entries vote (va - oa); tables recurse
static void scan_level(map_data_t *data, scratch_t *sc, uint64_t table_pa, uint64_t base_va, uint64_t shift,
                       int depth, uint64_t *cvals, uint64_t *ccnts, int *cn)
{
    if (depth < 0 || shift < sc->page_shift) return;
    if (table_pa == sc->pgd_pa) return; // never treat the top table as a lower level
    uint64_t view = scratch_map_page(data, sc, table_pa);
    uint64_t n = 1 << (sc->page_shift - 3);
    uint64_t pxd_bits = sc->page_shift - 3;
    uint64_t child_pa[8];
    uint64_t child_va[8];
    int tn = 0;
    for (uint64_t k = 0; k < n; k++) {
        uint64_t d = *(uint64_t *)(view + k * 8);
        uint64_t bits = d & 0x3;
        if (bits == 0) continue;
        uint64_t va = base_va + (k << shift);
        if (bits == 0x1) { // leaf
            uint64_t oa = d & (((1ull << (48 - shift)) - 1) << shift);
            // skip the kernel image's own mapping: its offset differs from
            // the linear offset on kernels where the scan is relevant
            if (va - oa != data->kimage_voffset) scan_add_cand(cvals, ccnts, cn, va - oa);
        } else if (tn < 8) { // table
            child_pa[tn] = d & (((1ull << (48 - sc->page_shift)) - 1) << sc->page_shift);
            child_va[tn] = va;
            tn++;
        }
    }
    scratch_unmap_page(data, sc);
    for (int i = 0; i < tn; i++) {
        scan_level(data, sc, child_pa[i], child_va[i], shift - pxd_bits, depth - 1, cvals, ccnts, cn);
    }
}

// recover linear_voffset from the real page tables; returns 0 if the scan
// is inconclusive (caller keeps the memblock-probed value then). votes
// equal to kimage_voffset are skipped: they belong to the image's own
// mapping, whose offset differs from the linear offset on older kernels
static uint64_t scan_linear_voffset(map_data_t *data, scratch_t *sc)
{
    uint64_t cvals[SCAN_CAND_MAX];
    uint64_t ccnts[SCAN_CAND_MAX];
    int cn = 0;
    uint64_t pxd_bits = sc->page_shift - 3;
    uint64_t top_shift = sc->top_shift;
    uint64_t n_top = 1 << (data->va1_bits - top_shift);
    uint64_t high_mask = ~((1ull << data->va1_bits) - 1);
    uint64_t pgd = sc->pgd_va;
    // 39-bit style walks start at level 1: the whole top table is kernel
    // space and the linear map typically lives in its first entries, so the
    // scan must cover all of it; 4-level walks keep the user-half skipped
    uint64_t half = data->va1_bits <= 39 ? 0 : (1 << (data->va1_bits - 1 - top_shift));
    for (uint64_t i = half; i < n_top; i++) {
        // never descend into our own scratch alias entries
        int mine = 0;
        for (int k = 0; k < sc->nslots; k++) mine |= (i == sc->slots[k]);
        if (mine) continue;
        uint64_t d = *(uint64_t *)(pgd + i * 8);
        uint64_t bits = d & 0x3;
        if (bits == 0) continue;
        uint64_t base_va = ((i << top_shift) | high_mask) & 0xFFFFFFFFFFFFFFFFull;
        if (bits == 0x1) { // top-level leaf (1GB block)
            uint64_t oa = d & (((1ull << (48 - top_shift)) - 1) << top_shift);
            if (base_va - oa != data->kimage_voffset) scan_add_cand(cvals, ccnts, &cn, base_va - oa);
        } else {
            uint64_t t_pa = d & (((1ull << (48 - sc->page_shift)) - 1) << sc->page_shift);
            scan_level(data, sc, t_pa, base_va, top_shift - pxd_bits, 2, cvals, ccnts, &cn);
        }
    }
    uint64_t best = 0, best_cnt = 0;
    for (int i = 0; i < cn; i++) {
        if (ccnts[i] > best_cnt) {
            best_cnt = ccnts[i];
            best = cvals[i];
        }
    }
    return best_cnt >= 2 ? best : 0;
}

// kernels >= 6.15 (early paging rework) have no usable linear map inside the
// paging_init hook: only the kernel image and fixmap are mapped, and the
// linear map is built later by setup_arch. provide KP's own linear window
// instead: identity-map the first GBs of RAM with 1GB block entries in a
// run of consecutive free top-level slots and return the window's VA base
// to be used as linear_voffset
static uint64_t install_kp_linear(map_data_t *data, scratch_t *sc)
{
    uint64_t pxd_bits = data->page_shift - 3;
    uint64_t page_level = (data->va1_bits - 4) / pxd_bits;
    if (page_level < 2) return 0; // no block-capable top level
    // blocks are only legal from level 1 down; for 4K pages the top level is
    // level 1 exactly when va1_bits <= 39 (walk starts below level 0)
    if (data->va1_bits > 39) return 0;
    uint64_t top_shift = 12 + pxd_bits * (page_level - 1);
    uint64_t pgd = sc->pgd_va;
    // with a level-1 start (va1_bits <= 39) every top entry is kernel space;
    // skip the real linear map's low entries by scanning from index 2
    uint64_t half = data->va1_bits <= 39 ? 2 : (1 << (data->va1_bits - 1 - top_shift));
    uint64_t n_top = 1 << (data->va1_bits - top_shift);
    uint64_t high_mask = ~((1ull << data->va1_bits) - 1);

    uint64_t run = 0;
    // the identity window must start at the RAM base, not at PA 0
    uint64_t ram_base = data->kernel_pa & ~((1ull << 30) - 1);
    for (uint64_t i = half; i < n_top; i++) {
        if ((*(uint64_t *)(pgd + i * 8) & 0x3) == 0) {
            // extend the consecutive free run, capped at 4GB of coverage
            while (i + run < n_top && run < 4 && (*(uint64_t *)(pgd + (i + run) * 8) & 0x3) == 0) run++;
            if (run < 2) { // too small to be useful, keep looking
                i += run;
                run = 0;
                continue;
            }
            uint64_t base = ((i << top_shift) | high_mask) & 0xFFFFFFFFFFFFFFFFull;
            // V | 1GB block | AF | SH inner | AttrIndx 0 | EL1 RW
            for (uint64_t k = 0; k < run; k++) {
                *(uint64_t *)(pgd + (i + k) * 8) = (((ram_base >> 30) + k) << 30) | 0x701ull;
            }
            flush_tlb_all();
            // linear_voffset so that pa + lv lands inside the window run
            return base - ram_base;
        }
    }
    return 0;
}

#endif // KP_TARGET_Y73S

void __noinline _paging_init()
{
	map_data_t buf;
	map_data_t *data = &buf;
    mem_proc(data);

#ifdef MAP_DEBUG
    printk_f printk = (printk_f)(data->printk_relo);
#define map_debug(idx, val) printk(data->str_fmt_px, idx, val)
    for (int i = 0; i < sizeof(map_data_t); i += 8) {
        map_debug(i, *(uint64_t *)((uint64_t)data + i));
    }
#else
#define map_debug(idx, val)
#endif

    uint64_t page_size = 1 << data->page_shift;
    if (data->start_offset < 0 || data->start_img_size < 0 || data->extra_size < 0 ||
        data->start_size <= 0 || data->alloc_size < 0) __builtin_trap();
    /*
     * The start image is copied at destination offset zero; extra data starts
     * at start_size. Reject a stale/corrupt preset that would make those
     * destination ranges overlap. The current linker layout makes them equal,
     * but allowing a smaller image keeps the zero-filled alignment gap valid.
     */
    if ((uint64_t)data->start_img_size > (uint64_t)data->start_size) __builtin_trap();
    if ((uint64_t)data->start_offset > ~(uint64_t)0 - data->kernel_pa) __builtin_trap();
    uint64_t old_start_pa = (uint64_t)data->start_offset + data->kernel_pa;
    if ((uint64_t)data->start_img_size > ~(uint64_t)0 - (uint64_t)data->extra_size) __builtin_trap();
    uint64_t reserve_size = (uint64_t)data->start_img_size + (uint64_t)data->extra_size;
    if (!reserve_size || old_start_pa > ~(uint64_t)0 - reserve_size) __builtin_trap();

    // memblock_reserve() returns 0 on success and a negative errno on failure.
    // Do not allocate the destination if protecting the source image failed.
    if (((memblock_reserve_f)data->map_symbol.memblock_reserve_relo)(old_start_pa, reserve_size))
        __builtin_trap();

    // Check every size calculation before asking memblock to reserve memory.
    if (data->extra_size > ~(uint64_t)0 - (page_size - 1)) __builtin_trap();
    uint64_t align_extra_size = (data->extra_size + page_size - 1) & ~(page_size - 1);
    if (data->start_size > ~(uint64_t)0 - align_extra_size) __builtin_trap();
    uint64_t start_and_extra = data->start_size + align_extra_size;
    if (data->alloc_size > ~(uint64_t)0 - start_and_extra) __builtin_trap();
    uint64_t all_size = start_and_extra + (uint64_t)data->alloc_size;
    if (!all_size || all_size > ~(uint64_t)0 - (page_size - 1) ||
        (all_size & (page_size - 1))) __builtin_trap();

    // alloc
    uint64_t start_pa = map_phys_alloc(data, all_size, page_size);
    if (!start_pa || (start_pa & (page_size - 1)) || start_pa > ~(uint64_t)0 - all_size) __builtin_trap();

    // A failed NOMAP update means the destination is not in the state expected
    // by the later mapping/copy path. Stop before touching it.
    if (((memblock_mark_nomap_f)data->map_symbol.memblock_mark_nomap_relo)(start_pa, all_size))
        __builtin_trap();

    // paging_init
    uint64_t paging_init_va = data->paging_init_relo;
#ifdef KP_TARGET_Y73S
    // Y73S runs Linux 4.14 and uses the legacy paging_init path.
    *(uint32_t *)(paging_init_va) = data->paging_init_backup;
#else
    scratch_t sc;
    // The scratch/scan/identity-window paths are needed on 6.x kernels only:
    // 6.15+ builds the linear map inside paging_init() (so there is no usable
    // linear map while the hook runs) and maps kernel text read-only.  Every
    // kernel <= 5.x (4.x, 5.4, 5.10, 5.15) keeps the legacy direct paths that
    // 0.13.5 verified on device; 5.4 follows the non-GKI (legacy) rule too,
    // and 4.9/4.19 additionally hang on the scratch path regardless of the
    // restore timing (bisected on 4.9.337).  Gate on the kernel version, NOT
    // on va1_bits: 4.19/5.4 both run 39-bit VAs.  If the version is unknown
    // (0), new_era stays 0 and the legacy path is taken, so an image patched
    // by an older kptools still boots.  The stored version is the raw
    // setup_preset kernel_version bytes, which on a little-endian machine
    // read back as [_][patch][minor][major]: major = kv >> 24.
    uint32_t kv = data->kernel_version;
    uint32_t kmajor = (kv >> 24) & 0xFF;
    int new_era = kmajor > 5;
    int have_scratch = new_era && scratch_prep(data, &sc) == 0;
    if (have_scratch) {
        scratch_activate(data, &sc);
        // kernel >= 6.15 maps kernel text read-only, so restore the hooked
        // instruction through a temporary alias instead of touching its PTE
        uint64_t page_size = 1 << data->page_shift;
        uint64_t insn_page = (paging_init_va - data->kimage_voffset) & ~(page_size - 1);
        uint64_t insn_view = scratch_map_page(data, &sc, insn_page);
        *(uint32_t *)(insn_view + (paging_init_va & (page_size - 1))) = data->paging_init_backup;
        scratch_unmap_page(data, &sc);
        scratch_teardown(data, &sc);
    } else {
        *(uint32_t *)(paging_init_va) = data->paging_init_backup;
    }
#endif // KP_TARGET_Y73S
    flush_icache_all();
    ((paging_init_f)(paging_init_va))();
#ifdef KP_TARGET_Y73S
    /* The 4.14 linear map only becomes usable after paging_init()/map_mem(). */
    detect_y73s_linear_voffset(data);
#endif
    // can't write data below

#ifndef KP_TARGET_Y73S
    if (have_scratch) {
        // re-prep on the post-paging_init tables (TTBR1 may have changed)
        have_scratch = scratch_prep(data, &sc) == 0;
    }
    if (have_scratch) {
        // the linear map only exists from here on (paging_init created it);
        // re-derive linear_voffset from the real page tables if possible
        scratch_activate(data, &sc);
        uint64_t lv = scan_linear_voffset(data, &sc);
        scratch_teardown(data, &sc);
        if (!lv) {
            // no kernel linear map reachable from here: provide our own
            lv = install_kp_linear(data, &sc);
        }
        if (lv) data->linear_voffset = lv;
    }
#endif // KP_TARGET_Y73S
    // can't write data below

    // AttrIndx[2:0] encoding
    uint64_t ktext_pte = get_or_create_pte(data, data->paging_init_relo, 0, 0);
    uint64_t attrs = *(uint64_t *)ktext_pte;
    uint64_t attr_indx = attrs & 0b11100;

    // clear wxn
    // todo: restore wxn later
    uint64_t sctlr_el1 = 0;
    asm volatile("mrs %[reg], sctlr_el1" : [reg] "+r"(sctlr_el1));
    sctlr_el1 &= 0xFFFFFFFFFFF7FFFF;
    asm volatile("msr sctlr_el1, %[reg]" : : [reg] "r"(sctlr_el1));

    // move start memory
    // Validate both physical-to-virtual translations before using the ranges.
    if (old_start_pa > ~(uint64_t)0 - data->linear_voffset) __builtin_trap();
    paging_init_va = phys_to_lm(data, old_start_pa);
    if (paging_init_va > ~(uint64_t)0 - reserve_size) __builtin_trap();

    // uint64_t vm_gurad_enough = page_size << 3;
    if (start_pa > ~(uint64_t)0 - data->kimage_voffset) __builtin_trap();
    sctlr_el1 = start_pa + data->kimage_voffset;
    if (sctlr_el1 > ~(uint64_t)0 - all_size ||
        (sctlr_el1 & (page_size - 1)) || (paging_init_va & (page_size - 1)))
        __builtin_trap();

    uint64_t off;
    for (off = 0; off < all_size; off += page_size) {
        uint64_t entry = get_or_create_pte(data, sctlr_el1 + off, start_pa + off, attr_indx);
        *(uint64_t *)entry = (*(uint64_t *)entry | 0x8000000000000) & 0xFFDFFFFFFFFFFF7F;
    }
    flush_tlb_all();

    for (off = sctlr_el1; off < sctlr_el1 + all_size; off += sizeof(uint64_t))
        *(uint64_t *)off = 0;

    /* The helper handles unaligned extra offsets and any partial final word. */
    copy_map_range(sctlr_el1, paging_init_va, (uint64_t)data->start_img_size);
    copy_map_range(sctlr_el1 + data->start_size,
                   paging_init_va + data->start_img_size,
                   (uint64_t)data->extra_size);

    flush_icache_all();

    // free old start
    ((memblock_free_f)data->map_symbol.memblock_free_relo)(old_start_pa, reserve_size);

    // start
    ((start_f)sctlr_el1)(data->kimage_voffset, data->linear_voffset);
}
