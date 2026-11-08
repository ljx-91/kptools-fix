/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hotpatch.h>
#include <cache.h>
#include <common.h>
#include <ksyms.h>
#include <symbol.h>
#include <pgtable.h>
#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include <uapi/asm-generic/errno.h>

static uintptr_t table_pa_mask = 0;

static void *alias_page = 0;
static uintptr_t *alias_entry = 0;
static uintptr_t alias_pte = 0;
static bool hotpatch_early_boot = false;

void hotpatch_set_early_boot(int enabled)
{
    hotpatch_early_boot = enabled != 0;
}
KP_EXPORT_SYMBOL(hotpatch_set_early_boot);

int kfunc_def(aarch64_insn_patch_text_nosync)(void *addr, uint32_t insn) = 0;
int kfunc_def(aarch64_insn_patch_text)(void *addrs[], uint32_t insns[], int cnt) = 0;

/*
 * Text-patching backend selection, decided at runtime by kver.
 *
 * The hotpatch framework (stop_machine + the alias/aarch64_insn_patch_text_nosync
 * trick) broke boot on 4.4/4.14: the alias path feeds a vmalloc alias address to
 * the kernel's aarch64_insn_patch_text_nosync, whose patch_map() resolves it via
 * virt_to_page() and writes to a bogus physical page.  Those kernels used to boot
 * through the kernel's own aarch64_insn_patch_text(), which is what the legacy
 * backend restores below.
 *
 * Legacy (4.14 and below): prefer the kernel's aarch64_insn_patch_text() (fixmap +
 * stop_machine, the path KP used before the hotpatch migration); fall back to a
 * direct page-table write only if it cannot be resolved.  5.0+ keep the hotpatch
 * framework.
 */
static bool hotpatch_use_legacy(void)
{
    return kver < VERSION(4, 15, 0);
}

static void modify_entry_kernel(uintptr_t va, uintptr_t *entry, uintptr_t value)
{
    if (!pte_valid_cont(*entry) && !pte_valid_cont(value)) {
        *entry = value;
        flush_tlb_kernel_page(va);
        return;
    }

    uintptr_t prot = value & ~table_pa_mask;
    uintptr_t *p = (uintptr_t *)((uintptr_t)entry & ~(sizeof(entry) * CONT_PTES - 1));
    for (int i = 0; i < CONT_PTES; ++i, ++p) {
        *p = (*p & table_pa_mask) | prot;
    }

    *entry = value;
    va &= CONT_PTE_MASK;
    flush_tlb_kernel_range(va, va + CONT_PTES * page_size);
}

int hotpatch_nosync(void *addr, uint32_t value)
{
    uintptr_t tp = (uintptr_t)addr;
    if (tp & 0x3) return -EINVAL;
    if (!hotpatch_use_legacy() && kfunc(aarch64_insn_patch_text_nosync) && alias_pte) {
        // todo: fixmap
        uintptr_t phys = pgtable_phys_kernel(tp);
        if (!phys) return -EFAULT;
        *alias_entry = (alias_pte & ~table_pa_mask) | (phys & ~(page_size - 1));
        dsb(ish);
        void *alias_addr = alias_page + (tp & (page_size - 1));
        int rc = kfunc(aarch64_insn_patch_text_nosync)(alias_addr, value);
        *alias_entry = alias_pte;
        dsb(ish);
        if (!rc) return rc;
    }
    uintptr_t *entry = pgtable_entry_kernel(tp);
    if (!entry) return -EFAULT;
    uintptr_t ori_prot = *entry;
    modify_entry_kernel(tp, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    *(uint32_t *)tp = value;
    modify_entry_kernel(tp, entry, ori_prot);
    flush_icache_all();
    return 0;
}
KP_EXPORT_SYMBOL(hotpatch_nosync);

#define HOTPATCH_MAX_INSN 64

struct hotpatch_t
{
    void **addrs;
    u32 *values;
    int cnt;
    u32 original[HOTPATCH_MAX_INSN];
};

static int hotpatch_cb(void *arg)
{
    struct hotpatch_t *pp = arg;
    int ret = 0;
    int applied = 0;

    if (!pp || !pp->addrs || !pp->values || pp->cnt <= 0 ||
        pp->cnt > HOTPATCH_MAX_INSN) return -EINVAL;

    /*
     * Preflight every target before changing any instruction. stop_machine()
     * keeps the page-table view stable while this callback runs.
     */
    for (int i = 0; i < pp->cnt; ++i) {
        uintptr_t addr = (uintptr_t)pp->addrs[i];
        if ((addr & 0x3) || !pgtable_entry_kernel(addr)) return -EFAULT;
        pp->original[i] = *(volatile u32 *)addr;
    }

    for (int i = 0; i < pp->cnt; ++i) {
        ret = hotpatch_nosync(pp->addrs[i], pp->values[i]);
        if (ret) break;
        applied++;
    }

    if (!ret) return 0;

    /*
     * Roll back the prefix in reverse order. If rollback itself fails,
     * report -EUCLEAN so the hook owner retains trampoline storage.
     */
    while (applied > 0) {
        --applied;
        if (hotpatch_nosync(pp->addrs[applied], pp->original[applied]))
            return -EUCLEAN;
    }
    return ret;
}

static inline int is_interrupt_masked()
{
    unsigned long daif;
    asm volatile("mrs %0, daif" : "=r"(daif));
    return daif & 0xC0;
}

int hotpatch(void *addrs[], uint32_t values[], int cnt)
{
    struct hotpatch_t patch = {
        .addrs = addrs,
        .values = values,
        .cnt = cnt,
    };

    if (!addrs || !values || cnt <= 0 || cnt > HOTPATCH_MAX_INSN) return -EINVAL;

    if (kver < VERSION(4, 6, 0)) {
        if (kfunc(aarch64_insn_patch_text))
            return kfunc(aarch64_insn_patch_text)(addrs, values, cnt);
        return -EOPNOTSUPP;
    }

    /*
     * Do not fall back to an uncoordinated per-CPU callback. In particular,
     * the Y73S 4.14 symbol table lacks cpu_online_mask/nr_cpu_ids, so the
     * old callback's num_online_cpus() dereferenced unresolved mask state.
     * A NULL cpumask asks stop_machine() to coordinate all online CPUs.
     */
    if (!kfunc(stop_machine) || (is_interrupt_masked() && !hotpatch_early_boot))
        return -EOPNOTSUPP;
    return stop_machine(hotpatch_cb, &patch, NULL);
}
KP_EXPORT_SYMBOL(hotpatch);

static void _arch_arm64_text_patching_init(const char *name, unsigned long addr)
{
    kfunc_match(aarch64_insn_patch_text_nosync, name, addr);
    kfunc_match(aarch64_insn_patch_text, name, addr);
}

static int _hotpatch_symbol_init(void *data, const char *name, struct module *m, unsigned long addr)
{
    _arch_arm64_text_patching_init(name, addr);
    return 0;
}

void hotpatch_symbol_init()
{
#ifdef INIT_USE_KALLSYMS_LOOKUP_NAME
    _hotpatch_symbol_init(0, 0, 0, 0);
#else
    kallsyms_on_each_symbol(_hotpatch_symbol_init, 0);
#endif

    table_pa_mask = (((1ul << (48 - page_shift)) - 1) << page_shift);
}

int hotpatch_init()
{
    if (kver < VERSION(4, 6, 0)) {
        log_boot("hotpatch backend: legacy aarch64_insn_patch_text");
        return 0;
    }
    alias_page = vmalloc(page_size);
    if (alias_page) {
        alias_entry = pgtable_entry_kernel((uintptr_t)alias_page);
        if (alias_entry) alias_pte = *alias_entry;
    }
    log_boot("hotpatch backend: framework (alias_page: %llx, alias_pte: %llx)\n", alias_page, alias_pte);
    return 0;
}
