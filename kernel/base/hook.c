/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hook.h>
#include <cache.h>
#include <io.h>
#include <symbol.h>
#include <pgtable.h>
#include <hotpatch.h>
#include <kpmalloc.h>
#include <uapi/asm-generic/errno.h>
#include "hmem.h"

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
#define align_ceil(x, align) (((u64)(x) + (u64)(align) - 1) & ~((u64)(align) - 1))

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_B 0x14000000
#define INST_BC 0x54000000
#define INST_BL 0x94000000
#define INST_ADR 0x10000000
#define INST_ADRP 0x90000000
#define INST_LDR_32 0x18000000
#define INST_LDR_64 0x58000000
#define INST_LDRSW_LIT 0x98000000
#define INST_PRFM_LIT 0xD8000000
#define INST_LDR_SIMD_32 0x1C000000
#define INST_LDR_SIMD_64 0x5C000000
#define INST_LDR_SIMD_128 0x9C000000
#define INST_CBZ 0x34000000
#define INST_CBNZ 0x35000000
#define INST_TBZ 0x36000000
#define INST_TBNZ 0x37000000
#define INST_HINT 0xD503201F
#define INST_IGNORE 0x0

#define MASK_B 0xFC000000
#define MASK_BC 0xFF000010
#define MASK_BL 0xFC000000
#define MASK_ADR 0x9F000000
#define MASK_ADRP 0x9F000000
#define MASK_LDR_32 0xFF000000
#define MASK_LDR_64 0xFF000000
#define MASK_LDRSW_LIT 0xFF000000
#define MASK_PRFM_LIT 0xFF000000
#define MASK_LDR_SIMD_32 0xFF000000
#define MASK_LDR_SIMD_64 0xFF000000
#define MASK_LDR_SIMD_128 0xFF000000
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_HINT 0xFFFFF01F
#define MASK_IGNORE 0x0

static inst_mask_t masks[] = {
    MASK_B,      MASK_BC,        MASK_BL,       MASK_ADR,         MASK_ADRP,        MASK_LDR_32,
    MASK_LDR_64, MASK_LDRSW_LIT, MASK_PRFM_LIT, MASK_LDR_SIMD_32, MASK_LDR_SIMD_64, MASK_LDR_SIMD_128,
    MASK_CBZ,    MASK_CBNZ,      MASK_TBZ,      MASK_TBNZ,        MASK_IGNORE,
};
static inst_type_t types[] = {
    INST_B,      INST_BC,        INST_BL,       INST_ADR,         INST_ADRP,        INST_LDR_32,
    INST_LDR_64, INST_LDRSW_LIT, INST_PRFM_LIT, INST_LDR_SIMD_32, INST_LDR_SIMD_64, INST_LDR_SIMD_128,
    INST_CBZ,    INST_CBNZ,      INST_TBZ,      INST_TBNZ,        INST_IGNORE,
};

static int32_t relo_len[] = { 6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2 };

// static uint64_t sign_extend(uint64_t x, uint32_t len)
// {
//     char sign_bit = bit(x, len - 1);
//     unsigned long sign_mask = 0 - sign_bit;
//     x |= ((sign_mask >> len) << len);
//     return x;
// }

static int is_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (addr >= tramp_start && addr < tramp_end) {
        return 1;
    }
    return 0;
}

/*
 * ADRP always forms a 4-KiB-aligned page address, independent of the
 * kernel's configured translation granule. Reject the whole page if it
 * overlaps bytes that hook_install will overwrite: a following ADD may
 * otherwise turn an apparently safe page base into a pointer into the
 * replaced prologue.
 */
static int is_page_in_tramp(hook_t *hook, uint64_t page_addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (tramp_end < tramp_start || page_addr > (~0ULL) - 0xfffULL) return 1;
    return page_addr < tramp_end && page_addr + 0x1000ULL > tramp_start;
}

static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (!(addr >= tramp_start && addr < tramp_end)) return addr;
    uint32_t addr_inst_index = (addr - tramp_start) / 4;
    uint64_t fix_addr = hook->relo_addr;
    for (int i = 0; i < addr_inst_index; i++) {
        inst_type_t inst = hook->origin_insts[i];
        for (int j = 0; j < sizeof(relo_len) / sizeof(relo_len[0]); j++) {
            if ((inst & masks[j]) == types[j]) {
                fix_addr += relo_len[j] * 4;
                break;
            }
        }
    }
    return fix_addr;
}

#ifdef HOOK_INTO_BRANCH_FUNC

static uint64_t branch_func_addr_once(uint64_t addr)
{
    uint64_t ret = addr;
    uint32_t inst = *(uint32_t *)addr;
    if ((inst & MASK_B) == INST_B) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        ret = addr + imm64;
    } else if (inst == ARM64_BTI_C || inst == ARM64_BTI_J ||
               (inst == ARM64_BTI_JC && !hook_get_mem_from_origin(addr))) {
        ret = addr + 4;
    } else {
    }
    return ret;
}

uint64_t branch_func_addr(uint64_t addr)
{
    /* Entry thunks must be finite. Reject cycles and unreasonable chains. */
    uint64_t visited[8];
    if (is_bad_address((void *)addr) || (addr & 0x3)) return 0;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < i; j++) {
            if (visited[j] == addr) return 0;
        }
        visited[i] = addr;
        uint64_t ret = branch_func_addr_once(addr);
        if (ret == addr) return addr;
        if (is_bad_address((void *)ret) || (ret & 0x3)) return 0;
        addr = ret;
    }
    /* More than eight consecutive entry branches is treated as malformed. */
    return 0;
}

#endif

static __noinline hook_err_t relo_b(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    uint64_t imm64;
    if (type == INST_BC) {
        uint64_t imm19 = bits32(inst, 23, 5);
        imm64 = sign64_extend(imm19 << 2u, 21u);
    } else {
        uint64_t imm26 = bits32(inst, 25, 0);
        imm64 = sign64_extend(imm26 << 2u, 28u);
    }
    uint64_t addr = inst_addr + imm64;
    addr = relo_in_tramp(hook, addr);

    uint32_t idx = 0;
    if (type == INST_BC) {
        buf[idx++] = (inst & 0xFF00001F) | 0x40u; // B.<cond> #8
        buf[idx++] = 0x14000006; // B #24
    }
    buf[idx++] = 0x58000051; // LDR X17, #8
    buf[idx++] = 0x14000003; // B #12
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E; // ADR X30, .
        buf[idx++] = 0x910033DE; // ADD X30, X30, #12
        buf[idx++] = 0xD65F0220; // RET X17
    } else {
        buf[idx++] = 0xD65F0220; // RET X17
    }
    buf[idx++] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_adr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t xd = bits32(inst, 4, 0);
    uint64_t immlo = bits32(inst, 30, 29);
    uint64_t immhi = bits32(inst, 23, 5);
    uint64_t addr;

    if (type == INST_ADR) {
        addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
        /* Do not retain a pointer into text that hook_install will overwrite. */
        if (is_in_tramp(hook, addr)) return -HOOK_BAD_RELO;
    } else {
        addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & 0xFFFFFFFFFFFFF000;
        if (is_page_in_tramp(hook, addr)) return -HOOK_BAD_RELO;
    }
    buf[0] = 0x58000040u | xd; // LDR Xd, #8
    buf[1] = 0x14000003; // B #12
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ldr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t rt = bits32(inst, 4, 0);
    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM_LIT) return -HOOK_BAD_RELO;

    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW_LIT) {
        buf[0] = 0x58000060u | rt; // LDR Xt, #12
        if (type == INST_LDR_32) {
            buf[1] = 0xB9400000 | rt | (rt << 5u); // LDR Wt, [Xt]
        } else if (type == INST_LDR_64) {
            buf[1] = 0xF9400000 | rt | (rt << 5u); // LDR Xt, [Xt]
        } else {
            // LDRSW_LIT
            buf[1] = 0xB9800000 | rt | (rt << 5u); // LDRSW Xt, [Xt]
        }
        buf[2] = 0x14000004; // B #16
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        buf[0] = 0xA93F47F0; // STP X16, X17, [SP, -0x10]
        buf[1] = 0x58000091; // LDR X17, #16
        if (type == INST_PRFM_LIT) {
            buf[2] = 0xF9800220 | rt; // PRFM Rt, [X17]
        } else if (type == INST_LDR_SIMD_32) {
            buf[2] = 0xBD400220 | rt; // LDR St, [X17]
        } else if (type == INST_LDR_SIMD_64) {
            buf[2] = 0xFD400220 | rt; // LDR Dt, [X17]
        } else {
            // LDR_SIMD_128
            buf[2] = 0x3DC00220u | rt; // LDR Qt, [X17]
        }
        buf[3] = 0xF85F83F1; // LDR X17, [SP, -0x8]
        buf[4] = 0x14000004; // B #16
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_cb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u; // CB(N)Z Rt, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xD65F0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_tb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm14 = bits32(inst, 18, 5);
    uint64_t offset = sign64_extend((imm14 << 2u), 16u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u; // TB(N)Z Rt, #<imm>, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xd61f0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ignore(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static uint32_t can_b_rel(uint64_t src_addr, uint64_t dst_addr)
{
    /* A64 B uses a signed imm26 scaled by four: [-128 MiB, +128 MiB-4]. */
    int64_t delta;
    if ((src_addr & 0x3) || (dst_addr & 0x3)) return 0;
    if (dst_addr >= src_addr) {
        uint64_t diff = dst_addr - src_addr;
        return diff <= 0x07fffffcULL;
    }
    delta = -(int64_t)(src_addr - dst_addr);
    return delta >= -0x08000000LL;
}

int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr)
{
    if (can_b_rel(src_addr, dst_addr)) {
        buf[0] = 0x14000000u | (((dst_addr - src_addr) & 0x0FFFFFFFu) >> 2u); // B <label>
        buf[1] = ARM64_NOP;
        return 2;
    }
    return 0;
}
KP_EXPORT_SYMBOL(branch_relative);

int32_t branch_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xd61f0220; // BR X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
KP_EXPORT_SYMBOL(branch_absolute);

int32_t ret_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xD65F0220; // RET X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
KP_EXPORT_SYMBOL(ret_absolute);

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr)
{
    int32_t len = branch_relative(tramp_buf, src_addr, dst_addr);
    if (len) return len;
    return ret_absolute(tramp_buf, dst_addr);
}

// transit0
typedef uint64_t (*transit0_func_t)();

static void hook_chain_reap_slots_locked(void *chain, int fp)
{
    int i, count = fp ? FP_HOOK_CHAIN_NUM : HOOK_CHAIN_NUM;
    chain_item_state *states = fp ? ((fp_hook_chain_t *)chain)->states : ((hook_chain_t *)chain)->states;
    void **before_owners = fp ? ((fp_hook_chain_t *)chain)->before_owners : ((hook_chain_t *)chain)->before_owners;
    void **after_owners = fp ? ((fp_hook_chain_t *)chain)->after_owners : ((hook_chain_t *)chain)->after_owners;
    void **befores = fp ? ((fp_hook_chain_t *)chain)->befores : ((hook_chain_t *)chain)->befores;
    void **afters = fp ? ((fp_hook_chain_t *)chain)->afters : ((hook_chain_t *)chain)->afters;
    void **udata = fp ? ((fp_hook_chain_t *)chain)->udata : ((hook_chain_t *)chain)->udata;
    unsigned int readers = fp ?
        __atomic_load_n(&((fp_hook_chain_t *)chain)->active_readers, __ATOMIC_SEQ_CST) :
        __atomic_load_n(&((hook_chain_t *)chain)->active_readers, __ATOMIC_SEQ_CST);
    if (readers)
        return;
    for (i = 0; i < count; i++) {
        if (__atomic_load_n(&states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_RETIRED)
            continue;
        kp_hook_owner_unregister(before_owners[i]);
        kp_hook_owner_unregister(after_owners[i]);
        before_owners[i] = after_owners[i] = NULL;
        befores[i] = afters[i] = udata[i] = NULL;
        __atomic_store_n(&states[i], CHAIN_ITEM_STATE_EMPTY, __ATOMIC_SEQ_CST);
    }
}


static inline void hook_chain_reader_enter(void *chain, int fp)
{
    unsigned long flags = hook_engine_lock();
    if (fp)
        __atomic_add_fetch(&((fp_hook_chain_t *)chain)->active_readers, 1, __ATOMIC_SEQ_CST);
    else
        __atomic_add_fetch(&((hook_chain_t *)chain)->active_readers, 1, __ATOMIC_SEQ_CST);
    hook_engine_unlock(flags);
}

static inline void hook_chain_reader_exit(void *chain, int fp)
{
    unsigned long flags = hook_engine_lock();
    if (fp)
        __atomic_sub_fetch(&((fp_hook_chain_t *)chain)->active_readers, 1, __ATOMIC_SEQ_CST);
    else
        __atomic_sub_fetch(&((hook_chain_t *)chain)->active_readers, 1, __ATOMIC_SEQ_CST);
    hook_chain_reap_slots_locked(chain, fp);
    hook_engine_unlock(flags);
}

static void hook_chain_pin_callbacks(void *chain, int fp,
                                      int *before_refs, int *after_refs,
                                      int *before_allowed, int *after_allowed)
{
    int i, count = fp ? FP_HOOK_CHAIN_NUM : HOOK_CHAIN_NUM;
    chain_item_state *states = fp ? ((fp_hook_chain_t *)chain)->states : ((hook_chain_t *)chain)->states;
    void **before_owners = fp ? ((fp_hook_chain_t *)chain)->before_owners : ((hook_chain_t *)chain)->before_owners;
    void **after_owners = fp ? ((fp_hook_chain_t *)chain)->after_owners : ((hook_chain_t *)chain)->after_owners;
    for (i = 0; i < count; i++) {
        before_refs[i] = after_refs[i] = 0;
        before_allowed[i] = after_allowed[i] = 0;
        if (__atomic_load_n(&states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY)
            continue;
        if (fp ? ((fp_hook_chain_t *)chain)->befores[i] != NULL :
                 ((hook_chain_t *)chain)->befores[i] != NULL) {
            before_refs[i] = kp_hook_owner_call_get(before_owners[i]);
            before_allowed[i] = before_refs[i] >= 0;
        }
        if (fp ? ((fp_hook_chain_t *)chain)->afters[i] != NULL :
                 ((hook_chain_t *)chain)->afters[i] != NULL) {
            after_refs[i] = kp_hook_owner_call_get(after_owners[i]);
            after_allowed[i] = after_refs[i] >= 0;
        }
    }
}

static void hook_chain_unpin_callbacks(void *chain, int fp, int *before_refs, int *after_refs)
{
    int i, count = fp ? FP_HOOK_CHAIN_NUM : HOOK_CHAIN_NUM;
    void **before_owners = fp ? ((fp_hook_chain_t *)chain)->before_owners : ((hook_chain_t *)chain)->before_owners;
    void **after_owners = fp ? ((fp_hook_chain_t *)chain)->after_owners : ((hook_chain_t *)chain)->after_owners;
    for (i = 0; i < count; i++) {
        if (before_refs[i] > 0) kp_hook_owner_call_put(before_owners[i]);
        if (after_refs[i] > 0) kp_hook_owner_call_put(after_owners[i]);
    }
}

static inline void hook_invoke_callback(void *func, void *fargs, void *udata, int allowed)
{
    if (func && allowed)
        ((void (*)(void *, void *))func)(fargs, udata);
}

#define current_inline_hook_chain() ({ \
    uint64_t chain_va; \
    asm volatile("mov %0, x16" : "=r"(chain_va)); \
    (hook_chain_t *)chain_va; \
})

uint64_t __attribute__((section(".transit0.text"))) __attribute__((__noinline__)) _transit0()
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 0);
    int before_refs[HOOK_CHAIN_NUM] = {0};
    int after_refs[HOOK_CHAIN_NUM] = {0};
    int before_allowed[HOOK_CHAIN_NUM] = {0};
    int after_allowed[HOOK_CHAIN_NUM] = {0};
    hook_chain_pin_callbacks(hook_chain, 0, before_refs, after_refs,
                             before_allowed, after_allowed);
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func();
    }
    for (int32_t i = HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_unpin_callbacks(hook_chain, 0, before_refs, after_refs);
    hook_chain_reader_exit(hook_chain, 0);
    return fargs.ret;
}
#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit0_end();
#endif

// transit4
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".transit4.text"))) __attribute__((__noinline__))
_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 0);
    int before_refs[HOOK_CHAIN_NUM] = {0};
    int after_refs[HOOK_CHAIN_NUM] = {0};
    int before_allowed[HOOK_CHAIN_NUM] = {0};
    int after_allowed[HOOK_CHAIN_NUM] = {0};
    hook_chain_pin_callbacks(hook_chain, 0, before_refs, after_refs,
                             before_allowed, after_allowed);
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_unpin_callbacks(hook_chain, 0, before_refs, after_refs);
    hook_chain_reader_exit(hook_chain, 0);
    return fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit4_end();
#endif

// transit8:
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".transit8.text"))) __attribute__((__noinline__))
_transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
          uint64_t arg7)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 0);
    int before_refs[HOOK_CHAIN_NUM] = {0};
    int after_refs[HOOK_CHAIN_NUM] = {0};
    int before_allowed[HOOK_CHAIN_NUM] = {0};
    int after_allowed[HOOK_CHAIN_NUM] = {0};
    hook_chain_pin_callbacks(hook_chain, 0, before_refs, after_refs,
                             before_allowed, after_allowed);
    hook_fargs8_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.relo_addr;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (int32_t i = HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_unpin_callbacks(hook_chain, 0, before_refs, after_refs);
    hook_chain_reader_exit(hook_chain, 0);
    return fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit8_end();
#endif

// transit12:
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".transit12.text"))) __attribute__((__noinline__))
_transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
           uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 0);
    int before_refs[HOOK_CHAIN_NUM] = {0};
    int after_refs[HOOK_CHAIN_NUM] = {0};
    int before_allowed[HOOK_CHAIN_NUM] = {0};
    int after_allowed[HOOK_CHAIN_NUM] = {0};
    hook_chain_pin_callbacks(hook_chain, 0, before_refs, after_refs,
                             before_allowed, after_allowed);
    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_unpin_callbacks(hook_chain, 0, before_refs, after_refs);
    hook_chain_reader_exit(hook_chain, 0);
    return fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit12_end();
#endif

static __noinline hook_err_t relocate_inst(hook_t *hook, uint64_t inst_addr, uint32_t inst)
{
    hook_err_t rc = HOOK_NO_ERR;
    inst_type_t it = INST_IGNORE;
    int len = 1;

    for (int j = 0; j < sizeof(relo_len) / sizeof(relo_len[0]); j++) {
        if ((inst & masks[j]) == types[j]) {
            it = types[j];
            len = relo_len[j];
            break;
        }
    }

    switch (it) {
    case INST_B:
    case INST_BC:
    case INST_BL:
        rc = relo_b(hook, inst_addr, inst, it);
        break;
    case INST_ADR:
    case INST_ADRP:
        rc = relo_adr(hook, inst_addr, inst, it);
        break;
    case INST_LDR_32:
    case INST_LDR_64:
    case INST_LDRSW_LIT:
    case INST_PRFM_LIT:
    case INST_LDR_SIMD_32:
    case INST_LDR_SIMD_64:
    case INST_LDR_SIMD_128:
        rc = relo_ldr(hook, inst_addr, inst, it);
        break;
    case INST_CBZ:
    case INST_CBNZ:
        rc = relo_cb(hook, inst_addr, inst, it);
        break;
    case INST_TBZ:
    case INST_TBNZ:
        rc = relo_tb(hook, inst_addr, inst, it);
        break;
    case INST_IGNORE:
    default:
        rc = relo_ignore(hook, inst_addr, inst, it);
        break;
    }

    hook->relo_insts_num += len;

    return rc;
}

hook_err_t hook_prepare(hook_t *hook)
{
    if (is_bad_address((void *)hook->func_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->origin_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->replace_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->relo_addr)) return -HOOK_BAD_ADDRESS;

    // backup origin instruction
    for (int i = 0; i < TRAMPOLINE_MAX_NUM; i++) {
        hook->origin_insts[i] = *((uint32_t *)hook->origin_addr + i);
    }
    // trampline to replace_addr
    if (hook->origin_insts[0] == ARM64_PACIASP || hook->origin_insts[0] == ARM64_PACIBSP) {
        hook->tramp_insts_num = branch_absolute(&hook->tramp_insts[1], hook->replace_addr);
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num++;
    } else {
        hook->tramp_insts_num = branch_absolute(hook->tramp_insts, hook->replace_addr);
    }

    // relocate
    for (int i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++) {
        hook->relo_insts[i] = ARM64_NOP;
    }

    for (int i = 0; i < hook->tramp_insts_num; i++) {
        uint64_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
            return -HOOK_BAD_RELO;
        }
    }

    // jump back
    uint64_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uint64_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);
    return HOOK_NO_ERR;
}
KP_EXPORT_SYMBOL(hook_prepare);

int hook_install(hook_t *hook)
{
    void *addrs[TRAMPOLINE_MAX_NUM];
    if (!hook || hook->tramp_insts_num <= 0 ||
        hook->tramp_insts_num > TRAMPOLINE_MAX_NUM) return -1;
    for (int32_t i = 0; i < hook->tramp_insts_num; ++i) {
        addrs[i] = (uint32_t *)hook->origin_addr + i;
    }
    /* Trampoline bytes are generated in executable memory before the branch
     * is installed. Publish them to every CPU's I-cache first. */
    flush_icache_all();
    return hotpatch(addrs, hook->tramp_insts, hook->tramp_insts_num);
}
KP_EXPORT_SYMBOL(hook_install);

int hook_uninstall(hook_t *hook)
{
    void *addrs[TRAMPOLINE_MAX_NUM];
    if (!hook || hook->tramp_insts_num <= 0 ||
        hook->tramp_insts_num > TRAMPOLINE_MAX_NUM) return -1;
    for (int32_t i = 0; i < hook->tramp_insts_num; ++i) {
        addrs[i] = (uint32_t *)hook->origin_addr + i;
    }
    return hotpatch(addrs, hook->origin_insts, hook->tramp_insts_num);
}
KP_EXPORT_SYMBOL(hook_uninstall);

hook_err_t hook(void *func, void *replace, void **backup)
{
    hook_err_t err;
    uint64_t origin;
    hook_t *hook;
    void *owner = NULL;
    unsigned long flags;
    int owner_rc, patch_rc;

    if (!func || !replace || !backup) return -HOOK_BAD_ADDRESS;
    *backup = NULL;
    origin = branch_func_addr((uintptr_t)func);
    if (is_bad_address((void *)origin)) return -HOOK_BAD_ADDRESS;
    owner_rc = kp_hook_owner_register((unsigned long)replace, &owner);
    if (owner_rc < 0) return -EBUSY;
    if (owner) {
        kp_hook_owner_unregister(owner);
        return -EOPNOTSUPP;
    }

    flags = hook_engine_lock();
    hook = (hook_t *)hook_mem_zalloc(origin, INLINE);
    hook_engine_unlock(flags);
    if (!hook) return -HOOK_NO_MEM;

    hook->func_addr = (uint64_t)func;
    hook->origin_addr = origin;
    hook->replace_addr = (uint64_t)replace;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    err = hook_prepare(hook);
    if (err) goto fail;

    /* hotpatch() may stop other CPUs on KPIMG; never hold the registry
     * spinlock across that rendezvous. The constructing slot reserves origin. */
    patch_rc = hook_install(hook);
    if (patch_rc) {
        if (patch_rc == -EUCLEAN) {
            hook_mem_publish(hook);
            return -HOOK_PATCH_UNCERTAIN;
        }
        err = -HOOK_PATCH_FAILED;
        goto fail;
    }
    hook_mem_publish(hook);
    *backup = (void *)hook->relo_addr;
    return HOOK_NO_ERR;
fail:
    hook_mem_free(hook);
    return err;
}
KP_EXPORT_SYMBOL(hook);

void unhook(void *func)
{
    uint64_t origin;
    hook_t *hook;
    unsigned long flags;
    int rc;

    if (is_bad_address(func)) return;
    origin = branch_func_addr((uint64_t)func);
    if (is_bad_address((void *)origin)) return;
    flags = hook_engine_lock();
    hook = hook_get_mem_from_origin_type(origin, INLINE);
    if (!hook || hook_mem_claim_retire(hook)) {
        hook_engine_unlock(flags);
        return;
    }
    hook_engine_unlock(flags);

    rc = hook_uninstall(hook);
    if (!rc)
        hook_mem_retire(hook);
    else
        hook_mem_cancel_retire(hook);
}
KP_EXPORT_SYMBOL(unhook);

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start;
    hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);

    if (argno < 0 || argno > 12)
        return -HOOK_BAD_ADDRESS;
    if (argno == 0)
        transit_start = (uint64_t)_transit0;
    else if (argno <= 4)
        transit_start = (uint64_t)_transit4;
    else if (argno <= 8)
        transit_start = (uint64_t)_transit8;
    else
        transit_start = (uint64_t)_transit12;

    /* Keep the chain pointer in x16, then branch to the resident transit
     * routine. Copying C code into the chain buffer would leave PC-relative
     * calls to helper functions with invalid relocated targets. */
    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000070; /* LDR X16, #12 */
    transit[2] = 0x14000004; /* B #16 */
    transit[3] = ARM64_NOP;
    transit[4] = (uint64_t)chain;
    transit[5] = (uint64_t)chain >> 32;
    branch_absolute(&transit[6], transit_start);
    return HOOK_NO_ERR;
}
#else
static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno);
#endif

static hook_err_t hook_chain_add_locked(hook_chain_t *chain, void *before, void *after, void *udata)
{
    void *before_owner = NULL, *after_owner = NULL;
    int rc, i;

    if (!chain || (!before && !after))
        return -HOOK_BAD_ADDRESS;
    if (before) {
        rc = kp_hook_owner_register((unsigned long)before, &before_owner);
        if (rc < 0) return -EBUSY;
    }
    if (after) {
        rc = kp_hook_owner_register((unsigned long)after, &after_owner);
        if (rc < 0) {
            kp_hook_owner_unregister(before_owner);
            return -EBUSY;
        }
    }

    for (i = 0; i < HOOK_CHAIN_NUM; i++) {
        int state = __atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST);
        if (state != CHAIN_ITEM_STATE_EMPTY &&
            ((before && chain->befores[i] == before) ||
             (after && chain->afters[i] == after))) {
            kp_hook_owner_unregister(before_owner);
            kp_hook_owner_unregister(after_owner);
            return -HOOK_DUPLICATED;
        }
    }
    for (i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_EMPTY)
            continue;
        chain->udata[i] = udata;
        chain->befores[i] = before;
        chain->afters[i] = after;
        chain->before_owners[i] = before_owner;
        chain->after_owners[i] = after_owner;
        if (i + 1 > chain->chain_items_max)
            chain->chain_items_max = i + 1;
        __atomic_store_n(&chain->states[i], CHAIN_ITEM_STATE_READY, __ATOMIC_SEQ_CST);
        return HOOK_NO_ERR;
    }
    kp_hook_owner_unregister(before_owner);
    kp_hook_owner_unregister(after_owner);
    return -HOOK_CHAIN_FULL;
}

hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata)
{
    unsigned long flags = hook_engine_lock();
    hook_err_t rc = hook_chain_add_locked(chain, before, after, udata);
    hook_engine_unlock(flags);
    return rc;
}
KP_EXPORT_SYMBOL(hook_chain_add);

static void hook_chain_remove_locked(hook_chain_t *chain, void *before, void *after)
{
    int i;
    for (i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY)
            continue;
        if ((before && chain->befores[i] == before) ||
            (after && chain->afters[i] == after)) {
            __atomic_store_n(&chain->states[i], CHAIN_ITEM_STATE_RETIRED, __ATOMIC_SEQ_CST);
            break;
        }
    }
}

int hook_chain_remove(hook_chain_t *chain, void *before, void *after)
{
    unsigned long flags;
    int busy;
    if (!chain) return -EINVAL;
    flags = hook_engine_lock();
    hook_chain_remove_locked(chain, before, after);
    busy = __atomic_load_n(&chain->active_readers, __ATOMIC_SEQ_CST) != 0;
    hook_chain_reap_slots_locked(chain, 0);
    hook_engine_unlock(flags);
    return busy ? -EBUSY : 0;
}
KP_EXPORT_SYMBOL(hook_chain_remove);

// todo: lock
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata)
{
    uint64_t faddr, origin;
    hook_chain_t *chain;
    hook_t *hook;
    hook_err_t err;
    unsigned long flags;
    int patch_rc;

    if (is_bad_address(func) || (!before && !after)) return -HOOK_BAD_ADDRESS;
    faddr = (uint64_t)func;
    origin = branch_func_addr(faddr);
    if (is_bad_address((void *)origin)) return -HOOK_BAD_ADDRESS;

    flags = hook_engine_lock();
    chain = (hook_chain_t *)hook_get_mem_from_origin_type(origin, INLINE_CHAIN);
    if (chain) {
        err = hook_chain_add_locked(chain, before, after, udata);
        hook_engine_unlock(flags);
        return err;
    }
    chain = (hook_chain_t *)hook_mem_zalloc(origin, INLINE_CHAIN);
    hook_engine_unlock(flags);
    if (!chain) return -HOOK_NO_MEM;

    hook = &chain->hook;
    hook->func_addr = faddr;
    hook->origin_addr = origin;
    hook->replace_addr = (uint64_t)chain->transit;
    hook->relo_addr = (uint64_t)hook->relo_insts;

    err = hook_prepare(hook);
    if (err) goto fail;
    err = hook_chain_prepare(chain->transit, argno);
    if (err) goto fail;

    flags = hook_engine_lock();
    err = hook_chain_add_locked(chain, before, after, udata);
    hook_engine_unlock(flags);
    if (err) goto fail;

    /* Do not hold hook_engine_lock across KPIMG stop_machine patching. */
    patch_rc = hook_install(hook);
    if (patch_rc) {
        if (patch_rc == -EUCLEAN) {
            hook_mem_publish(chain);
            return -HOOK_PATCH_UNCERTAIN;
        }
        flags = hook_engine_lock();
        hook_chain_remove_locked(chain, before, after);
        hook_chain_reap_slots_locked(chain, 0);
        hook_engine_unlock(flags);
        err = -HOOK_PATCH_FAILED;
        goto fail;
    }
    hook_mem_publish(chain);
    return HOOK_NO_ERR;

fail:
    hook_mem_free(chain);
    return err;
}
KP_EXPORT_SYMBOL(hook_wrap);

int hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    uint64_t origin;
    hook_chain_t *chain;
    unsigned long flags;
    int i, rc, busy;

    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    origin = branch_func_addr((uint64_t)func);
    if (is_bad_address((void *)origin)) return -HOOK_BAD_ADDRESS;

    flags = hook_engine_lock();
    chain = hook_get_mem_from_origin_type(origin, INLINE_CHAIN);
    if (!chain) {
        hook_engine_unlock(flags);
        return -ENOENT;
    }
    hook_chain_remove_locked(chain, before, after);
    busy = __atomic_load_n(&chain->active_readers, __ATOMIC_SEQ_CST) != 0;
    hook_chain_reap_slots_locked(chain, 0);
    if (busy) {
        hook_engine_unlock(flags);
        return -EBUSY;
    }
    if (!remove) {
        hook_engine_unlock(flags);
        return 0;
    }
    for (i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_EMPTY) {
            hook_engine_unlock(flags);
            return 0;
        }
    }
    rc = hook_mem_claim_retire(chain);
    hook_engine_unlock(flags);
    if (rc)
        return rc;

    /* The memory-registry retiring state blocks a new wrap while patching. */
    rc = hook_uninstall(&chain->hook);
    if (!rc)
        hook_mem_retire(chain);
    else
        hook_mem_cancel_retire(chain);
    return rc;
}
KP_EXPORT_SYMBOL(hook_unwrap_remove);
