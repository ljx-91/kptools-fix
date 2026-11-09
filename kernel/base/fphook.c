/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hook.h>
#include <cache.h>
#include <symbol.h>
#include <pgtable.h>
#include <hotpatch.h>
#include <uapi/asm-generic/errno.h>
#include "hmem.h"

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

static void hook_chain_reap_slots(void *chain, int fp)
{
    unsigned long flags = hook_engine_lock();
    hook_chain_reap_slots_locked(chain, fp);
    hook_engine_unlock(flags);
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

#define current_fp_hook_chain() ({ \
    uint64_t chain_va; \
    asm volatile("mov %0, x16" : "=r"(chain_va)); \
    (fp_hook_chain_t *)chain_va; \
})

uint64_t __attribute__((section(".fp.transit0.text"))) __attribute__((__noinline__)) _fp_transit0()
{
    fp_hook_chain_t *hook_chain = current_fp_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 1);
    int before_refs[FP_HOOK_CHAIN_NUM] = {0};
    int after_refs[FP_HOOK_CHAIN_NUM] = {0};
    int before_allowed[FP_HOOK_CHAIN_NUM] = {0};
    int after_allowed[FP_HOOK_CHAIN_NUM] = {0};
    hook_chain_pin_callbacks(hook_chain, 1, before_refs, after_refs,
                             before_allowed, after_allowed);
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func();
    }
    for (int32_t i = FP_HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_unpin_callbacks(hook_chain, 1, before_refs, after_refs);
    hook_chain_reader_exit(hook_chain, 1);
    return fargs.ret;
}
extern void _fp_transit0_end();

// transit4
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit4.text"))) __attribute__((__noinline__))
_fp_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    fp_hook_chain_t *hook_chain = current_fp_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 1);
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = FP_HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_reader_exit(hook_chain, 1);
    return fargs.ret;
}

extern void _fp_transit4_end();

// transit8:
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit8.text"))) __attribute__((__noinline__))
_fp_transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
             uint64_t arg7)
{
    fp_hook_chain_t *hook_chain = current_fp_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 1);
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
    for (int32_t i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.origin_fp;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (int32_t i = FP_HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_reader_exit(hook_chain, 1);
    return fargs.ret;
}

extern void _fp_transit8_end();

// transit12:
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit12.text"))) __attribute__((__noinline__))
_fp_transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
              uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    fp_hook_chain_t *hook_chain = current_fp_hook_chain();
    if (!hook_chain) return 0;
    hook_chain_reader_enter(hook_chain, 1);
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
    for (int32_t i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->befores[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], before_allowed[i]);
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = FP_HOOK_CHAIN_NUM - 1; i >= 0; i--) {
        if (__atomic_load_n(&hook_chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->afters[i];
        hook_invoke_callback(func, &fargs, hook_chain->udata[i], after_allowed[i]);
    }
    hook_chain_reader_exit(hook_chain, 1);
    return fargs.ret;
}

extern void _fp_transit12_end();

static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start;
    fp_hook_chain_t *chain = local_container_of(transit, fp_hook_chain_t, transit);

    if (argno < 0 || argno > 12)
        return -HOOK_BAD_ADDRESS;
    if (argno == 0)
        transit_start = (uint64_t)_fp_transit0;
    else if (argno <= 4)
        transit_start = (uint64_t)_fp_transit4;
    else if (argno <= 8)
        transit_start = (uint64_t)_fp_transit8;
    else
        transit_start = (uint64_t)_fp_transit12;

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

static int fp_hook_locked(uintptr_t fp_addr, void *replace, void **backup)
{
    void *addrs[2];
    uint32_t values[2];
    uintptr_t original;
    if (!backup || is_bad_address((void *)fp_addr) || (fp_addr & 7) || !replace)
        return -EINVAL;
    addrs[0] = (void *)fp_addr;
    addrs[1] = (void *)(fp_addr + 4);
    values[0] = (uint32_t)(uintptr_t)replace;
    values[1] = (uint32_t)((uintptr_t)replace >> 32);
    original = *(volatile uintptr_t *)fp_addr;
    *backup = (void *)original;
    return hotpatch(addrs, values, 2);
}

int fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    void *owner = NULL;
    unsigned long flags;
    int rc;
    int owner_rc;
    if (!backup || !replace) return -EINVAL;
    owner_rc = kp_hook_owner_register((unsigned long)replace, &owner);
    if (owner_rc < 0) return -EBUSY;
    if (owner) {
        kp_hook_owner_unregister(owner);
        return -EOPNOTSUPP;
    }
    flags = hook_engine_lock();
    rc = fp_hook_locked(fp_addr, replace, backup);
    hook_engine_unlock(flags);
    return rc;
}
KP_EXPORT_SYMBOL(fp_hook);

static int fp_unhook_locked(uintptr_t fp_addr, void *backup)
{
    void *addrs[2];
    uint32_t values[2];
    if (is_bad_address((void *)fp_addr) || (fp_addr & 7) || !backup)
        return -EINVAL;
    addrs[0] = (void *)fp_addr;
    addrs[1] = (void *)(fp_addr + 4);
    values[0] = (uint32_t)(uintptr_t)backup;
    values[1] = (uint32_t)((uintptr_t)backup >> 32);
    return hotpatch(addrs, values, 2);
}

int fp_unhook(uintptr_t fp_addr, void *backup)
{
    unsigned long flags = hook_engine_lock();
    int rc = fp_unhook_locked(fp_addr, backup);
    hook_engine_unlock(flags);
    return rc;
}
KP_EXPORT_SYMBOL(fp_unhook);

static hook_err_t fp_chain_add_locked(fp_hook_chain_t *chain, void *before, void *after, void *udata)
{
    void *before_owner = NULL, *after_owner = NULL;
    int rc, i;
    if (!chain || (!before && !after)) return -HOOK_BAD_ADDRESS;
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
    for (i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        int state = __atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST);
        if (state != CHAIN_ITEM_STATE_EMPTY &&
            ((before && chain->befores[i] == before) ||
             (after && chain->afters[i] == after))) {
            kp_hook_owner_unregister(before_owner);
            kp_hook_owner_unregister(after_owner);
            return -HOOK_DUPLICATED;
        }
    }
    for (i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_EMPTY)
            continue;
        chain->udata[i] = udata;
        chain->befores[i] = before;
        chain->afters[i] = after;
        chain->before_owners[i] = before_owner;
        chain->after_owners[i] = after_owner;
        if (i + 1 > chain->chain_items_max) chain->chain_items_max = i + 1;
        __atomic_store_n(&chain->states[i], CHAIN_ITEM_STATE_READY, __ATOMIC_SEQ_CST);
        return HOOK_NO_ERR;
    }
    kp_hook_owner_unregister(before_owner);
    kp_hook_owner_unregister(after_owner);
    return -HOOK_CHAIN_FULL;
}

static void fp_chain_remove_locked(fp_hook_chain_t *chain, void *before, void *after)
{
    int i;
    for (i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_READY)
            continue;
        if ((before && chain->befores[i] == before) ||
            (after && chain->afters[i] == after)) {
            __atomic_store_n(&chain->states[i], CHAIN_ITEM_STATE_RETIRED, __ATOMIC_SEQ_CST);
            break;
        }
    }
}

hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata)
{
    fp_hook_chain_t *chain;
    unsigned long flags;
    hook_err_t err;
    int patch_rc;

    if (is_bad_address((void *)fp_addr) || (fp_addr & 7) || (!before && !after))
        return -HOOK_BAD_ADDRESS;
    flags = hook_engine_lock();
    chain = hook_get_mem_from_origin_type(fp_addr, FUNCTION_POINTER_CHAIN);
    if (chain) {
        err = fp_chain_add_locked(chain, before, after, udata);
        hook_engine_unlock(flags);
        return err;
    }
    chain = (fp_hook_chain_t *)hook_mem_zalloc(fp_addr, FUNCTION_POINTER_CHAIN);
    if (!chain) {
        hook_engine_unlock(flags);
        return -HOOK_NO_MEM;
    }
    chain->hook.fp_addr = fp_addr;
    chain->hook.replace_addr = (uint64_t)chain->transit;
    err = hook_chain_prepare(chain->transit, argno);
    if (err) goto fail;
    flush_icache_all();
    /* Snapshot and patch are serialized against all KP hook-manager writers.
     * A foreign writer that bypasses this manager remains outside this lock. */
    patch_rc = fp_hook_locked(chain->hook.fp_addr, (void *)chain->hook.replace_addr,
                              (void **)&chain->hook.origin_fp);
    if (patch_rc) {
        if (patch_rc == -EUCLEAN) {
            hook_mem_publish(chain);
            hook_engine_unlock(flags);
            return -HOOK_PATCH_UNCERTAIN;
        }
        err = -HOOK_PATCH_FAILED;
        goto fail;
    }
    err = fp_chain_add_locked(chain, before, after, udata);
    if (err) {
        int restore_rc = fp_unhook_locked(chain->hook.fp_addr, (void *)chain->hook.origin_fp);
        if (restore_rc) {
            hook_mem_publish(chain);
            hook_engine_unlock(flags);
            return -HOOK_PATCH_UNCERTAIN;
        }
        goto fail;
    }
    hook_mem_publish(chain);
    hook_engine_unlock(flags);
    return HOOK_NO_ERR;
fail:
    hook_mem_free(chain);
    hook_engine_unlock(flags);
    return err;
}
KP_EXPORT_SYMBOL(fp_hook_wrap);

void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after)
{
    fp_hook_chain_t *chain;
    unsigned long flags;
    int i, rc;

    if (is_bad_address((void *)fp_addr) || (fp_addr & 7)) return;
    chain = hook_get_mem_from_origin_type(fp_addr, FUNCTION_POINTER_CHAIN);
    if (!chain) return;
    flags = hook_engine_lock();
    fp_chain_remove_locked(chain, before, after);
    hook_engine_unlock(flags);
    hook_chain_reap_slots(chain, 1);

    flags = hook_engine_lock();
if (hook_get_mem_from_origin_type(fp_addr, FUNCTION_POINTER_CHAIN) != chain) {
        hook_engine_unlock(flags);
        return;
    }
    for (i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_SEQ_CST) != CHAIN_ITEM_STATE_EMPTY) {
            hook_engine_unlock(flags);
            return;
        }
    }
    rc = fp_unhook_locked(chain->hook.fp_addr, (void *)chain->hook.origin_fp);
    if (!rc)
        hook_mem_retire(chain);
    hook_engine_unlock(flags);
    if (rc)
        logkv("Unwrap func pointer: %llx restore failed: %d; retaining chain memory\\n",
              fp_addr, rc);
}
KP_EXPORT_SYMBOL(fp_hook_unwrap);
