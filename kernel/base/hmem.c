/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "hook.h"

#include <stdint.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>
#include <linux/spinlock.h>
#include <kp_spinlock.h>
#include <kpmalloc.h>

static uint64_t mem_region_start = 0;
static uint64_t mem_region_end = 0;
static DEFINE_SPINLOCK(hook_mem_lock);
static DEFINE_SPINLOCK(hook_engine_spinlock);
static bool hook_locks_ready;

unsigned long hook_engine_lock(void) { return kp_private_spin_lock(&hook_engine_spinlock); }
void hook_engine_unlock(unsigned long flags) { kp_private_spin_unlock(&hook_engine_spinlock, flags); }

typedef struct
{
    int using;
    enum hook_type type;
    uintptr_t addr;
    void *exec_relo;
    void *exec_transit;
    // must align 8
    union
    {
        hook_t inl;
        hook_chain_t inl_chain;
        fp_hook_chain_t fp_chain;
    } chain __attribute__((aligned(8)));
} hook_mem_warp_t __attribute__((aligned(16)));

int hook_mem_add(uint64_t start, int32_t size)
{
    uint64_t end;
    if (!start || size <= 0 || (start & 0xf) ||
        (uint64_t)size > (~0ULL - start) ||
        ((uint64_t)size / sizeof(hook_mem_warp_t)) == 0)
        return -EINVAL;
    if (hook_locks_ready)
        return -EBUSY;
    end = start + (uint64_t)size;
    hook_locks_ready = true;
    for (uint64_t i = start; i <= end - sizeof(uint64_t); i += sizeof(uint64_t))
        *(uint64_t *)i = 0;
    mem_region_start = start;
    mem_region_end = end;
    return 0;
}

void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type)
{
    uint64_t start, end;
    if (!hook_locks_ready || !origin_addr ||
        (type != INLINE && type != INLINE_CHAIN && type != FUNCTION_POINTER_CHAIN))
        return 0;
    unsigned long flags = kp_private_spin_lock(&hook_mem_lock);
    start = mem_region_start;
    end = mem_region_end;
    for (uint64_t addr = start; addr < end && sizeof(hook_mem_warp_t) <= end - addr;
         addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        if (wrap->using == 1 || wrap->using == 3 || wrap->using == 4 || wrap->using == 5) {
            if (wrap->addr == origin_addr) {
                kp_private_spin_unlock(&hook_mem_lock, flags);
                return 0;
            }
            continue;
        }
        if (wrap->using == 2)
            continue;
        wrap->using = 3;
        wrap->addr = origin_addr;
        wrap->type = type;
        kp_private_spin_unlock(&hook_mem_lock, flags);
        memset(&wrap->chain, 0, sizeof(wrap->chain));
        if (((uintptr_t)&wrap->chain) & 0x7) {
            flags = kp_private_spin_lock(&hook_mem_lock);
            wrap->using = 0;
            kp_private_spin_unlock(&hook_mem_lock, flags);
            return 0;
        }
        return &wrap->chain;
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
    return 0;
}

void hook_mem_free(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    void *exec_relo = NULL;
    void *exec_transit = NULL;
    int relo_rc = 0, transit_rc = 0;

    if (!hook_mem || !hook_locks_ready) return;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 3) {
        exec_relo = warp->exec_relo;
        exec_transit = warp->exec_transit;
        /* State 5 reserves cleanup without colliding with retire-claimed state 4. */
        warp->using = 5;
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);

    if (exec_relo) relo_rc = kp_free_exec(exec_relo);
    if (exec_transit) transit_rc = kp_free_exec(exec_transit);

    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 5) {
        if (!relo_rc) warp->exec_relo = NULL;
        if (!transit_rc) warp->exec_transit = NULL;
        if (!warp->exec_relo && !warp->exec_transit) {
            warp->using = 0;
            warp->addr = 0;
            warp->type = NONE;
        } else {
            /* A failed RW-NX restore must never make this record reusable. */
            warp->using = 2;
        }
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
}

static int hook_mem_set_exec_ptr(void *hook_mem, void *exec_ptr, int transit)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    int rc = -EINVAL;

    if (!hook_mem || !exec_ptr || !hook_locks_ready) return -EINVAL;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 3) {
        void **slot = transit ? &warp->exec_transit : &warp->exec_relo;
        if (!*slot) {
            *slot = exec_ptr;
            rc = 0;
        } else {
            rc = -EBUSY;
        }
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
    return rc;
}

int hook_mem_set_relo(void *hook_mem, void *exec_ptr)
{
    return hook_mem_set_exec_ptr(hook_mem, exec_ptr, 0);
}

int hook_mem_set_transit(void *hook_mem, void *exec_ptr)
{
    return hook_mem_set_exec_ptr(hook_mem, exec_ptr, 1);
}

void hook_mem_publish(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    if (!hook_mem || !hook_locks_ready) return;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 3)
        __atomic_store_n(&warp->using, 1, __ATOMIC_RELEASE);
    kp_private_spin_unlock(&hook_mem_lock, flags);
}

void hook_mem_retire(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    if (!hook_mem || !hook_locks_ready) return;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 1 || warp->using == 4)
        __atomic_store_n(&warp->using, 2, __ATOMIC_RELEASE);
    kp_private_spin_unlock(&hook_mem_lock, flags);
}

int hook_mem_claim_retire(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    int rc = -ENOENT;
    if (!hook_mem || !hook_locks_ready) return -EINVAL;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 1) {
        __atomic_store_n(&warp->using, 4, __ATOMIC_RELEASE);
        rc = 0;
    } else if (warp->using == 4) {
        rc = -EBUSY;
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
    return rc;
}

void hook_mem_cancel_retire(void *hook_mem)
{
    hook_mem_warp_t *warp;
    unsigned long flags;
    if (!hook_mem || !hook_locks_ready) return;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 4)
        __atomic_store_n(&warp->using, 1, __ATOMIC_RELEASE);
    kp_private_spin_unlock(&hook_mem_lock, flags);
}

void *hook_get_mem_from_origin(uint64_t origin_addr)
{
    uint64_t start, end;
    unsigned long flags;
    if (!hook_locks_ready) return 0;
    flags = kp_private_spin_lock(&hook_mem_lock);
    start = mem_region_start;
    end = mem_region_end;
    for (uint64_t addr = start; addr < end && sizeof(hook_mem_warp_t) <= end - addr;
         addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        if (__atomic_load_n(&wrap->using, __ATOMIC_ACQUIRE) == 1 &&
            wrap->addr == origin_addr) {
            kp_private_spin_unlock(&hook_mem_lock, flags);
            return &wrap->chain;
        }
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
    return 0;
}

void *hook_get_mem_from_origin_type(uint64_t origin_addr, enum hook_type type)
{
    uint64_t start, end;
    unsigned long flags;
    if (!hook_locks_ready) return 0;
    flags = kp_private_spin_lock(&hook_mem_lock);
    start = mem_region_start;
    end = mem_region_end;
    for (uint64_t addr = start; addr < end && sizeof(hook_mem_warp_t) <= end - addr;
         addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        if (__atomic_load_n(&wrap->using, __ATOMIC_ACQUIRE) == 1 &&
            wrap->addr == origin_addr && wrap->type == type) {
            kp_private_spin_unlock(&hook_mem_lock, flags);
            return &wrap->chain;
        }
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
    return 0;
}
