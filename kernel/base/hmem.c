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

static uint64_t mem_region_start = 0;
static uint64_t mem_region_end = 0;
static spinlock_t hook_mem_lock;
static spinlock_t hook_engine_spinlock;
static bool hook_locks_ready;

unsigned long hook_engine_lock(void) { return kp_private_spin_lock(&hook_engine_spinlock); }
void hook_engine_unlock(unsigned long flags) { kp_private_spin_unlock(&hook_engine_spinlock, flags); }

typedef struct
{
    int using;
    enum hook_type type;
    uintptr_t addr;
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
    spin_lock_init(&hook_mem_lock);
    spin_lock_init(&hook_engine_spinlock);
    hook_locks_ready = true;
    for (uint64_t i = start; i + sizeof(uint64_t) <= end; i += sizeof(uint64_t))
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
        if (wrap->using == 1 || wrap->using == 3) {
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
    if (!hook_mem || !hook_locks_ready) return;
    warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    flags = kp_private_spin_lock(&hook_mem_lock);
    if (warp->using == 3) {
        warp->using = 0;
        warp->addr = 0;
        warp->type = NONE;
    }
    kp_private_spin_unlock(&hook_mem_lock, flags);
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
    if (warp->using == 1)
        __atomic_store_n(&warp->using, 2, __ATOMIC_RELEASE);
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
