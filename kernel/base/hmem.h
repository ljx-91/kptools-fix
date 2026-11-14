/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_HMEM_H_
#define _KP_HMEM_H_

#include <stdint.h>

int hook_mem_add(uint64_t start, int32_t size);
void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type);
void hook_mem_free(void *hook_mem);
void hook_mem_retire(void *hook_mem);
int hook_mem_claim_retire(void *hook_mem);
void hook_mem_cancel_retire(void *hook_mem);
void hook_mem_publish(void *hook_mem);
int hook_mem_set_relo(void *hook_mem, void *exec_ptr);
int hook_mem_set_transit(void *hook_mem, void *exec_ptr);
void *hook_get_mem_from_origin(uint64_t origin_addr);
void *hook_get_mem_from_origin_type(uint64_t origin_addr, enum hook_type type);

#endif
