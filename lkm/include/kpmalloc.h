/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_KPMALLOC_H_
#define _KP_LKM_KPMALLOC_H_

#include <linux/types.h>

/* Standalone LKM adapters for the shared hook relocation code. */
void *kp_lkm_exec_alloc(size_t size);
void kp_lkm_exec_free(void *region, unsigned long size);
int kp_lkm_exec_seal(void *region, unsigned long size);

#endif
