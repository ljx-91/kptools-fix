// SPDX-License-Identifier: GPL-2.0-or-later
/* Reuse KernelPatch's ARM64 relocation and hook-chain engine. */
#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/cacheflush.h>
#include <hook.h>

/* The shared source selects this backend-specific helper at compile time. */
static hook_err_t hook_chain_prepare(hook_chain_t *chain,
                                     uint32_t **transit_out, int32_t argno);

#ifndef __noinline
#define __noinline noinline
#endif

/* The original kpimg linker script provides _transit*_end and copies each
 * transit function into hook memory. Linux modules have no such linker
 * markers, so emit a small absolute branch to the resident LKM function. */
#define KP_HOOK_EXTERNAL_CHAIN_PREPARE
#define KP_HOOK_FLUSH_ICACHE_RANGE(start, end) do { \
	flush_icache_range((unsigned long)(start), (unsigned long)(end)); \
	__flush_icache_all(); \
} while (0)

#include "../../kernel/base/hook.c"

static hook_err_t hook_chain_prepare(hook_chain_t *chain,
                                     uint32_t **transit_out, int32_t argno)
{
	uint64_t target;
	uint32_t *transit;
	int32_t abi_class = hook_argno_abi_class(argno);

	if (!chain || !transit_out || abi_class < 0)
		return -HOOK_BAD_ADDRESS;
	*transit_out = NULL;
	chain->argno_abi_class = abi_class;
	if (argno == 0)
		target = (uint64_t)_transit0;
	else if (argno <= 4)
		target = (uint64_t)_transit4;
	else if (argno <= 8)
		target = (uint64_t)_transit8;
	else
		target = (uint64_t)_transit12;

	/* Keep mutable chain state in kzalloc memory. Only the generated branch
	 * stub is allocated from the executable module-memory backend. */
	transit = kp_lkm_exec_alloc(64);
	if (!transit)
		return -HOOK_TRANSIT_NO_MEM;
	if (hook_mem_set_transit(chain, transit)) {
		kp_lkm_exec_free(transit, PAGE_ALIGN(64));
		return -HOOK_TRANSIT_NO_MEM;
	}

	transit[0] = ARM64_BTI_JC;
	transit[1] = 0x58000070; /* LDR X16, #12 */
	transit[2] = 0x14000004; /* B #16 */
	transit[3] = ARM64_NOP;
	transit[4] = (uint64_t)chain;
	transit[5] = (uint64_t)chain >> 32;
	if (branch_absolute(&transit[6], target) <= 0)
		return -HOOK_TRANSIT_NO_MEM;
	flush_icache_range((unsigned long)transit,
			   (unsigned long)(transit + 16));
	__flush_icache_all();
	if (kp_lkm_exec_seal(transit, PAGE_ALIGN(64)))
		return -HOOK_TRANSIT_NO_MEM;
	*transit_out = transit;
	return HOOK_NO_ERR;
}
