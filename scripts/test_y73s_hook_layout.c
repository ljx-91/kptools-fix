// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Host-side ABI layout contract for the shared ARM64 Hook structures.
 * This checks the 64-bit C layout; it does not replace a target-KDIR build.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <hook.h>

_Static_assert(sizeof(void *) == 8, "run this contract on a 64-bit host");
_Static_assert(sizeof(hook_t) == 296, "hook_t size changed");
_Static_assert(offsetof(hook_t, func_addr) == 0, "hook_t.func_addr offset");
_Static_assert(offsetof(hook_t, origin_addr) == 8, "hook_t.origin_addr offset");
_Static_assert(offsetof(hook_t, replace_addr) == 16, "hook_t.replace_addr offset");
_Static_assert(offsetof(hook_t, relo_addr) == 24, "hook_t.relo_addr offset");
_Static_assert(offsetof(hook_t, tramp_insts_num) == 32, "hook_t.tramp_insts_num offset");
_Static_assert(offsetof(hook_t, relo_insts_num) == 36, "hook_t.relo_insts_num offset");
_Static_assert(offsetof(hook_t, origin_insts) == 40, "hook_t.origin_insts offset");
_Static_assert(offsetof(hook_t, tramp_insts) == 64, "hook_t.tramp_insts offset");
_Static_assert(offsetof(hook_t, relo_insts) == 88, "hook_t.relo_insts offset");

_Static_assert(offsetof(hook_chain_t, hook) == 0, "hook_chain_t.hook offset");
_Static_assert(offsetof(hook_chain_t, chain_items_max) == 296,
               "hook_chain_t.chain_items_max offset");
_Static_assert(offsetof(hook_chain_t, active_readers) == 300,
               "hook_chain_t.active_readers offset");
_Static_assert(offsetof(hook_chain_t, states) == 304,
               "hook_chain_t.states offset");
_Static_assert(offsetof(hook_chain_t, udata) == 320,
               "hook_chain_t.udata offset");
_Static_assert(offsetof(hook_chain_t, befores) == 448,
               "hook_chain_t.befores offset");
_Static_assert(offsetof(hook_chain_t, afters) == 576,
               "hook_chain_t.afters offset");
_Static_assert(offsetof(hook_chain_t, before_owners) == 704,
               "hook_chain_t.before_owners offset");
_Static_assert(offsetof(hook_chain_t, after_owners) == 832,
               "hook_chain_t.after_owners offset");
_Static_assert(offsetof(hook_chain_t, transit) == 960,
               "hook_chain_t.transit offset");
_Static_assert(sizeof(hook_chain_t) == 1408, "hook_chain_t size changed");

int main(void)
{
	printf("hook_t=%zu hook_chain_t=%zu transit=%zu\n",
	       sizeof(hook_t), sizeof(hook_chain_t),
	       offsetof(hook_chain_t, transit));
	return 0;
}
