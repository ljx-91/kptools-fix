/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_HOTPATCH_H_
#define _KP_HOTPATCH_H_

/* Allow the pre-rest_init, single-CPU boot hook path to use stop_machine's
 * documented pre-initialization fallback while local IRQs are masked. */
void hotpatch_set_early_boot(int enabled);

#endif
