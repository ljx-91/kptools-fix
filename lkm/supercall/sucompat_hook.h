/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
#ifndef _KP_LKM_SUCOMPAT_HOOK_H_
#define _KP_LKM_SUCOMPAT_HOOK_H_

/* Hook prepare_binprm to prepare pending SU exec credentials. Returns 0 on success. */
int kp_sucompat_hook_init(void);

/* Retire the prepare_binprm hook and wait for in-flight callbacks. */
int kp_sucompat_hook_exit(void);

#endif /* _KP_LKM_SUCOMPAT_HOOK_H_ */
