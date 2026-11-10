/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Credential switching for the current task and pending exec credentials.
 * Cross-task SU is deliberately disabled until target-cred ownership and
 * synchronization can be implemented safely.
 */
#ifndef _KP_LKM_ACCCTL_H_
#define _KP_LKM_ACCCTL_H_
#include <linux/types.h>

/* Resolve the SELinux translabel helper at init. */
int kp_accctl_init(void);

struct cred;

/* Apply root uid/gid/capabilities and an SELinux context to a pending cred. */
int kp_apply_su_cred(struct cred **cred, uid_t to_uid, const char *sctx);

/* Grant root to the current task (uid/gid -> to_uid, all caps). */
int kp_commit_su(uid_t to_uid, const char *sctx);

/* Cross-task SU is currently fail-closed and returns -EOPNOTSUPP. */
int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx);

#endif /* _KP_LKM_ACCCTL_H_ */
