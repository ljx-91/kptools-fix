// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * The ko is compiled against a fixed KMI, so struct cred fields are directly
 * addressable (KP's kpimg needs runtime cred_offset instead). Full root =
 * all capabilities + uid/gid switch via a freshly prepared cred. The SELinux
 * translabel helper is resolved at runtime like KP does.
 */
#include "accctl.h"

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"

/*
 * security_secctx_to_secid is not exported by the 4.14 vendor baseline.
 * Resolve it through kallsyms there; 5.15+ exposes the GPL export.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
extern int security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);
#define kp_security_secctx_to_secid security_secctx_to_secid
#else
typedef int (*kp_secctx_to_secid_fn_t)(const char *secdata, u32 seclen, u32 *secid);
static kp_secctx_to_secid_fn_t kp_security_secctx_to_secid;
#endif

/* selinux_blob_sizes is hidden data with CONFIG_KALLSYMS_ALL=n. */
struct kp_lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
};

static struct kp_lsm_blob_sizes *kp_selinux_blob_sizes;
static int kp_selinux_cred_offset = -1;

/* struct cred_security_struct { osid, sid, ... }; */
struct kp_task_sec {
	u32 osid;
	u32 sid;
};

int kp_accctl_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	kp_security_secctx_to_secid =
		(kp_secctx_to_secid_fn_t)kp_resolve_symbol("security_secctx_to_secid");
#endif
	kp_selinux_blob_sizes = (struct kp_lsm_blob_sizes *)kp_resolve_symbol("selinux_blob_sizes");
	if (kp_selinux_blob_sizes) {
		kp_selinux_cred_offset = kp_selinux_blob_sizes->lbs_cred;
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) && defined(CONFIG_SECURITY_SELINUX)
		/*
		 * Android 4.14 uses the legacy single-SELinux cred blob. The
		 * target config has SELinux enabled and all other optional LSMs
		 * disabled, so its cred_security_struct starts at cred->security.
		 */
		kp_selinux_cred_offset = 0;
		logkw("selinux_blob_sizes hidden; using verified 4.14 cred offset 0\n");
#endif
	}

	if (kp_selinux_cred_offset < 0 || !kp_security_secctx_to_secid) {
		logkw("SELinux translabel unavailable (offset=%d resolver=%px)\n",
		      kp_selinux_cred_offset, kp_security_secctx_to_secid);
		return 0;
	}
	logki("SELinux cred offset: %d; secctx resolver: %px\n",
	      kp_selinux_cred_offset, kp_security_secctx_to_secid);
	return 0;
}

/* Translabel a freshly-prepared cred to the given SELinux context (5.15 has no
 * set_security_override_from_ctx; it was removed in GKI). Resolve the context
 * to a sid and write tsec->sid directly. */
static int kp_selinux_set_cred_context(struct cred *new, const char *sctx)
{
	struct kp_task_sec *tsec;
	u32 sid;
	int rc;

	if (kp_selinux_cred_offset < 0 || !kp_security_secctx_to_secid ||
	    !sctx || !sctx[0])
		return -EINVAL;

	rc = kp_security_secctx_to_secid(sctx, strlen(sctx), &sid);
	if (rc || !sid) {
		logkw("secctx_to_secid(%s) failed: %d sid=%u\n", sctx, rc, sid);
		return rc ? rc : -EINVAL;
	}

	tsec = (struct kp_task_sec *)((char *)new->security + kp_selinux_cred_offset);
	tsec->sid = sid;
	return 0;
}

/* Fill every capability in a kernel_cap_t. */
static void fill_caps(struct cred *new)
{
	kernel_cap_t all = CAP_FULL_SET;
	new->cap_effective = all;
	new->cap_permitted = all;
	new->cap_inheritable = all;
	new->cap_bset = all;
	new->cap_ambient = all;
}

static void su_cred(struct cred *new, uid_t uid)
{
	fill_caps(new);
	new->uid = make_kuid(current_user_ns(), uid);
	new->euid = new->uid;
	new->fsuid = new->uid;
	new->suid = new->uid;
	new->gid = make_kgid(current_user_ns(), uid);
	new->egid = new->gid;
	new->fsgid = new->gid;
	new->sgid = new->gid;
}

/*
 * Apply a root identity and SELinux domain to a not-yet-installed cred.
 * This is used by the 4.14 prepare_binprm fallback, where the exec cred is
 * separate from current_cred() and must be changed before exec installs it.
 */
int kp_apply_su_cred(struct cred **cred, uid_t to_uid, const char *sctx)
{
	struct cred *new;
	struct cred *kernel;
	const char *target_sctx = sctx && sctx[0] ? sctx : ALL_ALLOW_SCONTEXT_MAGISK;
	int rc;

	if (!cred || !*cred)
		return -EINVAL;
	new = *cred;
	su_cred(new, to_uid);
	rc = kp_selinux_set_cred_context(new, target_sctx);
	if (!rc)
		return 0;

	logkw("SELinux translabel failed (%d), falling back to kernel cred\n", rc);
	kernel = prepare_kernel_cred(NULL);
	if (!kernel)
		return -ENOMEM;
	put_cred(new);
	*cred = kernel;
	return 0;
}

/* no_sanitize("cfi") keeps credential helpers outside legacy CFI checks. */
__attribute__((no_sanitize("cfi")))
int kp_commit_su(uid_t to_uid, const char *sctx)
{
	struct cred *new;
	int rc;

	/* Disable seccomp on the caller, matching KP's commit_common_su. */
	current_thread_info()->flags &= ~_TIF_SECCOMP;
	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	rc = kp_apply_su_cred(&new, to_uid, sctx);
	if (rc) {
		abort_creds(new);
		return rc;
	}
	commit_creds(new);
	logki("commit_su: to_uid=%u\n", to_uid);
	return 0;
}

int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
	struct task_struct *task;
	const struct cred *old;
	struct cred *new;

	task = find_get_task_by_vpid(pid);
	if (!task) {
		logke("task_su: no task pid %d\n", pid);
		return -ESRCH;
	}

	new = prepare_creds();
	if (!new) {
		put_task_struct(task);
		return -ENOMEM;
	}
	su_cred(new, to_uid);
	(void)sctx;

	rcu_read_lock();
	old = task->cred;
	rcu_assign_pointer(task->cred, new);
	rcu_assign_pointer(task->real_cred, new);
	rcu_read_unlock();
	put_cred(old);

	put_task_struct(task);
	logki("task_su: pid %d -> uid %u\n", pid, to_uid);
	return 0;
}
