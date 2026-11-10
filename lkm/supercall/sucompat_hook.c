// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Intercept su execs at prepare_binprm and prepare only bprm->cred.
 * Credentials are committed by the kernel only after exec passes validation.
 */
#include "sucompat_hook.h"
#include "accctl.h"
#include "sucompat.h"

#include <asm/processor.h>
#include <asm/unistd.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"
#include "../manager/manager.h"
#include <hook.h>

static const char kp_sh_path[] = SH_PATH; /* unique bprm provenance marker */
#define KP_SH_PATH kp_sh_path

enum kp_sucompat_backend {
	KP_SUCOMPAT_BACKEND_NONE,
	KP_SUCOMPAT_BACKEND_BINPRM,
};

enum kp_bprm_hook_state {
	KP_BPRM_HOOK_NONE,
	KP_BPRM_HOOK_SU_REDIRECT,
	KP_BPRM_HOOK_SU_CHAIN,
};
static enum kp_sucompat_backend kp_sucompat_backend;
/* Resolved hook targets are retained for exact teardown. */
static unsigned long kp_prepare_binprm_addr;
typedef struct file *(*kp_open_exec_fn_t)(const char *name);
static kp_open_exec_fn_t kp_open_exec;
static const char *kp_default_sctx(uid_t uid, char *sctx, size_t sctx_size);

/*
 * A full-size strncpy_from_user() result means no NUL was found in range.
 * Never pass that unterminated buffer to strcmp(), logging, or profile code.
 */
static long kp_copy_user_string(char *dst, size_t dst_size,
				const char __user *src)
{
	long len;

	if (!dst || !dst_size || !src)
		return -EINVAL;
	len = strncpy_from_user(dst, src, dst_size);
	if (len < 0)
		return len;
	if ((size_t)len >= dst_size) {
		dst[dst_size - 1] = 0;
		return -ENAMETOOLONG;
	}
	dst[len] = 0;
	return len;
}



/* Parse the -Z <sctx> option from a SUPERCMD argv: "truncate <key> -Z <sctx>".
 * Copies into the caller's stack buffer, or returns NULL if absent/invalid. */
static const char *kp_get_supercmd_sctx(const struct pt_regs *regs,
					char *sctx, size_t sctx_size)
{
	char __user **uargv = (char __user **)regs->regs[1];
	int i;

	if (!uargv || !sctx || !sctx_size)
		return NULL;

	/* argv layout: [0]=truncate [1]=key [2..]=options. Walk args 2.. */
	for (i = 2; i < 16; i++) {
		char __user *arg;
		char buf[64];

		if (copy_from_user(&arg, &uargv[i], sizeof(arg)) || !arg)
			break;
		if (kp_copy_user_string(buf, sizeof(buf), arg) <= 0)
			break;
		if (buf[0] != '-')
			break;
		if (buf[1] == 'Z') {
			char __user *sctx_arg;
			long len;

			if (copy_from_user(&sctx_arg, &uargv[i + 1], sizeof(sctx_arg)) ||
			    !sctx_arg)
				break;
			len = kp_copy_user_string(sctx, sctx_size, sctx_arg);
			return len > 0 ? sctx : NULL;
		}
	}
	return NULL;
}
/*
 * Linux 4.14 vendor kernels may hide sys_call_table with CONFIG_KALLSYMS_ALL=n.
 * prepare_binprm() is a text symbol and runs only on the exec path, after the
 * filename and file are attached to linux_binprm but before argv is copied.
 * Redirect the file itself to sh here, then update the pending exec cred after
 * the kernel's security_bprm_set_creds() has completed.
 */
static void kp_before_prepare_binprm(hook_fargs1_t *args, void *udata)
{
	struct linux_binprm *bprm = (struct linux_binprm *)args->arg0;
	struct file *shell_file;
	struct file *old_file;
	uid_t uid;
	const char *su_path;
	bool su_exec;
	bool supercmd;

	if (!bprm || !bprm->filename || !bprm->file)
		return;

	/*
	 * binfmt_script may call prepare_binprm() again for the interpreter.
	 * filename remains our unique static marker across bprm_change_interp().
	 * Do not re-run SU/SELinux setup; mark the later callback so it can
	 * fail closed after the kernel reprocesses interpreter credentials.
	 */
	if (bprm->filename == KP_SH_PATH) {
		args->local.data0 = KP_BPRM_HOOK_SU_CHAIN;
		return;
	}

	uid = from_kuid(current_user_ns(), current_uid());
	if (!kp_is_su_allow_uid(uid) && !kp_is_manager_uid(uid))
		return;

	su_path = kp_su_get_path();
	su_exec = !strcmp(bprm->filename, su_path) ||
		  !strcmp(bprm->filename, LEGACY_SU_PATH) ||
		  !strcmp(bprm->filename, SU_PATH) ||
		  !strcmp(bprm->filename, "su") ||
		  !strcmp(bprm->filename, "kp");
	supercmd = !strcmp(bprm->filename, SUPERCMD);
	if (!su_exec && !supercmd)
		return;

	if (!kp_open_exec)
		return;
	shell_file = kp_open_exec(KP_SH_PATH);
	if (IS_ERR(shell_file)) {
		logkw("sucompat: open shell for %s failed: %ld\n",
		      bprm->filename, PTR_ERR(shell_file));
		return;
	}

	old_file = bprm->file;
	bprm->file = shell_file;
	bprm->filename = KP_SH_PATH;
	bprm->interp = KP_SH_PATH;
	if (supercmd && bprm->argc > 1)
		bprm->argc = 1; /* Keep argv[0], discard the SUPERCMD key/options. */
	/* open_exec() and do_open_execat() both hold deny_write_access(). */
	allow_write_access(old_file);
	fput(old_file);

	args->local.data0 = KP_BPRM_HOOK_SU_REDIRECT;
	args->local.data1 = uid;
	args->local.data2 = supercmd;
}

static void kp_after_prepare_binprm(hook_fargs1_t *args, void *udata)
{
	struct linux_binprm *bprm;
	struct cred *new;
	char sctx_buf[SUPERCALL_SCONTEXT_LEN];
	const char *sctx;
	uid_t uid;
	int rc;

	if ((long)args->ret < 0)
		return;

	bprm = (struct linux_binprm *)args->arg0;
	if (!bprm || !bprm->cred)
		return;

	if (args->local.data0 == KP_BPRM_HOOK_SU_CHAIN) {
		/*
		 * prepare_binprm() re-runs bprm_fill_uid() and all bprm_set_creds
		 * hooks for interpreter chains. In particular commoncap may
		 * recompute/downgrade capability sets, so restoring only euid/egid
		 * would produce a partially privileged exec. Until the complete
		 * chain credential transaction is implemented, abort this SU exec.
		 */
		logkw("sucompat: interpreter chain is unsupported; aborting SU exec\n");
		args->ret = (unsigned long)(long)-EOPNOTSUPP;
		return;
	}
	if (args->local.data0 != KP_BPRM_HOOK_SU_REDIRECT)
		return;

	uid = (uid_t)args->local.data1;
	sctx = NULL;
	if (args->local.data2) {
		struct pt_regs *regs = task_pt_regs(current);

		/* Only execve has argv in x1; execveat and kernel_execve use
		 * the configured default SELinux profile instead. */
		if (regs && regs->syscallno == __NR_execve)
			sctx = kp_get_supercmd_sctx(regs, sctx_buf, sizeof(sctx_buf));
	}
	if (!sctx)
		sctx = kp_default_sctx(uid, sctx_buf, sizeof(sctx_buf));
	new = bprm->cred;
	rc = kp_apply_su_cred(&new, 0, sctx);
	if (rc) {
		logke("sucompat: prepare exec cred failed: %d\n", rc);
		args->ret = (unsigned long)(long)rc;
		return;
	}
	bprm->cred = new;
	/*
	 * Keep the current task's seccomp state intact here. prepare_binprm()
	 * runs before ELF validation and install_exec_creds(); the exec may
	 * still fail after this callback. Clearing TIF_SECCOMP now would leak
	 * the policy change into the still-running caller on an early failure.
	 */
	logki("sucompat: prepare_binprm redirected to shell; root cred prepared (uid=%u)\n",
	      uid);
}

static int kp_hook_prepare_binprm(void)
{
	unsigned long addr;

	kp_open_exec = (kp_open_exec_fn_t)kp_resolve_symbol("open_exec");
	if (!kp_open_exec) {
		logke("sucompat: open_exec not found; cannot safely replace bprm->file\n");
		return -ENOENT;
	}
	addr = kp_resolve_symbol("prepare_binprm.cfi");
	if (!addr)
		addr = kp_resolve_symbol("prepare_binprm");
	if (!addr) {
		kp_open_exec = NULL;
		logke("sucompat: prepare_binprm not found; no safe execve fallback\n");
		return -ENOENT;
	}

	logki("sucompat: prepare_binprm at %px; open_exec=%px\n",
	      (void *)addr, kp_open_exec);
	/*
	 * Record the target before patching: hook_wrap1() can return
	 * -HOOK_PATCH_UNCERTAIN after publishing a live chain. Init rollback
	 * must still know which entry to retire before the LKM image is freed.
	 */
	kp_prepare_binprm_addr = addr;
	kp_sucompat_backend = KP_SUCOMPAT_BACKEND_BINPRM;
	return hook_wrap1((void *)addr, kp_before_prepare_binprm,
			  kp_after_prepare_binprm, 0);
}

/*
 * hook_unwrap_remove() retires the callback immediately but reports -EBUSY
 * while a transit invocation still holds a reader reference. The API
 * explicitly requires retry; module teardown must wait rather than panic on
 * an ordinary in-flight exec, and must not return until the callback is gone.
 */
static int kp_unwrap_wait(void *func, void *before, void *after)
{
	int rc;

	do {
		rc = hook_unwrap_remove(func, before, after, 1);
		if (rc == -EBUSY)
			cond_resched();
	} while (rc == -EBUSY);
	return rc;
}

/* Default SELinux context */
static const char *kp_default_sctx(uid_t uid, char *sctx, size_t sctx_size)
{
	struct su_profile profile;
	size_t sctx_len;

	if (!sctx || !sctx_size)
		return ALL_ALLOW_SCONTEXT_MAGISK;
	if (kp_su_allow_uid_profile(uid, &profile) == 0) {
		sctx_len = strnlen(profile.scontext, sizeof(profile.scontext));
		if (sctx_len && sctx_len < sizeof(profile.scontext) &&
		    sctx_len < sctx_size) {
			memcpy(sctx, profile.scontext, sctx_len + 1);
			return sctx;
		}
	}
	return ALL_ALLOW_SCONTEXT_MAGISK;
}
int kp_sucompat_hook_init(void)
{
	/*
	 * Do not use the syscall-table backend: it commits current credentials
	 * before user-stack rewriting and before the original execve can fail.
	 * prepare_binprm lets us modify only bprm->cred; install_exec_creds()
	 * publishes it after the kernel has accepted the new executable.
	 * If this kernel does not expose a usable prepare_binprm entry, fail
	 * closed instead of falling back to an early credential commit.
	 */
	return kp_hook_prepare_binprm();
}

int kp_sucompat_hook_exit(void)
{
	int rc = 0;
	int unhook_rc;

	if (kp_sucompat_backend == KP_SUCOMPAT_BACKEND_BINPRM &&
	    kp_prepare_binprm_addr) {
		unhook_rc = kp_unwrap_wait((void *)kp_prepare_binprm_addr,
					   kp_before_prepare_binprm,
					   kp_after_prepare_binprm);
		if (!unhook_rc || unhook_rc == -ENOENT) {
			kp_prepare_binprm_addr = 0;
			kp_open_exec = NULL;
			kp_sucompat_backend = KP_SUCOMPAT_BACKEND_NONE;
		} else {
			logke("sucompat: prepare_binprm hook is still live: %d\n",
			      unhook_rc);
			rc = unhook_rc;
		}
	}

	return rc;
}
