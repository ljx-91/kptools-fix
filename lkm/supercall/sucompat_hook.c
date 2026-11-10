// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Intercept execve of the su binary (/system/bin/kp). When a su-allowed or
 * manager uid execs it, grant root inline (kp_commit_su) and redirect the exec
 * to the shell (/system/bin/sh). Ported from KP's handle_before_execve, minus
 * the apd daemon branch (framework).
 */
#include "sucompat_hook.h"
#include "accctl.h"
#include "sucompat.h"

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/syscall_table.h"
#include "../infra/symbol_resolver.h"
#include "../manager/manager.h"
#include <hook.h>

#define KP_EXECVE_NR __NR_execve /* 221 on arm64 */
#define KP_SH_PATH SH_PATH       /* /system/bin/sh */

static kp_syscall_fn_t kp_orig_execve;
enum kp_sucompat_backend {
	KP_SUCOMPAT_BACKEND_NONE,
	KP_SUCOMPAT_BACKEND_SYSCALL,
	KP_SUCOMPAT_BACKEND_BINPRM,
};
static enum kp_sucompat_backend kp_sucompat_backend;
/* Resolved hook targets are retained for exact teardown. */
static unsigned long kp_getname_flags_addr;
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
/* Grant root and repoint the execve to apd (su only, if installed) or sh.
 * @su_exec: true when the intercepted binary is an actual su invocation (so a
 * -c/-u command must be preserved for apd's root_shell); false for SUPERCMD
 * (truncate <key> -Z <sctx>), which is a plain root shell request that sh
 * should get with no args. Overwrites the caller's user-space filename buffer
 * and argv in place.
 * @sctx: SELinux context to switch to. */
static long kp_redirect_to_sh(const struct pt_regs *regs, const char *what, uid_t uid,
			      bool su_exec, bool manager_exec, const char *sctx)
{
	char __user **uargv = (char __user **)regs->regs[1];
	const char *target = KP_SH_PATH;
	struct file *fp;
	bool use_apd = false;
	uintptr_t sp;
	char __user *new_filename;

	logki("execve %s by uid %u: granting root (sctx=%s)\n", what, uid,
	      sctx ? sctx : "(kernel)");
	kp_commit_su(0, sctx);

	/* Keep manager launches on the direct shell path. */
	if (su_exec && !manager_exec) {
		fp = filp_open(APD_PATH, O_RDONLY | O_NOFOLLOW, 0);
		if (!IS_ERR(fp)) {
			filp_close(fp, NULL);
			target = APD_PATH;
			use_apd = true;
		}
	}
	logki("redirect to %s\n", target);

	/*
	 * Never overwrite the caller's original filename buffer: it may only
	 * contain a short string such as "su". Place the replacement string in
	 * fresh user stack space and redirect syscall argument x0 instead.
	 */
	sp = current_user_stack_pointer();
	if (sp < strlen(target) + 1 + 8)
		goto passthrough;
	sp -= strlen(target) + 1;
	sp &= ~(uintptr_t)7;
	new_filename = (char __user *)sp;
	if (copy_to_user(new_filename, target, strlen(target) + 1)) {
		logkw("failed to write replacement filename\n");
		goto passthrough;
	}

	if (use_apd) {
		char __user *arg0;

		if (!uargv || sp < strlen(LEGACY_SU_PATH) + 1 + 8)
			goto passthrough;
		sp -= strlen(LEGACY_SU_PATH) + 1;
		sp &= ~(uintptr_t)7;
		arg0 = (char __user *)sp;
		if (copy_to_user(arg0, LEGACY_SU_PATH, strlen(LEGACY_SU_PATH) + 1)) {
			logkw("failed to write su argv[0]\n");
			goto passthrough;
		}
		if (copy_to_user(&uargv[0], &arg0, sizeof(arg0))) {
			logkw("failed to rewrite argv[0]\n");
			goto passthrough;
		}
	} else if (!su_exec && uargv) {
		/* Manager and SUPERCMD root shells take no arguments. */
		char __user *nullp = NULL;

		if (copy_to_user(&uargv[1], &nullp, sizeof(nullp))) {
			logkw("failed to rewrite argv[1]\n");
			goto passthrough;
		}
	}

	((struct pt_regs *)regs)->regs[0] = (unsigned long)new_filename;
	return kp_orig_execve(regs);

passthrough:
	if (kp_orig_execve)
		return kp_orig_execve(regs);
	return -ENOSYS;
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
	fput(old_file);

	args->local.data0 = 1;
	args->local.data1 = uid;
}

static void kp_after_prepare_binprm(hook_fargs1_t *args, void *udata)
{
	struct linux_binprm *bprm;
	struct cred *new;
	char sctx_buf[SUPERCALL_SCONTEXT_LEN];
	const char *sctx;
	uid_t uid;
	int rc;

	if (!args->local.data0 || (long)args->ret < 0)
		return;

	bprm = (struct linux_binprm *)args->arg0;
	if (!bprm || !bprm->cred)
		return;

	uid = (uid_t)args->local.data1;
	sctx = kp_default_sctx(uid, sctx_buf, sizeof(sctx_buf));
	new = bprm->cred;
	rc = kp_apply_su_cred(&new, 0, sctx);
	if (rc) {
		logke("sucompat: prepare exec cred failed: %d\n", rc);
		args->ret = (unsigned long)(long)rc;
		return;
	}
	bprm->cred = new;
	current_thread_info()->flags &= ~_TIF_SECCOMP;
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

/* ---- getname_flags path-probe redirect -------------------------------- */

static void kp_after_getname_flags(hook_fargs4_t *args, void *udata)
{
	struct filename *fn = (struct filename *)args->ret;
	const char *sh_path = SH_PATH;
	const char *su_path;
	size_t sh_len, su_len;

	if (IS_ERR_OR_NULL(fn))
		return;

	{
		uid_t uid = from_kuid(current_user_ns(), current_uid());
		if (!kp_is_su_allow_uid(uid) && !kp_is_manager_uid(uid))
			return;
	}

	su_path = kp_su_get_path();
	if (!fn->name || strcmp(fn->name, su_path))
		return;

	sh_len = strlen(sh_path);
	su_len = strlen(su_path);

	if (sh_len <= su_len) {
		/* New name fits in existing buffer. */
		strscpy((char *)fn->name, sh_path, su_len + 1);
		return;
	}

	/* sh_path is longer: allocate a fresh filename object. */
	{
		typeof(&getname_kernel) kp_getname;
		typeof(&putname) kp_putname;

		kp_getname = (typeof(kp_getname))kallsyms_lookup_name("getname_kernel");
		kp_putname = (typeof(kp_putname))kallsyms_lookup_name("putname");
		if (kp_getname && kp_putname) {
			struct filename *nf = kp_getname(sh_path);
			if (!IS_ERR_OR_NULL(nf)) {
				kp_putname(fn);
				args->ret = (unsigned long)nf;
			}
		}
	}
}

static int kp_hook_getname_flags(void)
{
	unsigned long addr;

	addr = kallsyms_lookup_name("__original_getname_flags");
	if (!addr)
		addr = kallsyms_lookup_name("getname_flags");
	if (!addr) {
		logki("sucompat: getname_flags not found, path-probe unavailable\n");
		return -ENOENT;
	}
	logki("sucompat: getname_flags at %px\n", (void *)addr);
	kp_getname_flags_addr = addr;
	return hook_wrap3((void *)addr, 0, kp_after_getname_flags, 0);
}

/* Default SELinux context */
static const char *kp_default_sctx(uid_t uid, char *sctx, size_t sctx_size)
{
	struct su_profile profile;

	if (sctx && sctx_size &&
	    kp_su_allow_uid_profile(uid, &profile) == 0 && profile.scontext[0]) {
		strscpy(sctx, profile.scontext, sctx_size);
		return sctx;
	}
	return ALL_ALLOW_SCONTEXT_MAGISK;
}
static long kp_execve_handler(const struct pt_regs *regs)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());
	char __user *ufilename = (char __user *)regs->regs[0];
	char filename[SU_PATH_MAX_LEN];
	char sctx_buf[SUPERCALL_SCONTEXT_LEN];
	long flen;
	bool su_ok, mgr_ok;

	/* Only su-allowed / manager uids trigger the interception. */
	mgr_ok = kp_is_manager_uid(uid);
	su_ok = kp_is_su_allow_uid(uid);
	if (!su_ok && !mgr_ok)
		goto passthrough;

	if (!ufilename)
		goto passthrough;
	flen = kp_copy_user_string(filename, sizeof(filename), ufilename);
	if (flen <= 0)
		goto passthrough;
	logki("execve uid=%u path=%s (su_path=%s)\n", uid, filename, kp_su_get_path());

	/* su binary: match any path an app may exec, not just the configured one. */
	{
		const char *su_path = kp_su_get_path();
		bool is_su_bin = strcmp(filename, su_path) == 0 ||
				 strcmp(filename, LEGACY_SU_PATH) == 0 ||
				 strcmp(filename, SU_PATH) == 0;
		if (!is_su_bin && (strcmp(filename, "su") == 0 || strcmp(filename, "kp") == 0))
			is_su_bin = true;
		if (is_su_bin)
			return kp_redirect_to_sh(regs, filename, uid, true, mgr_ok,
						 kp_default_sctx(uid, sctx_buf, sizeof(sctx_buf)));
	}

	/* SUPERCMD (/system/bin/truncate) is a plain root-shell request. */
	if (strcmp(filename, SUPERCMD) == 0) {
		const char *sctx = kp_get_supercmd_sctx(regs, sctx_buf, sizeof(sctx_buf));
		if (!sctx)
			sctx = kp_default_sctx(uid, sctx_buf, sizeof(sctx_buf));
		return kp_redirect_to_sh(regs, filename, uid, false, mgr_ok, sctx);
	}

passthrough:
	if (kp_orig_execve)
		return kp_orig_execve(regs);
	return -ENOSYS;
}
int kp_sucompat_hook_init(void)
{
	int rc;

	/* The syscall table is hidden on Y73s (CONFIG_KALLSYMS_ALL=n). */
	rc = kp_syscall_table_init();
	if (!rc)
		rc = kp_syscall_hook(KP_EXECVE_NR, kp_execve_handler, &kp_orig_execve);
	if (!rc) {
		kp_sucompat_backend = KP_SUCOMPAT_BACKEND_SYSCALL;
		logki("sucompat: execve syscall hook installed (su path %s -> %s)\n",
		      kp_su_get_path(), KP_SH_PATH);
		rc = kp_hook_getname_flags();
		if (rc)
			logkfd("sucompat: getname_flags hook failed: %d\n", rc);
		else
			logki("sucompat: getname_flags hook installed\n");
		return 0;
	}

	logkw("sucompat: syscall-table execve hook unavailable (%d); using prepare_binprm fallback\n",
	      rc);
	return kp_hook_prepare_binprm();
}

int kp_sucompat_hook_exit(void)
{
	int rc = 0;
	int unhook_rc;

	if (kp_sucompat_backend == KP_SUCOMPAT_BACKEND_SYSCALL) {
		kp_syscall_unhook(KP_EXECVE_NR, kp_orig_execve);
		kp_orig_execve = NULL;
		kp_sucompat_backend = KP_SUCOMPAT_BACKEND_NONE;
	} else if (kp_sucompat_backend == KP_SUCOMPAT_BACKEND_BINPRM &&
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

	if (kp_getname_flags_addr) {
		unhook_rc = kp_unwrap_wait((void *)kp_getname_flags_addr,
					       0, kp_after_getname_flags);
		if (!unhook_rc || unhook_rc == -ENOENT)
			kp_getname_flags_addr = 0;
		else {
			logke("sucompat: getname_flags hook is still live: %d\n",
			      unhook_rc);
			if (!rc)
				rc = unhook_rc;
		}
	}

	return rc;
}
