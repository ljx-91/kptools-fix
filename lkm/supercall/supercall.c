// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * syscall 45 (truncate) is repurposed as the KP supercall channel
 * (user/uapi/scdefs.h: __NR_supercall). Authentication is manager-based: the
 * caller's uid must match the trusted APatch manager appid. Anything else
 * passes through to the original sys_truncate unchanged.
 */
#include "supercall.h"
#include "dispatch.h"

#include <linux/cred.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include "scdefs.h"

#include "../include/kp_lkm.h"
#include "../infra/syscall_table.h"
#include "../infra/symbol_resolver.h"
#include "../manager/manager.h"
#include <hook.h>
#include "sucompat.h"

#define KP_SUPERCALL_NR 45 /* __NR3264_truncate */

enum kp_supercall_backend {
	KP_SUPERCALL_BACKEND_NONE = 0,
	KP_SUPERCALL_BACKEND_TABLE,
	KP_SUPERCALL_BACKEND_INLINE_REGS,
	KP_SUPERCALL_BACKEND_INLINE_ARGS,
};

static enum kp_supercall_backend kp_supercall_backend;
static kp_syscall_fn_t kp_orig_truncate_regs;
static long (*kp_orig_truncate_args)(const char __user *path, long length);
static void *kp_supercall_inline_target;

/* Inline-hook backups are generated trampolines and have no kernel CFI
 * shadow entry. Keep only these indirect calls outside the CFI check. */
__attribute__((no_sanitize("cfi")))
static long kp_call_original_regs_inline(const struct pt_regs *regs)
{
	return kp_orig_truncate_regs ? kp_orig_truncate_regs(regs) : -ENOSYS;
}

__attribute__((no_sanitize("cfi")))
static long kp_call_original_truncate_args(const char __user *path, long length)
{
	return kp_orig_truncate_args ? kp_orig_truncate_args(path, length) : -ENOSYS;
}

static long kp_supercall_handler(const struct pt_regs *regs)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());

	/* The manager may grant/revoke allowlist entries; an already-allowed uid
	 * may use the SU supercalls. Anything else is a plain truncate() call. */
	if (!kp_is_manager_uid(uid) && !kp_is_su_allow_uid(uid)) {
		logkd("supercall: uid %u not authorized (manager?%d allow?%d)\n", uid,
		      kp_is_manager_uid(uid), kp_is_su_allow_uid(uid));
		if (kp_supercall_backend == KP_SUPERCALL_BACKEND_TABLE)
			return kp_orig_truncate_regs ? kp_orig_truncate_regs(regs) : -ENOSYS;
		return kp_call_original_regs_inline(regs);
	}

	long ver_xx_cmd = regs->regs[1];
	long cmd = ver_xx_cmd & 0xFFFF;
	if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) {
		logkd("bad supercall cmd 0x%lx\n", cmd);
		if (kp_supercall_backend == KP_SUPERCALL_BACKEND_TABLE)
			return kp_orig_truncate_regs ? kp_orig_truncate_regs(regs) : -EINVAL;
		return kp_call_original_regs_inline(regs);
	}

	return kp_handle_supercall(cmd, regs->regs[2], regs->regs[3], regs->regs[4], regs->regs[5]);
}

/*
 * Linux 4.14 ARM64 syscall table entries point directly at sys_* functions,
 * whose ABI is the ordinary C argument list, not struct pt_regs *. The
 * truncate syscall receives x0-x5 from el0_svc; the extra four registers are
 * deliberately accepted here for the KP supercall payload.
 */
static long kp_supercall_handler_legacy(const char __user *path, long length,
					unsigned long arg2, unsigned long arg3,
					unsigned long arg4, unsigned long arg5)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());
	long cmd = (unsigned long)length & 0xFFFF;

	if (!kp_is_manager_uid(uid) && !kp_is_su_allow_uid(uid))
		return kp_call_original_truncate_args(path, length);
	if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX)
		return kp_call_original_truncate_args(path, length);
	return kp_handle_supercall(cmd, arg2, arg3, arg4, arg5);
}

static int kp_install_inline_supercall(const char *symbol, void *handler,
				       void **backup,
				       enum kp_supercall_backend backend)
{
	unsigned long addr = kp_resolve_symbol(symbol);
	hook_err_t hook_rc;

	if (!addr) {
		logke("failed to resolve supercall target %s\n", symbol);
		return -ENOENT;
	}
	/* Publish the ABI/backend before the patch becomes reachable. */
	kp_supercall_backend = backend;
	hook_rc = hook((void *)addr, handler, backup);
	if (hook_rc) {
		kp_supercall_backend = KP_SUPERCALL_BACKEND_NONE;
		if (hook_rc == -HOOK_PATCH_UNCERTAIN) {
			int undo_rc = unhook_checked((void *)addr);
			if (undo_rc && undo_rc != -ENOENT) {
				logke("uncertain supercall hook rollback failed: %d\n", undo_rc);
				BUG_ON(1);
			}
		}
		logke("inline supercall hook %s failed: %d\n", symbol, hook_rc);
		return -EIO;
	}
	kp_supercall_inline_target = (void *)addr;
	return 0;
}

int kp_supercall_install(void)
{
	int rc;

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
	/*
	 * Newer ARM64 kernels use pt_regs syscall wrappers. Prefer the table
	 * backend when its data symbol and patch path are actually available;
	 * otherwise hook the text wrapper, which remains visible with KALLSYMS_ALL=n.
	 */
	rc = kp_syscall_table_init();
	if (!rc) {
		rc = kp_syscall_hook(KP_SUPERCALL_NR, kp_supercall_handler,
				     &kp_orig_truncate_regs);
		if (!rc) {
			kp_supercall_backend = KP_SUPERCALL_BACKEND_TABLE;
			logki("supercall installed through syscall table (%d)\n",
			      KP_SUPERCALL_NR);
			return 0;
		}
		logkw("syscall-table supercall unavailable (%d); falling back to wrapper hook\n", rc);
	}
	rc = kp_install_inline_supercall("__arm64_sys_truncate",
					 (void *)kp_supercall_handler,
					 (void **)&kp_orig_truncate_regs,
					 KP_SUPERCALL_BACKEND_INLINE_REGS);
#else
	/*
	 * Linux 4.14.141 ARM64 has no ARCH_HAS_SYSCALL_WRAPPER. sys_truncate
	 * is a text symbol, while sys_call_table is a hidden data symbol when
	 * CONFIG_KALLSYMS_ALL=n. Hook the real two-argument syscall entry.
	 */
	rc = kp_install_inline_supercall("sys_truncate",
					 (void *)kp_supercall_handler_legacy,
					 (void **)&kp_orig_truncate_args,
					 KP_SUPERCALL_BACKEND_INLINE_ARGS);
#endif
	if (!rc)
		logki("supercall installed through inline syscall hook\n");
	return rc;
}

void kp_supercall_uninstall(void)
{
	if (kp_supercall_backend == KP_SUPERCALL_BACKEND_TABLE) {
		kp_syscall_unhook(KP_SUPERCALL_NR, kp_orig_truncate_regs);
	} else if (kp_supercall_inline_target) {
		int rc = unhook_checked(kp_supercall_inline_target);
		if (rc && rc != -ENOENT) {
			logke("supercall inline hook restore failed: %d\n", rc);
			BUG_ON(1);
		}
	}
	kp_supercall_inline_target = NULL;
	kp_supercall_backend = KP_SUPERCALL_BACKEND_NONE;
	kp_orig_truncate_regs = NULL;
	kp_orig_truncate_args = NULL;
}
