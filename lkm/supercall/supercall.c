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
static long (*kp_orig_truncate_args)(long arg0, long arg1);
static void *kp_supercall_inline_target;

/* KPM management is manager-only. A plain SU allowlist grant must not
 * authorize loading, unloading, or controlling arbitrary kernel modules. */
static bool kp_supercall_manager_only(long cmd)
{
	switch (cmd) {
	case SUPERCALL_KPM_LOAD:
	case SUPERCALL_KPM_UNLOAD:
	case SUPERCALL_KPM_CONTROL:
	case SUPERCALL_KPM_NUMS:
	case SUPERCALL_KPM_LIST:
	case SUPERCALL_KPM_INFO:
		return true;
	default:
		return false;
	}
}

/* Inline-hook backups are generated trampolines and have no kernel CFI
 * shadow entry. Keep only these indirect calls outside the CFI check. */
__attribute__((no_sanitize("cfi")))
static long kp_call_original_regs_inline(const struct pt_regs *regs)
{
	return kp_orig_truncate_regs ? kp_orig_truncate_regs(regs) : -ENOSYS;
}

__attribute__((no_sanitize("cfi")))
static long kp_call_original_truncate_args(long arg0, long arg1)
{
	return kp_orig_truncate_args ? kp_orig_truncate_args(arg0, arg1) : -ENOSYS;
}

static long kp_supercall_handler(const struct pt_regs *regs)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());
	bool is_manager = kp_is_manager_uid(uid);
	bool is_allowed = kp_is_su_allow_uid(uid);
	long ver_xx_cmd = regs->regs[1];
	long cmd = ver_xx_cmd & 0xFFFF;

	/* Untrusted callers retain the original truncate() semantics. */
	if (!is_manager && !is_allowed) {
		logkd("supercall: uid %u not authorized (manager?%d allow?%d)\n", uid,
		      is_manager, is_allowed);
		if (kp_supercall_backend == KP_SUPERCALL_BACKEND_TABLE)
			return kp_orig_truncate_regs ? kp_orig_truncate_regs(regs) : -ENOSYS;
		return kp_call_original_regs_inline(regs);
	}

	/* SU allowlist membership is not manager authentication. */
	if (kp_supercall_manager_only(cmd) && !is_manager)
		return -EPERM;
	if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) {
		logkd("bad supercall cmd 0x%lx\n", cmd);
		if (kp_supercall_backend == KP_SUPERCALL_BACKEND_TABLE)
			return kp_orig_truncate_regs ? kp_orig_truncate_regs(regs) : -EINVAL;
		return kp_call_original_regs_inline(regs);
	}

	return kp_handle_supercall(cmd, regs->regs[2], regs->regs[3], regs->regs[4], regs->regs[5]);
}

/*
 * Linux 4.14 ARM64 has no pt_regs syscall wrapper. SYSCALL_DEFINE2 emits a
 * four-byte sys_truncate alias/jump-table entry and a real SyS_truncate.cfi
 * implementation with two long arguments. Hook the implementation, never
 * overwrite the adjacent four-byte CFI jump-table entries. el0_svc preserves
 * x0-x5 across the alias branch, so the four supercall payload registers are
 * still available to this six-argument replacement.
 */
static long kp_supercall_handler_legacy(long arg0, long arg1,
					unsigned long arg2, unsigned long arg3,
					unsigned long arg4, unsigned long arg5)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());
	bool is_manager = kp_is_manager_uid(uid);
	bool is_allowed = kp_is_su_allow_uid(uid);
	long cmd = (unsigned long)arg1 & 0xFFFF;

	if (!is_manager && !is_allowed)
		return kp_call_original_truncate_args(arg0, arg1);
	if (kp_supercall_manager_only(cmd) && !is_manager)
		return -EPERM;
	if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX)
		return kp_call_original_truncate_args(arg0, arg1);
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
	 * Linux 4.14.141 ARM64 has no ARCH_HAS_SYSCALL_WRAPPER. The public
	 * sys_truncate alias is a 4-byte CFI jump-table stub; hook its full
	 * SyS_truncate.cfi implementation instead.
	 */
	rc = kp_install_inline_supercall("SyS_truncate.cfi",
					 (void *)kp_supercall_handler_legacy,
					 (void **)&kp_orig_truncate_args,
					 KP_SUPERCALL_BACKEND_INLINE_ARGS);
#endif
	if (!rc)
		logki("supercall installed through inline syscall hook\n");
	return rc;
}

int kp_supercall_uninstall(void)
{
	int rc = 0;

	if (kp_supercall_backend == KP_SUPERCALL_BACKEND_TABLE) {
		rc = kp_syscall_unhook(KP_SUPERCALL_NR, kp_supercall_handler,
				       kp_orig_truncate_regs);
	} else if (kp_supercall_inline_target) {
		rc = unhook_checked(kp_supercall_inline_target);
		if (rc == -ENOENT)
			rc = 0;
	}
	if (rc) {
		logke("supercall hook restore failed: %d; retaining callback state\n", rc);
		return rc;
	}

	kp_supercall_inline_target = NULL;
	kp_supercall_backend = KP_SUPERCALL_BACKEND_NONE;
	kp_orig_truncate_regs = NULL;
	kp_orig_truncate_args = NULL;
	return 0;
}
