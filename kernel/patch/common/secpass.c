/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <hook.h>
#include <kallsyms.h>
#include <common.h>
#include <uapi/asm-generic/errno.h>

#include <predata.h>

struct pt_regs;
int cfi_bypass = 0;
static inline bool should_cfi_pass(unsigned long target)
{
    return is_kp_text_area(target) || is_kp_hook_area(target) || is_kpm_rox_area(target);
}

enum bug_trap_type
{
    BUG_TRAP_TYPE_NONE = 0,
    BUG_TRAP_TYPE_WARN = 1,
    BUG_TRAP_TYPE_BUG = 2,
};

static enum bug_trap_type (*backup_report_cfi_failure)(struct pt_regs *regs, unsigned long addr, unsigned long *target,
                                                       u32 type) = 0;
static enum bug_trap_type replace_report_cfi_failure(struct pt_regs *regs, unsigned long addr, unsigned long *target,
                                                     u32 type)
{
    /* A successful hook must always have captured its original target. */
    if (!target || !backup_report_cfi_failure) return BUG_TRAP_TYPE_BUG;
    if (should_cfi_pass(*target)) {
        return BUG_TRAP_TYPE_WARN;
    }
    return backup_report_cfi_failure(regs, addr, target, type);
}

typedef void (*cfi_check_fn)(uint64_t id, void *ptr, void *diag);

static void (*backup__cfi_slowpath)(uint64_t id, void *ptr, void *diag) = 0;
static void replace__cfi_slowpath(uint64_t id, void *ptr, void *diag)
{
    if (should_cfi_pass((unsigned long)ptr)) return;
    /* Never turn a missing trampoline backup into a null indirect call. */
    if (!backup__cfi_slowpath) __builtin_trap();
    backup__cfi_slowpath(id, ptr, diag);
}

int bypass_kcfi()
{
    int rc = 0;
    bool report_cfi_failure_hooked = false;
    bool cfi_slowpath_hooked = false;

    // 6.1.0
    // todo: Is there more elegant way?
    unsigned long report_cfi_failure_addr = patch_config->report_cfi_failure;
    // runtime fallback: the patcher may have missed these symbols (kallsyms
    // version mismatch / KASLR math); resolve them ourselves so the kCFI guard
    // is never silently absent -> otherwise every kCFI mismatch on KP memory
    // panics (random reboots on CFI-enabled kernels)
    if (!report_cfi_failure_addr && kallsyms_lookup_name) {
        report_cfi_failure_addr = kallsyms_lookup_name("report_cfi_failure");
        if (report_cfi_failure_addr)
            log_boot("report_cfi_failure resolved at runtime: %llx\n", report_cfi_failure_addr);
    }
    if (report_cfi_failure_addr) {
        hook_err_t err = hook((void *)report_cfi_failure_addr, (void *)replace_report_cfi_failure,
                              (void **)&backup_report_cfi_failure);
        if (err) {
            log_boot("hook report_cfi_failure: %llx, error: %d\n", report_cfi_failure_addr, err);
            rc = err;
            goto out;
        }
        if (!backup_report_cfi_failure) {
            log_boot("report_cfi_failure hook returned no original target\n");
            rc = -EFAULT;
            goto out;
        }
        report_cfi_failure_hooked = true;
    }

    // todo: direct modify cfi_shadow, __cfi_check?
    unsigned long __cfi_slowpath_addr = patch_config->__cfi_slowpath_diag;
    if (!__cfi_slowpath_addr) {
        __cfi_slowpath_addr = patch_config->__cfi_slowpath;
    }
    if (!__cfi_slowpath_addr && kallsyms_lookup_name) {
        __cfi_slowpath_addr = kallsyms_lookup_name("__cfi_slowpath_diag");
        if (!__cfi_slowpath_addr) __cfi_slowpath_addr = kallsyms_lookup_name("__cfi_slowpath");
        if (__cfi_slowpath_addr)
            log_boot("__cfi_slowpath_diag resolved at runtime: %llx\n", __cfi_slowpath_addr);
    }
    if (__cfi_slowpath_addr) {
        hook_err_t err =
            hook((void *)__cfi_slowpath_addr, (void *)replace__cfi_slowpath, (void **)&backup__cfi_slowpath);
        if (err) {
            log_boot("hook __cfi_slowpath: %llx, error: %d\n", __cfi_slowpath_addr, err);
            rc = err;
            goto out;
        }
        if (!backup__cfi_slowpath) {
            log_boot("__cfi_slowpath hook returned no original target\n");
            rc = -EFAULT;
            goto out;
        }
        cfi_slowpath_hooked = true;
    }

#if defined(KP_TARGET_Y73S)
    /*
     * The exact Y73S 4.14.141 image has CONFIG_CFI_CLANG=y and exposes
     * __cfi_slowpath (not report_cfi_failure/__cfi_slowpath_diag).
     * The legacy slowpath is the required enforcement point; resolving or
     * hooking only the newer report helper is not sufficient.
     */
    if (!cfi_slowpath_hooked) {
        log_boot("Y73S CFI slowpath is required but was not hooked\n");
        rc = -ENOSYS;
        goto out;
    }
#endif

    if (!cfi_slowpath_hooked && !report_cfi_failure_hooked) {
        log_boot("no verified CFI enforcement hook was installed\n");
    }
    /* Publish success only after at least one enforcement hook is live. */
    cfi_bypass = cfi_slowpath_hooked || report_cfi_failure_hooked;

out:
    return rc;
}