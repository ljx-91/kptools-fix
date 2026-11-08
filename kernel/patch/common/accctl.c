/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "accctl.h"

#include <pgtable.h>
#include <ksyms.h>
#include <taskext.h>
#include <uapi/scdefs.h>
#include <linux/spinlock.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <asm/thread_info.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <linux/string.h>
#include <security/selinux/include/avc.h>
#include <security/selinux/include/security.h>
#include <predata.h>
#include <linux/slab.h>

extern void kp_debug_write(const char *fmt, ...);

char all_allow_sctx[SUPERCALL_SCONTEXT_LEN] = { '\0' };
uint32_t all_allow_sid = SECSID_NULL;

#define CRED_LAYOUT_SIZE 0x100
#define TASK_LAYOUT_SIZE 0x1800

static bool cred_field_valid(int offset, size_t size)
{
    return offset >= 0 && size <= CRED_LAYOUT_SIZE &&
           (size_t)offset <= CRED_LAYOUT_SIZE - size &&
           ((size_t)offset % sizeof(uint32_t)) == 0;
}

static bool cred_fields_disjoint(void)
{
    const int offsets[] = {
        cred_offset.cap_inheritable_offset, cred_offset.cap_permitted_offset,
        cred_offset.cap_effective_offset, cred_offset.cap_bset_offset,
        cred_offset.cap_ambient_offset, cred_offset.uid_offset,
        cred_offset.euid_offset, cred_offset.fsuid_offset, cred_offset.suid_offset,
        cred_offset.gid_offset, cred_offset.egid_offset,
        cred_offset.fsgid_offset, cred_offset.sgid_offset,
    };
    const size_t sizes[] = {
        sizeof(kernel_cap_t), sizeof(kernel_cap_t), sizeof(kernel_cap_t),
        sizeof(kernel_cap_t), sizeof(kernel_cap_t), sizeof(uid_t),
        sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), sizeof(gid_t),
        sizeof(gid_t), sizeof(gid_t), sizeof(gid_t),
    };
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        for (size_t j = i + 1; j < sizeof(offsets) / sizeof(offsets[0]); j++) {
            size_t a = (size_t)offsets[i];
            size_t b = (size_t)offsets[j];
            if (a < b + sizes[j] && b < a + sizes[i]) return false;
        }
    }
    return true;
}

static bool cred_layout_valid(void)
{
    return cred_field_valid(cred_offset.cap_inheritable_offset, sizeof(kernel_cap_t)) &&
           cred_field_valid(cred_offset.cap_permitted_offset, sizeof(kernel_cap_t)) &&
           cred_field_valid(cred_offset.cap_effective_offset, sizeof(kernel_cap_t)) &&
           cred_field_valid(cred_offset.cap_bset_offset, sizeof(kernel_cap_t)) &&
           cred_field_valid(cred_offset.cap_ambient_offset, sizeof(kernel_cap_t)) &&
           cred_field_valid(cred_offset.uid_offset, sizeof(uid_t)) &&
           cred_field_valid(cred_offset.euid_offset, sizeof(uid_t)) &&
           cred_field_valid(cred_offset.fsuid_offset, sizeof(uid_t)) &&
           cred_field_valid(cred_offset.suid_offset, sizeof(uid_t)) &&
           cred_field_valid(cred_offset.gid_offset, sizeof(gid_t)) &&
           cred_field_valid(cred_offset.egid_offset, sizeof(gid_t)) &&
           cred_field_valid(cred_offset.fsgid_offset, sizeof(gid_t)) &&
           cred_field_valid(cred_offset.sgid_offset, sizeof(gid_t)) &&
           cred_fields_disjoint();
}

static bool task_range_valid(int offset, size_t size)
{
    return offset >= 0 && size <= TASK_LAYOUT_SIZE &&
           (size_t)offset <= TASK_LAYOUT_SIZE - size;
}

static bool task_field_valid(int offset, size_t size)
{
    return task_range_valid(offset, size) &&
           ((size_t)offset % sizeof(void *)) == 0;
}

static bool task_cred_fields_valid(void)
{
    return task_field_valid(task_struct_offset.cred_offset, sizeof(void *)) &&
           task_field_valid(task_struct_offset.real_cred_offset, sizeof(void *));
}

static int su_cred(struct cred *cred, uid_t uid)
{
    if (!cred || !cred_layout_valid()) {
        logkfe("su_cred refused: invalid cred pointer or unresolved cred layout\\n");
        return -EINVAL;
    }

    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_permitted_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_ambient_offset) = full_cap;

    *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsuid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.suid_offset) = uid;

    *(uid_t *)((uintptr_t)cred + cred_offset.gid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.egid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsgid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.sgid_offset) = uid;
    return 0;
}

int set_all_allow_sctx(const char *sctx)
{
    if (!sctx || !sctx[0]) {
        all_allow_sctx[0] = 0;
        all_allow_sid = SECSID_NULL;
        dsb(ish);
        logkfd("clear all allow sconetxt\n");
        return 0;
    }

    int rc = security_secctx_to_secid(sctx, strlen(sctx), &all_allow_sid);
    if (!rc && all_allow_sid != SECSID_NULL) {
        strncpy(all_allow_sctx, sctx, sizeof(all_allow_sctx) - 1);
        all_allow_sctx[sizeof(all_allow_sctx) - 1] = '\0';
        dsb(ish);
        logkfd("set all allow sconetxt: %s, sid: %d\n", all_allow_sctx, all_allow_sid);
    }
    return rc;
}

int commit_kernel_su()
{
    if (!cred_layout_valid()) return -EINVAL;
    struct cred *new = prepare_kernel_cred(0);
    if (!new) return -ENOMEM;
    int rc = set_security_override(new, all_allow_sid);
    if (rc) {
        abort_creds(new);
        return rc;
    }
    return commit_creds(new);
}

int commit_common_su(uid_t to_uid, const char *sctx)
{
    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = kf_task_ext_ensure(task);
    int ext_ok = ext && task_ext_valid(ext);
    logkfi("commit_common_su: task=%llx ext=%llx ok=%d pid=%d\n", (uint64_t)task, (uint64_t)ext, ext_ok,
           ext_ok ? ext->pid : -1);
    if (unlikely(!ext_ok)) {
        logkfe("task_ext ensure failed, pid(maybe dirty): %d\n", ext ? ext->pid : -1);
        rc = -ENOMEM;
        goto out;
    }

    if (!cred_layout_valid()) {
        rc = -EINVAL;
        goto out;
    }

    /*
     * Do not change seccomp state or publish the SELinux bypass flag until
     * the credential transition has committed successfully. Otherwise an
     * allocation/layout failure leaves a partially privileged task behind.
     */
    int sel_allow_after_commit = 1;

    struct cred *new = prepare_creds();
    if (!new) {
        rc = -ENOMEM;
        goto out;
    }
    rc = su_cred(new, to_uid);
    if (rc) {
        abort_creds(new);
        goto out;
    }

    struct group_info *group_info = groups_alloc(0);
    if (!group_info) {
        abort_creds(new);
        rc = -ENOMEM;
        goto out;
    }
    set_groups(new, group_info);

    if (sctx && sctx[0]) {
        sel_allow_after_commit = !!set_security_override_from_ctx(new, sctx);
    }
    rc = commit_creds(new);
    if (rc) {
        abort_creds(new);
        goto out;
    }

    ext->sel_allow = sel_allow_after_commit;
    struct thread_info *thi = current_thread_info();
    if (thi) thi->flags &= ~(_TIF_SECCOMP);
    if (task_range_valid(task_struct_offset.seccomp_offset, sizeof(struct seccomp))) {
        struct seccomp *seccomp = (struct seccomp *)((uintptr_t)task + task_struct_offset.seccomp_offset);
        seccomp->mode = SECCOMP_MODE_DISABLED;
    } else {
        logkfe("commit_common_su: unresolved seccomp offset; leaving seccomp unchanged\\n");
    }

out:
    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext ? ext->pid : -1, ext ? ext->tgid : -1,
           to_uid, sctx, ext ? ext->sel_allow : 0);
    return rc;
}

int commit_su(uid_t to_uid, const char *sctx)
{
    if (all_allow_sid != SECSID_NULL && !to_uid) {
        return commit_kernel_su();
    } else {
        return commit_common_su(to_uid, sctx);
    }
}

// todo: rcu
int task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
    int rc = 0;
    int scontext_changed = 0;
    struct task_struct *task = find_get_task_by_vpid(pid);
    if (!task) {
        logkfe("no such pid: %d\n", pid);
        return -ESRCH;
    }
    struct task_ext *ext = kf_task_ext_ensure(task);

    if (unlikely(!ext || !task_ext_valid(ext))) {
        logkfe("task_ext ensure failed, pid(maybe dirty): %d\n", ext ? ext->pid : -1);
        rc = -ENOMEM;
        goto out;
    }

    if (!task_cred_fields_valid() || !cred_layout_valid()) {
        rc = -EINVAL;
        goto out;
    }

    struct thread_info *thi = get_task_thread_info(task);
    if (!thi) {
        rc = -EINVAL;
        goto out;
    }
    thi->flags &= ~(_TIF_SECCOMP);

    if (task_range_valid(task_struct_offset.seccomp_offset, sizeof(struct seccomp))) {
        struct seccomp *seccomp = (struct seccomp *)((uintptr_t)task + task_struct_offset.seccomp_offset);
        seccomp->mode = SECCOMP_MODE_DISABLED;
        // only be called when the task is exiting, so no barriers
        // todo: WARN_ON(tsk->sighand != NULL);
        // seccomp_filter_release(task);
    } else {
        logkfe("task_su: unresolved seccomp offset; leaving seccomp unchanged\\n");
    }

    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    struct cred *real_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset);
    if (!cred || !real_cred) {
        rc = -EINVAL;
        goto out;
    }
    rc = su_cred(cred, to_uid);
    if (rc) goto out;
    if (sctx && sctx[0]) scontext_changed = !set_security_override_from_ctx(cred, sctx);

    if (cred != real_cred) {
        rc = su_cred(real_cred, to_uid);
        if (rc) goto out;
        if (sctx && sctx[0]) scontext_changed = scontext_changed && !set_security_override_from_ctx(real_cred, sctx);
    }
    ext->priv_sel_allow = !scontext_changed;

    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext->pid, ext->tgid, to_uid, sctx,
           ext->priv_sel_allow);
out:
    return rc;
}

static int (*avc_denied_backup)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                                void *driver, void *xperm, void *flags, struct av_decision *avd) = 0;

static int avc_denied_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass, void *_requested,
                              void *_driver, void *_xperm, void *_flags, struct av_decision *_avd)
{
    if (all_allow_sid != SECSID_NULL) {
        u32 ssid = (u32)(u64)_ssid;
        if ((uint64_t)_state <= 0xffffffffL) {
            ssid = (u32)(u64)_state;
        }
        if (ssid == all_allow_sid) {
            goto allow;
        }
    }

    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->sel_allow || ext->priv_sel_allow))) {
        goto allow;
    }

    int rc = avc_denied_backup(_state, _ssid, _tsid, _tclass, _requested, _driver, _xperm, _flags, _avd);
    return rc;

allow:
    struct av_decision *avd = (struct av_decision *)_avd;
    if ((uint64_t)_state <= 0xffffffffL) {
        avd = (struct av_decision *)_flags;
    }
    avd->allowed = 0xffffffff;
    avd->auditallow = 0;
    avd->auditdeny = 0;
    return 0;
}

static int (*slow_avc_audit_backup)(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                    void *_requested, void *_audited, void *_denied, void *_result,
                                    struct common_audit_data *_a) = 0;

static int slow_avc_audit_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                  void *_requested, void *_audited, void *_denied, void *_result,
                                  struct common_audit_data *_a)
{
    if (all_allow_sid != SECSID_NULL) {
        u32 ssid = (u64)_ssid;
        if ((uint64_t)_state <= 0xffffffffL) {
            ssid = (u64)_state;
        }
        if (ssid == all_allow_sid) {
            return 0;
        }
    }

    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->sel_allow || ext->priv_sel_allow))) {
        return 0;
    }

    int rc = slow_avc_audit_backup(_state, _ssid, _tsid, _tclass, _requested, _audited, _denied, _result, _a);
    return rc;
}

int bypass_selinux()
{
    hook_err_t primary_rc = HOOK_BAD_ADDRESS;
    unsigned long avc_denied_addr = patch_config->avc_denied;
    if (avc_denied_addr) {
        primary_rc = hook((void *)avc_denied_addr, (void *)avc_denied_replace, (void **)&avc_denied_backup);
        if (primary_rc == HOOK_NO_ERR) {
            log_boot("hook avc_denied: %llx installed\\n", avc_denied_addr);
            return 0;
        }
        log_boot("hook avc_denied: %llx, error: %d\\n", avc_denied_addr, primary_rc);
    }

    unsigned long slow_avc_audit_addr = patch_config->slow_avc_audit;
    if (slow_avc_audit_addr) {
        hook_err_t fallback_rc =
            hook((void *)slow_avc_audit_addr, (void *)slow_avc_audit_replace, (void **)&slow_avc_audit_backup);
        if (fallback_rc == HOOK_NO_ERR) {
            log_boot("hook slow_avc_audit: %llx installed\\n", slow_avc_audit_addr);
            return 0;
        }
        log_boot("hook slow_avc_audit: %llx, error: %d\\n", slow_avc_audit_addr, fallback_rc);
        return fallback_rc;
    }

    return primary_rc;
}
