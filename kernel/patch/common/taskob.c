/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <taskob.h>
#include <taskext.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/compiler.h>
#include <log.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <pgtable.h>
#include <linux/fs.h>
#include <linux/seccomp.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>
#include <symbol.h>
#include <kp_spinlock.h>
#include <stdarg.h>
#include <asm/atomic.h>
#include <baselib.h>

extern void kp_debug_write(const char *fmt, ...);
extern int kp_task_ext_identity(struct task_struct *task,
                                unsigned long *stack_identity);

/*
 * task_ext per-task slot table.
 *
 * Slot identity (task pointer, PID/TGID and kernel-stack allocation) is immutable
 * after publication; policy flags are mutable and accessed with READ_ONCE/WRITE_ONCE.
 * Slots are deliberately not recycled:
 * lock-free readers (including SELinux hooks) may still hold a returned ext
 * pointer after lookup. Reusing a slot from do_exit would create a use-after-
 * reuse race. The bounded table fails closed when exhausted.
 */
#define TASK_EXT_SLOT_NUM 1024
struct task_ext_slot {
    struct task_struct *task;
    unsigned long stack_identity;
    struct task_ext ext;
};
static struct task_ext_slot task_ext_slots[TASK_EXT_SLOT_NUM];
static struct task_ext task_ext_invalid;
static spinlock_t task_ext_lock;
static atomic_t task_ext_active_count = ATOMIC_INIT(0);

static inline void task_ext_reset(struct task_ext *ext)
{
    lib_memset(ext, 0, sizeof(*ext));
    ext->size = task_ext_size;
    ext->_magic = TASK_EXT_MAGIC;
}

/*
 * The ext identity is initialized before publishing its task key. Slots are
 * never reused, so a lock-free lookup can safely retain the returned pointer.
 */
struct task_ext *kf_get_task_ext(const struct task_struct *task)
{
    if (unlikely(!task)) return &task_ext_invalid;
    if (likely(!atomic_read(&task_ext_active_count))) return &task_ext_invalid;
    pid_t pid = __task_pid_nr_ns((struct task_struct *)task, PIDTYPE_PID, 0);
    pid_t tgid = __task_pid_nr_ns((struct task_struct *)task, PIDTYPE_TGID, 0);
    unsigned long stack_identity;
    if (kp_task_ext_identity((struct task_struct *)task, &stack_identity))
        return &task_ext_invalid;
    for (int i = 0; i < TASK_EXT_SLOT_NUM; i++) {
        struct task_struct *slot_task = READ_ONCE(task_ext_slots[i].task);
        if (slot_task != task) continue;
        /* Pair the publisher's pre-key barrier with an ordered read of the
         * extension identity after observing the published task pointer. */
        dsb(ish);
        pid_t slot_pid = READ_ONCE(task_ext_slots[i].ext.pid);
        pid_t slot_tgid = READ_ONCE(task_ext_slots[i].ext.tgid);
        unsigned long slot_stack = READ_ONCE(task_ext_slots[i].stack_identity);
        if (slot_pid == pid && slot_tgid == tgid && slot_stack == stack_identity)
            return &task_ext_slots[i].ext;
    }
    return &task_ext_invalid;
}

static struct task_ext *task_ext_create(struct task_struct *task, bool sel_allow, bool priv_sel_allow)
{
    if (unlikely(!task)) return NULL;
    pid_t pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
    pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    unsigned long stack_identity;
    if (kp_task_ext_identity(task, &stack_identity))
        return NULL;
    struct task_ext *ret = NULL;
    unsigned long flags = kp_private_spin_lock(&task_ext_lock);
    for (int i = 0; i < TASK_EXT_SLOT_NUM; i++) {
        if (READ_ONCE(task_ext_slots[i].task) == task &&
            READ_ONCE(task_ext_slots[i].ext.pid) == pid &&
            READ_ONCE(task_ext_slots[i].ext.tgid) == tgid &&
            READ_ONCE(task_ext_slots[i].stack_identity) == stack_identity) {
            ret = &task_ext_slots[i].ext;
            if (sel_allow) WRITE_ONCE(ret->sel_allow, true);
            if (priv_sel_allow) WRITE_ONCE(ret->priv_sel_allow, true);
            break;
        }
    }
    if (!ret) {
        for (int i = 0; i < TASK_EXT_SLOT_NUM; i++) {
            if (!READ_ONCE(task_ext_slots[i].task)) {
                ret = &task_ext_slots[i].ext;
                task_ext_reset(ret);
                ret->pid = pid;
                ret->tgid = tgid;
                WRITE_ONCE(task_ext_slots[i].stack_identity, stack_identity);
                WRITE_ONCE(ret->sel_allow, sel_allow);
                WRITE_ONCE(ret->priv_sel_allow, priv_sel_allow);
                dsb(ish);
                WRITE_ONCE(task_ext_slots[i].task, task);
                atomic_inc(&task_ext_active_count);
                break;
            }
        }
    }
    kp_private_spin_unlock(&task_ext_lock, flags);
    return ret;
}

struct task_ext *kf_task_ext_ensure(struct task_struct *task)
{
    if (unlikely(!task)) return &task_ext_invalid;
    struct task_ext *ext = kf_get_task_ext(task);
    if (task_ext_valid(ext)) return ext;
    return task_ext_create(task, false, false);
}


extern int (*vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);

void kp_debug_write(const char *fmt, ...)
{
    va_list va;
    char buf[192];
    int len;
    struct file *filp;
    loff_t off = 0;

    va_start(va, fmt);
    if (vsnprintf)
        len = vsnprintf(buf, sizeof(buf), fmt, va);
    else
        len = 0;
    va_end(va);
    if (len <= 0) return;

    filp = filp_open("/data/local/tmp/kp_dbg.log", O_WRONLY | O_APPEND, 0644);
    if (IS_ERR(filp)) return;
    kernel_write(filp, buf, len, &off);
    filp_close(filp, 0);
}

static int prepare_init_ext(struct task_struct *task)
{
    if (!task) return -EINVAL;
    struct task_ext *ext = task_ext_create(task, false, false);
    if (!ext) {
        logkfe("task_ext_create(init) FAILED\\n");
        return -ENOMEM;
    }
    dsb(ish);
    return 0;
}

static void prepare_task_ext(struct task_struct *new, struct task_struct *old)
{
    if (unlikely(!new || IS_ERR(new) || !old || IS_ERR(old))) return;
    struct task_ext *old_ext = get_task_ext(old);
    /*
     * Slots are only needed by the su lineage: a task outside it holds no ext
     * (invalid = shared task_ext_invalid), which is normal, not an error. Only
     * when a root task forks do we hand the child a slot so the bypass carries
     * over. This keeps the table from filling up with one entry per thread.
     */
    if (unlikely(!task_ext_valid(old_ext))) return;
    bool sel_allow = READ_ONCE(old_ext->sel_allow);
    bool priv_sel_allow = READ_ONCE(old_ext->priv_sel_allow);
    if (!(sel_allow || priv_sel_allow)) return;
    struct task_ext *new_ext = task_ext_create(new, sel_allow, priv_sel_allow);
    if (!new_ext) {
        logkfe("task_ext slot table full, skip\n");
        return;
    }
}

int task_ext_size = offsetof(struct task_ext, _magic);
KP_EXPORT_SYMBOL(task_ext_size);

static void after_copy_process(hook_fargs8_t *args, void *udata)
{
    struct task_struct *new = (struct task_struct *)args->ret;
    if (unlikely(!new || IS_ERR(new))) return;
    prepare_task_ext(new, current);
}

static void after_cgroup_post_fork(hook_fargs4_t *args, void *udata)
{
    struct task_struct *new = (struct task_struct *)args->arg0;
    if (unlikely(!new || IS_ERR(new))) return;
    prepare_task_ext(new, current);
}

int task_observer()
{
    int rc = 0;

    spin_lock_init(&task_ext_lock);
    rc = prepare_init_ext(init_task);
    if (rc) return rc;

    unsigned long copy_process_addr = patch_config->copy_process;
    if (copy_process_addr) {
        rc = hook_wrap8((void *)copy_process_addr, 0, after_copy_process, 0);
        log_boot("hook copy_process: %llx, rc: %d\\n", copy_process_addr, rc);
    }
    if (!copy_process_addr || rc) {
        unsigned long cgroup_post_fork_addr = patch_config->cgroup_post_fork;
        if (cgroup_post_fork_addr) {
            rc = hook_wrap4((void *)cgroup_post_fork_addr, 0, after_cgroup_post_fork, 0);
            log_boot("hook cgroup_post_fork: %llx, rc: %d\\n", cgroup_post_fork_addr, rc);
        } else if (!rc) {
            rc = HOOK_BAD_ADDRESS;
        }
    }


    return rc;
}
