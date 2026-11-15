/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Read-only startup event probe for vivo Y73s / KernelPatch.
 * This module deliberately installs no hooks and changes no kernel state.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("y73s-boot-diagnostic");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KernelPatch Y73s audit");
KPM_DESCRIPTION("Read-only early startup event diagnostic");

static long diagnostic_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;

    pr_info("[Y73S-DIAG] init name=y73s-boot-diagnostic version=1.0.1\n");
    pr_info("[Y73S-DIAG] event=%s\n", event ? event : "(null)");
    pr_info("[Y73S-DIAG] args=%s\n", args ? args : "(null)");
    return 0;
}

static long diagnostic_exit(void *__user reserved)
{
    (void)reserved;
    return 0;
}

KPM_INIT(diagnostic_init);
KPM_EXIT(diagnostic_exit);
