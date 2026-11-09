/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch LKM common definitions: version and logging.
 */
#ifndef _KP_LKM_H_
#define _KP_LKM_H_

#include <linux/printk.h>
#include <linux/version.h>
#include <asm/pgtable.h>

/*
 * ARM64 kernels before v5.8 do not expose the generic p4d layer in
 * asm/pgtable-types.h. On these kernels the level is folded: the next
 * directory is reached directly from the PGD. The LKM permission walkers
 * use the modern pgd -> p4d -> pud spelling, so provide the folded bridge.
 * Keep this version-gated; newer ARM64 headers define the real p4d_t API.
 */
#if defined(CONFIG_ARM64) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
typedef pgd_t p4d_t;
#define p4d_offset(pgd, address) ((p4d_t *)(pgd))
#define p4d_none(p4d) (0)
#define p4d_bad(p4d) (0)
#endif

/* Version. Kbuild reads the repo-root ../version file and passes the three
 * numbers in as -DKP_LKM_MAJOR/MINOR/PATCH, so this header can never drift
 * from it. The #ifndef fallbacks keep the file buildable standalone. */
#ifndef KP_LKM_MAJOR
#define KP_LKM_MAJOR 0
#endif
#ifndef KP_LKM_MINOR
#define KP_LKM_MINOR 13
#endif
#ifndef KP_LKM_PATCH
#define KP_LKM_PATCH 3
#endif
#define KP_LKM_VERSION_CODE ((KP_LKM_MAJOR << 16) | (KP_LKM_MINOR << 8) | KP_LKM_PATCH)
#define kpver KP_LKM_VERSION_CODE

/* "x.y.z" for MODULE_VERSION. */
#define KP_LKM_STR2(x) #x
#define KP_LKM_STR(x) KP_LKM_STR2(x)
#define KP_LKM_VERSION_STRING \
	KP_LKM_STR(KP_LKM_MAJOR) "." KP_LKM_STR(KP_LKM_MINOR) "." KP_LKM_STR(KP_LKM_PATCH)

/* kver mirrors KP: major<<16 | minor<<8 | patch. */
static inline long kp_kver(void)
{
	return (long)LINUX_VERSION_CODE;
}

#define KPLKM_TAG "kernelpatch-lkm"
#define logki(fmt, ...) pr_info(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logkw(fmt, ...) pr_warn(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logkd(fmt, ...) pr_debug(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) logki(fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) logke(fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) logkd(fmt, ##__VA_ARGS__)

#endif /* _KP_LKM_H_ */
