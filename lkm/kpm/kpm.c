// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KPM supercall handlers. ABI matches kernel/patch/common/supercall.c
 * call_kpm_* and user/uapi/scdefs.h. Strings are copied from user space; the
 * loader works on kernel buffers.
 */
#include "kpm.h"

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "module.h"

#define KPM_LOAD_PATH_LEN 1024
#define KPM_NAME_LEN 32
#define KPM_CTL_ARGS_LEN 1024

/*
 * strncpy_from_user() returns dst_size when the source has no NUL in range.
 * In that case the destination is not a valid C string. Reject it explicitly
 * and terminate every accepted buffer before passing it to string consumers.
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
		dst[dst_size - 1] = '\0';
		return -ENAMETOOLONG;
	}
	dst[len] = '\0';
	return len;
}

long kp_kpm_load_sc(const char __user *upath, const char __user *uargs,
		    void __user *reserved)
{
	char path[KPM_LOAD_PATH_LEN];
	char *args = NULL;
	long pathlen, arglen = 0;
	long rc;

	pathlen = kp_copy_user_string(path, sizeof(path), upath);
	if (pathlen <= 0)
		return pathlen < 0 ? pathlen : -EINVAL;

	if (uargs) {
		args = kzalloc(KPM_ARGS_LEN, GFP_KERNEL);
		if (!args)
			return -ENOMEM;
		arglen = kp_copy_user_string(args, KPM_ARGS_LEN, uargs);
		if (arglen < 0) {
			kfree(args);
			return arglen;
		}
	}
	rc = kp_load_module_path(path, arglen > 0 ? args : NULL, reserved);
	kfree(args);
	return rc;
}

long kp_kpm_control_sc(const char __user *uname, const char __user *uctl_args,
		       char __user *out_msg, int outlen)
{
	char name[KPM_NAME_LEN];
	char *ctl_args;
	long namelen, arglen, rc;

	namelen = kp_copy_user_string(name, sizeof(name), uname);
	if (namelen <= 0)
		return namelen < 0 ? namelen : -EINVAL;
	if (!uctl_args)
		return -EINVAL;

	ctl_args = kzalloc(KPM_CTL_ARGS_LEN, GFP_KERNEL);
	if (!ctl_args)
		return -ENOMEM;
	arglen = kp_copy_user_string(ctl_args, KPM_CTL_ARGS_LEN, uctl_args);
	if (arglen < 0) {
		kfree(ctl_args);
		return arglen;
	}
	if (!arglen) {
		kfree(ctl_args);
		return -EINVAL;
	}
	rc = kp_module_control0(name, ctl_args, out_msg, outlen);
	kfree(ctl_args);
	return rc;
}

long kp_kpm_unload_sc(const char __user *uname, void __user *reserved)
{
	char name[KPM_NAME_LEN];
	long len = kp_copy_user_string(name, sizeof(name), uname);

	if (len <= 0)
		return len < 0 ? len : -EINVAL;
	return kp_unload_module(name, reserved);
}

long kp_kpm_nums_sc(void)
{
	return kp_get_module_nums();
}

long kp_kpm_list_sc(char __user *names, int len)
{
	char *buf;
	int sz, copy_len, rc;

	if (!names || len <= 0)
		return -EINVAL;
	buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	sz = kp_list_modules(buf, 4096);
	if (sz < 0) {
		kfree(buf);
		return sz;
	}
	if (sz > len) {
		kfree(buf);
		return -ENOBUFS;
	}
	copy_len = sz > 0 ? sz : 1;
	rc = copy_to_user(names, buf, copy_len) ? -EFAULT : sz;
	kfree(buf);
	return rc;
}

long kp_kpm_info_sc(const char __user *uname, char __user *out_info, int out_len)
{
	char name[KPM_NAME_LEN];
	char *buf;
	int len, sz, rc;

	if (!out_info || out_len <= 0)
		return -EINVAL;
	len = (int)kp_copy_user_string(name, sizeof(name), uname);
	if (len <= 0)
		return len < 0 ? len : -EINVAL;
	buf = kzalloc(2048, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	sz = kp_get_module_info(name, buf, 2048);
	if (sz < 0) {
		kfree(buf);
		return sz;
	}
	if (sz > out_len) {
		kfree(buf);
		return -ENOBUFS;
	}
	rc = copy_to_user(out_info, buf, sz) ? -EFAULT : sz;
	kfree(buf);
	return rc;
}
