#!/usr/bin/env python3
"""Compile and execute real Manager UID refresh, read, and rename-hook helpers."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def extract_function(source, signature):
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise RuntimeError(f"unterminated function: {signature}")


def main():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("no host C compiler")
    source = (ROOT / "kernel/patch/android/userd.c").read_text(encoding="utf-8")
    signatures = [
        "static int refresh_trusted_manager_state_from_packages_list(",
        "int is_trusted_manager_uid_android(uid_t uid)",
        "uid_t get_trusted_manager_uid(void)",
        "static void before_sys_renameat2(hook_fargs5_t *args, void *udata)",
        "static void after_sys_renameat2(hook_fargs5_t *args, void *udata)",
    ]
    functions = [extract_function(source, signature) for signature in signatures]
    prefix = r"""
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
typedef unsigned int uid_t;
#define TRUSTED_MANAGER_UID_INVALID ((uid_t)-1)
#define ANDROID_PACKAGES_LIST_PATH "/data/system/packages.list"
#define ANDROID_PACKAGES_LIST_TMP_PATH "/data/system/packages.list.tmp"
#define __user
typedef struct {
    uint64_t arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7;
    struct { uint64_t data0, data1, data2, data3, data4, data5, data6, data7; } local;
    uint64_t ret;
} hook_fargs5_t;
static int trusted_manager_refresh_lock;
static unsigned int trusted_manager_refresh_generation;
static uid_t trusted_manager_uid = TRUSTED_MANAGER_UID_INVALID;
static int refresh_rc;
static uid_t refresh_uid;
static int lock_depth;
static int supersede_during_scan;
static int saw_invalid_before_scan;
static int refresh_calls;
static int last_use_tmp;
static unsigned long mock_lock(int *lock)
{
    if (*lock || lock_depth++) __builtin_trap();
    *lock = 1;
    return 0;
}
static void mock_unlock(int *lock, unsigned long flags)
{
    (void)flags;
    if (!*lock || --lock_depth) __builtin_trap();
    *lock = 0;
}
#define spin_lock_irqsave(lock) mock_lock((lock))
#define spin_unlock_irqrestore(lock, flags) mock_unlock((lock), (flags))
static long compat_strncpy_from_user(char *dst, const char *src, size_t size)
{
    size_t i;
    if (!src) return -EFAULT;
    for (i = 0; i < size; ++i) {
        dst[i] = src[i];
        if (!src[i]) return (long)i;
    }
    return (long)size;
}
static int refresh_trusted_manager_uid_from_packages_list(uid_t *out, int use_tmp)
{
    ++refresh_calls;
    last_use_tmp = use_tmp;
    saw_invalid_before_scan = trusted_manager_uid == TRUSTED_MANAGER_UID_INVALID;
    if (lock_depth || trusted_manager_refresh_lock) __builtin_trap();
    if (supersede_during_scan) ++trusted_manager_refresh_generation;
    if (refresh_rc) return refresh_rc;
    *out = refresh_uid;
    return 0;
}
#define log_boot(...) ((void)0)
#define KP_EXPORT_SYMBOL(symbol)
"""
    tests = r"""
int main(void)
{
    int rc;
    trusted_manager_uid = 10042;
    refresh_uid = 10088;
    refresh_rc = 0;
    supersede_during_scan = 0;
    saw_invalid_before_scan = 0;
    rc = refresh_trusted_manager_state_from_packages_list(0);
    if (rc || trusted_manager_uid != 10088 || !saw_invalid_before_scan ||
        lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "successful refresh failed to replace stale UID safely\n");
        return 1;
    }
    puts("[PASS] successful refresh replaces stale UID");

    trusted_manager_uid = 10088;
    refresh_rc = -ENOENT;
    saw_invalid_before_scan = 0;
    rc = refresh_trusted_manager_state_from_packages_list(1);
    if (rc != -ENOENT || trusted_manager_uid != TRUSTED_MANAGER_UID_INVALID ||
        !saw_invalid_before_scan || lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "failed refresh retained stale Manager UID or leaked lock\n");
        return 1;
    }
    puts("[PASS] failed refresh revokes stale UID");

    trusted_manager_uid = 10088;
    refresh_rc = 0;
    supersede_during_scan = 1;
    rc = refresh_trusted_manager_state_from_packages_list(0);
    if (rc != -EAGAIN || trusted_manager_uid != TRUSTED_MANAGER_UID_INVALID ||
        lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "superseded scan published stale UID or leaked lock\n");
        return 1;
    }
    supersede_during_scan = 0;
    puts("[PASS] superseded scan cannot publish stale UID");

    trusted_manager_uid = 12345;
    if (!is_trusted_manager_uid_android(12345) ||
        is_trusted_manager_uid_android(12346) ||
        get_trusted_manager_uid() != 12345 ||
        lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "exported UID readers failed or leaked lock\n");
        return 1;
    }
    puts("[PASS] exported UID readers synchronize with publication");

    {
        hook_fargs5_t args = { 0 };
        refresh_calls = 0;
        refresh_rc = 0;
        refresh_uid = 20456;
        trusted_manager_uid = 20400;
        args.arg1 = (uint64_t)(uintptr_t)"/data/system/packages.list.tmp";
        args.arg3 = (uint64_t)(uintptr_t)"/data/system/packages.list";
        args.arg4 = 0;
        before_sys_renameat2(&args, NULL);
        args.ret = 0;
        after_sys_renameat2(&args, NULL);
        if (refresh_calls != 1 || last_use_tmp != 0 || trusted_manager_uid != 20456) {
            fprintf(stderr, "successful committed rename did not refresh final packages.list\n");
            return 1;
        }
        puts("[PASS] exact successful packages.list rename refreshes committed file");
    }

    {
        hook_fargs5_t args = { 0 };
        refresh_calls = 0;
        args.arg1 = (uint64_t)(uintptr_t)"/data/system/packages.list.tmp";
        args.arg3 = (uint64_t)(uintptr_t)"/data/system/packages.list";
        args.arg4 = 0;
        before_sys_renameat2(&args, NULL);
        args.ret = (uint64_t)-EIO;
        after_sys_renameat2(&args, NULL);
        if (refresh_calls) {
            fprintf(stderr, "failed rename incorrectly refreshed Manager UID\n");
            return 1;
        }
        puts("[PASS] failed packages.list rename never refreshes trust");
    }

    {
        hook_fargs5_t args = { 0 };
        refresh_calls = 0;
        args.arg1 = (uint64_t)(uintptr_t)"/data/system/packages.list.tmp";
        args.arg3 = (uint64_t)(uintptr_t)"/data/system/other.list";
        args.arg4 = 0;
        before_sys_renameat2(&args, NULL);
        args.ret = 0;
        after_sys_renameat2(&args, NULL);
        if (refresh_calls) {
            fprintf(stderr, "unrelated rename incorrectly refreshed Manager UID\n");
            return 1;
        }
        puts("[PASS] unrelated rename does not refresh Manager UID");
    }

    {
        hook_fargs5_t args = { 0 };
        refresh_calls = 0;
        args.arg1 = (uint64_t)(uintptr_t)"/data/system/packages.list.tmp";
        args.arg3 = (uint64_t)(uintptr_t)"/data/system/packages.list";
        args.arg4 = 2;
        before_sys_renameat2(&args, NULL);
        args.ret = 0;
        after_sys_renameat2(&args, NULL);
        if (refresh_calls) {
            fprintf(stderr, "flagged rename incorrectly refreshed Manager UID\n");
            return 1;
        }
        puts("[PASS] flagged rename variants are ignored");
    }
    return 0;
}
"""
    code = prefix + "\n" + "\n".join(functions) + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-manager-refresh-") as tmp:
        cfile = Path(tmp) / "manager_refresh.c"
        binary = Path(tmp) / "manager_refresh"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] runtime trusted Manager UID refresh fixture")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
