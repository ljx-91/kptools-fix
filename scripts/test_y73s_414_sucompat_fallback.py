#!/usr/bin/env python3
"""Execute the real Y73S 4.14 prepare_binprm sucompat callbacks."""
from pathlib import Path
import shutil
import subprocess
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
    source = (ROOT / "lkm/supercall/sucompat_hook.c").read_text(encoding="utf-8")
    callbacks = "\n\n".join([
        extract_function(source, "static long kp_copy_user_string("),
        extract_function(source, "static const char *kp_get_supercmd_sctx("),
        extract_function(source, "static void kp_before_prepare_binprm("),
        extract_function(source, "static void kp_after_prepare_binprm("),
    ])
    prefix = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef unsigned int uid_t;
#define KP_SH_PATH "/system/bin/sh"
#define SH_PATH "/system/bin/sh"
#define SUPERCMD "/system/bin/truncate"
#define LEGACY_SU_PATH "/system/bin/su"
#define SU_PATH "/system/bin/kp"
#define SUPERCALL_SCONTEXT_LEN 128
#define O_RDONLY 0
#define O_NOFOLLOW 0x20000
#define IS_ERR(p) ((intptr_t)(p) < 0)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define _TIF_SECCOMP 0x10UL
#define __NR_execve 221
#define current ((void *)1)
#define __user

struct pt_regs { unsigned long regs[31]; int syscallno; };
static struct pt_regs test_regs;

struct file { int id; bool executable; };
struct cred { uid_t uid; };
struct linux_binprm {
    const char *filename;
    const char *interp;
    struct file *file;
    int argc;
    struct cred *cred;
};
typedef struct { uint64_t data0, data1, data2; } hook_local_t;
typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    uint64_t arg0, arg1, arg2, arg3;
} hook_fargs1_t;
struct thread_info { unsigned long flags; };
static struct thread_info ti = { .flags = _TIF_SECCOMP };
static struct file shell_file = { .id = 2, .executable = true };
static uid_t test_uid = 10001;
static bool allow_uid = true, manager_uid;
static bool fail_shell_open;
static int fput_calls, apply_calls;
static int apply_result;
static char last_sctx[128];

static int current_user_ns(void) { return 0; }
static uid_t current_uid(void) { return test_uid; }
static uid_t from_kuid(int ns, uid_t uid) { (void)ns; return uid; }
static bool kp_is_su_allow_uid(uid_t uid) { (void)uid; return allow_uid; }
static bool kp_is_manager_uid(uid_t uid) { (void)uid; return manager_uid; }
static const char *kp_su_get_path(void) { return SU_PATH; }
static const char *kp_default_sctx(uid_t uid, char *buf, size_t size)
{
    (void)uid;
    if (size) snprintf(buf, size, "%s", "u:r:magisk:s0");
    return buf;
}
static struct file *open_exec_stub(const char *path)
{
    if (strcmp(path, KP_SH_PATH) || fail_shell_open)
        return (struct file *)(intptr_t)-ENOENT;
    return &shell_file;
}
static struct file *(*kp_open_exec)(const char *name) = open_exec_stub;
static void fput(struct file *file) { (void)file; fput_calls++; }
static struct pt_regs *task_pt_regs(void *task) { (void)task; return &test_regs; }
static long copy_from_user(void *to, const void *from, size_t n)
{
    if (!to || !from) return (long)n;
    memcpy(to, from, n);
    return 0;
}
static long strncpy_from_user(char *to, const char *from, long n)
{
    long i;
    if (!to || !from || n <= 0) return -EFAULT;
    for (i = 0; i < n; i++) {
        to[i] = from[i];
        if (!from[i]) return i;
    }
    return n;
}
static int kp_apply_su_cred(struct cred **cred, uid_t uid, const char *sctx)
{
    apply_calls++;
    snprintf(last_sctx, sizeof(last_sctx), "%s", sctx ? sctx : "");
    if (apply_result) return apply_result;
    (*cred)->uid = uid;
    return 0;
}
#define logkw(...) ((void)0)
#define logki(...) ((void)0)
#define logke(...) ((void)0)
"""
    tests = r"""
int main(void)
{
    struct file old_file = { .id = 1 };
    struct cred cred = { .uid = 10001 };
    struct linux_binprm bprm = {
        .filename = SU_PATH, .interp = SU_PATH, .file = &old_file,
        .argc = 3, .cred = &cred
    };
    hook_fargs1_t args = { .arg0 = (uint64_t)(uintptr_t)&bprm };

    kp_before_prepare_binprm(&args, NULL);
    if (!args.local.data0 || bprm.file != &shell_file || !bprm.file->executable ||
        strcmp(bprm.filename, KP_SH_PATH) || strcmp(bprm.interp, KP_SH_PATH) ||
        bprm.argc != 3 || fput_calls != 1) {
        fprintf(stderr, "su exec redirect failed\n");
        return 1;
    }
    args.ret = 128;
    kp_after_prepare_binprm(&args, NULL);
    if (apply_calls != 1 || cred.uid != 0 || !(ti.flags & _TIF_SECCOMP) ||
        strcmp(last_sctx, "u:r:magisk:s0")) {
        fprintf(stderr, "su exec pending root cred failed\n");
        return 1;
    }
    puts("[PASS] allowed su exec prepares root SELinux cred while preserving seccomp until exec commit");

    {
        struct file old = { .id = 3 };
        struct cred c = { .uid = 10001 };
        struct linux_binprm b = {
            .filename = SUPERCMD, .interp = SUPERCMD, .file = &old,
            .argc = 4, .cred = &c
        };
        char arg0[] = "truncate", key[] = "key", z[] = "-Z";
        char ctx[] = "u:r:custom:s0";
        char *argv[] = { arg0, key, z, ctx, NULL };
        hook_fargs1_t a = { .arg0 = (uint64_t)(uintptr_t)&b };
        test_regs.syscallno = __NR_execve;
        test_regs.regs[1] = (unsigned long)(uintptr_t)argv;
        kp_before_prepare_binprm(&a, NULL);
        if (!a.local.data0 || b.file != &shell_file || b.argc != 1) {
            fprintf(stderr, "SUPERCMD argument stripping failed\n");
            return 1;
        }
        a.ret = 128;
        kp_after_prepare_binprm(&a, NULL);
        if (apply_calls != 2 || c.uid != 0 ||
            strcmp(last_sctx, "u:r:custom:s0")) {
            fprintf(stderr, "SUPERCMD root cred failed\n");
            return 1;
        }
    }
    puts("[PASS] SUPERCMD keeps argv[0] and strips the key/options");

    {
        struct file old = { .id = 4 };
        struct cred c = { .uid = 10001 };
        struct linux_binprm b = {
            .filename = SU_PATH, .interp = SU_PATH, .file = &old,
            .argc = 2, .cred = &c
        };
        hook_fargs1_t a = { .arg0 = (uint64_t)(uintptr_t)&b };
        allow_uid = false;
        kp_before_prepare_binprm(&a, NULL);
        a.ret = 128;
        kp_after_prepare_binprm(&a, NULL);
        if (a.local.data0 || b.file != &old || c.uid != 10001 ||
            apply_calls != 2) {
            fprintf(stderr, "unauthorized caller was modified\n");
            return 1;
        }
        allow_uid = true;
    }
    puts("[PASS] unauthorized caller is untouched");

    {
        struct file old = { .id = 5 };
        struct cred c = { .uid = 10001 };
        struct linux_binprm b = {
            .filename = SU_PATH, .interp = SU_PATH, .file = &old,
            .argc = 2, .cred = &c
        };
        hook_fargs1_t a = { .arg0 = (uint64_t)(uintptr_t)&b };
        fail_shell_open = true;
        kp_before_prepare_binprm(&a, NULL);
        a.ret = 128;
        kp_after_prepare_binprm(&a, NULL);
        if (a.local.data0 || b.file != &old || c.uid != 10001 ||
            apply_calls != 2) {
            fprintf(stderr, "failed shell open did not fail closed\n");
            return 1;
        }
        fail_shell_open = false;
    }
    puts("[PASS] missing shell file does not grant credentials");

    {
        struct file old = { .id = 6 };
        struct cred c = { .uid = 10001 };
        struct linux_binprm b = {
            .filename = SU_PATH, .interp = SU_PATH, .file = &old,
            .argc = 2, .cred = &c
        };
        hook_fargs1_t a = { .arg0 = (uint64_t)(uintptr_t)&b };
        kp_before_prepare_binprm(&a, NULL);
        a.ret = (uint64_t)(long)-ENOEXEC;
        kp_after_prepare_binprm(&a, NULL);
        if (apply_calls != 2 || c.uid != 10001) {
            fprintf(stderr, "failed prepare_binprm granted credentials\n");
            return 1;
        }
    }
    puts("[PASS] failed prepare_binprm never grants credentials");

    {
        struct file old = { .id = 7 };
        struct cred c = { .uid = 10001 };
        struct linux_binprm b = {
            .filename = SU_PATH, .interp = SU_PATH, .file = &old,
            .argc = 2, .cred = &c
        };
        hook_fargs1_t a = { .arg0 = (uint64_t)(uintptr_t)&b };
        kp_before_prepare_binprm(&a, NULL);
        a.ret = 128;
        apply_result = -ENOMEM;
        kp_after_prepare_binprm(&a, NULL);
        if ((long)a.ret != -ENOMEM || c.uid != 10001 || apply_calls != 3) {
            fprintf(stderr, "credential failure did not fail exec closed\n");
            return 1;
        }
    }
    puts("[PASS] pending-cred failure aborts the exec path");
    return 0;
}
"""
    code = prefix + "\n" + callbacks + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-414-sucompat-") as tmp:
        cfile = Path(tmp) / "sucompat_fallback.c"
        binary = Path(tmp) / "sucompat_fallback"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", str(cfile), "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] Y73S 4.14 prepare_binprm sucompat fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
