#!/usr/bin/env python3
"""Execute the real six-register Y73S Linux 4.14 supercall handler."""
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
    source = (ROOT / "lkm/supercall/supercall.c").read_text(encoding="utf-8")
    original = extract_function(
        source, "static long kp_call_original_truncate_args("
    )
    handler = extract_function(
        source, "static long kp_supercall_handler_legacy("
    )
    # Host compiler does not implement Clang's CFI sanitizer attribute.
    original = original.replace('__attribute__((no_sanitize("cfi")))', "")
    prefix = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef unsigned int uid_t;
#define __user
#define SUPERCALL_HELLO 1
#define SUPERCALL_MAX 8
static uid_t test_uid;
static bool manager_allowed;
static bool su_allowed;
static int original_calls;
static long original_arg0, original_arg1;
static long original_result = -77;
static int dispatch_calls;
static unsigned long dispatch_args[5];
static long (*kp_orig_truncate_args)(long, long);

static int current_user_ns(void) { return 0; }
static uid_t current_uid(void) { return test_uid; }
static uid_t from_kuid(int ns, uid_t uid) { (void)ns; return uid; }
static bool kp_is_manager_uid(uid_t uid) { (void)uid; return manager_allowed; }
static bool kp_is_su_allow_uid(uid_t uid) { (void)uid; return su_allowed; }
static long original_truncate(long a0, long a1)
{
    original_calls++;
    original_arg0 = a0;
    original_arg1 = a1;
    return original_result;
}
static long kp_handle_supercall(long cmd, unsigned long a2, unsigned long a3,
                                unsigned long a4, unsigned long a5)
{
    dispatch_calls++;
    dispatch_args[0] = (unsigned long)cmd;
    dispatch_args[1] = a2;
    dispatch_args[2] = a3;
    dispatch_args[3] = a4;
    dispatch_args[4] = a5;
    return 0x123456;
}
static long kp_call_original_truncate_args(long a0, long a1)
{
    return kp_orig_truncate_args ? kp_orig_truncate_args(a0, a1) : -ENOSYS;
}
"""
    tests = r"""
int main(void)
{
    long rc;

    kp_orig_truncate_args = original_truncate;
    test_uid = 10001;
    manager_allowed = true;
    su_allowed = false;
    rc = kp_supercall_handler_legacy(0x1111, 0x10002, 0x22, 0x33, 0x44, 0x55);
    if (rc != 0x123456 || dispatch_calls != 1 || original_calls != 0 ||
        dispatch_args[0] != 2 || dispatch_args[1] != 0x22 ||
        dispatch_args[2] != 0x33 || dispatch_args[3] != 0x44 ||
        dispatch_args[4] != 0x55) {
        fprintf(stderr, "authorized supercall dispatch failed\n");
        return 1;
    }
    puts("[PASS] authorized 4.14 syscall ABI forwards x1-x5 correctly");

    manager_allowed = false;
    su_allowed = false;
    rc = kp_supercall_handler_legacy(0x1111, 0x10002, 1, 2, 3, 4);
    if (rc != original_result || original_calls != 1 || dispatch_calls != 1 ||
        original_arg0 != 0x1111 || original_arg1 != 0x10002) {
        fprintf(stderr, "unauthorized truncate passthrough failed\n");
        return 1;
    }
    puts("[PASS] unauthorized caller is passed to original SyS_truncate");

    manager_allowed = true;
    rc = kp_supercall_handler_legacy(0x1111, 0x1ffff, 1, 2, 3, 4);
    if (rc != original_result || original_calls != 2 || dispatch_calls != 1 ||
        original_arg0 != 0x1111 || original_arg1 != 0x1ffff) {
        fprintf(stderr, "invalid command passthrough failed\n");
        return 1;
    }
    puts("[PASS] invalid command is passed to original SyS_truncate");

    kp_orig_truncate_args = NULL;
    manager_allowed = false;
    su_allowed = false;
    rc = kp_supercall_handler_legacy(0x1111, 0x10002, 1, 2, 3, 4);
    if (rc != -ENOSYS) {
        fprintf(stderr, "missing original trampoline was not fail-closed\n");
        return 1;
    }
    puts("[PASS] missing original trampoline fails closed");
    return 0;
}
"""
    code = prefix + "\n" + original + "\n" + handler + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-414-supercall-") as tmp:
        cfile = Path(tmp) / "supercall_abi.c"
        binary = Path(tmp) / "supercall_abi"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] Y73S 4.14 supercall ABI fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
