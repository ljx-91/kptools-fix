#!/usr/bin/env python3
"""Compile and execute the real trusted Manager UID refresh helper."""
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
    function = extract_function(
        source, "static int refresh_trusted_manager_state_from_packages_list("
    )
    prefix = r"""
#include <stdio.h>
#include <errno.h>
typedef unsigned int uid_t;
#define TRUSTED_MANAGER_UID_INVALID ((uid_t)-1)
#define DEFINE_MUTEX(name) int name
static uid_t trusted_manager_uid = TRUSTED_MANAGER_UID_INVALID;
static int refresh_rc;
static uid_t refresh_uid;
static int lock_depth;
static int saw_invalid_before_scan;
static void mutex_lock(int *lock) { (void)lock; if (lock_depth++) __builtin_trap(); }
static void mutex_unlock(int *lock) { (void)lock; if (--lock_depth) __builtin_trap(); }
static int refresh_trusted_manager_uid_from_packages_list(uid_t *out, int use_tmp)
{
    (void)use_tmp;
    saw_invalid_before_scan = trusted_manager_uid == TRUSTED_MANAGER_UID_INVALID;
    if (refresh_rc) return refresh_rc;
    *out = refresh_uid;
    return 0;
}
#define log_boot(...) ((void)0)
"""
    tests = r"""
int main(void)
{
    int rc;
    trusted_manager_uid = 10042;
    refresh_uid = 10088;
    refresh_rc = 0;
    saw_invalid_before_scan = 0;
    rc = refresh_trusted_manager_state_from_packages_list(0);
    if (rc || trusted_manager_uid != 10088 || !saw_invalid_before_scan || lock_depth) {
        fprintf(stderr, "successful refresh failed to replace stale UID under lock\n");
        return 1;
    }
    puts("[PASS] successful refresh replaces the UID only after clearing old trust");

    trusted_manager_uid = 10088;
    refresh_rc = -ENOENT;
    saw_invalid_before_scan = 0;
    rc = refresh_trusted_manager_state_from_packages_list(1);
    if (rc != -ENOENT || trusted_manager_uid != TRUSTED_MANAGER_UID_INVALID ||
        !saw_invalid_before_scan || lock_depth) {
        fprintf(stderr, "failed refresh retained stale Manager UID\n");
        return 1;
    }
    puts("[PASS] failed refresh revokes stale Manager UID and releases lock");
    return 0;
}
"""
    code = prefix + "\n" + function + "\n" + tests
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
