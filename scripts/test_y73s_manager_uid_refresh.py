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
static int trusted_manager_refresh_lock;
static unsigned int trusted_manager_refresh_generation;
static uid_t trusted_manager_uid = TRUSTED_MANAGER_UID_INVALID;
static int refresh_rc;
static uid_t refresh_uid;
static int lock_depth;
static int supersede_during_scan;
static int saw_invalid_before_scan;
static void mock_lock(int *lock, unsigned long *flags) {
    *flags = 0;
    if (*lock || lock_depth++) __builtin_trap();
    *lock = 1;
}
static void mock_unlock(int *lock, unsigned long flags) {
    (void)flags;
    if (!*lock || --lock_depth) __builtin_trap();
    *lock = 0;
}
#define spin_lock_irqsave(lock, flags) mock_lock((lock), &(flags))
#define spin_unlock_irqrestore(lock, flags) mock_unlock((lock), (flags))
static int refresh_trusted_manager_uid_from_packages_list(uid_t *out, int use_tmp)
{
    (void)use_tmp;
    saw_invalid_before_scan = trusted_manager_uid == TRUSTED_MANAGER_UID_INVALID;
    if (supersede_during_scan) ++trusted_manager_refresh_generation;
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
    supersede_during_scan = 0;
    saw_invalid_before_scan = 0;
    rc = refresh_trusted_manager_state_from_packages_list(0);
    if (rc || trusted_manager_uid != 10088 || !saw_invalid_before_scan ||
        lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "successful refresh failed to replace stale UID safely
");
        return 1;
    }
    puts("[PASS] successful refresh replaces stale UID");

    trusted_manager_uid = 10088;
    refresh_rc = -ENOENT;
    saw_invalid_before_scan = 0;
    rc = refresh_trusted_manager_state_from_packages_list(1);
    if (rc != -ENOENT || trusted_manager_uid != TRUSTED_MANAGER_UID_INVALID ||
        !saw_invalid_before_scan || lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "failed refresh retained stale Manager UID or leaked lock
");
        return 1;
    }
    puts("[PASS] failed refresh revokes stale UID");

    trusted_manager_uid = 10088;
    refresh_rc = 0;
    supersede_during_scan = 1;
    rc = refresh_trusted_manager_state_from_packages_list(0);
    if (rc != -EAGAIN || trusted_manager_uid != TRUSTED_MANAGER_UID_INVALID ||
        lock_depth || trusted_manager_refresh_lock) {
        fprintf(stderr, "superseded scan published stale UID or leaked lock
");
        return 1;
    }
    puts("[PASS] superseded scan cannot publish stale UID");
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
