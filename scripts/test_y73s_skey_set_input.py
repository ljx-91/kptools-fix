#!/usr/bin/env python3
"""Compile and exercise the real KPIMG call_skey_set() input boundary."""
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
    source = (ROOT / "kernel/patch/common/supercall.c").read_text(encoding="utf-8")
    function = extract_function(source, "static long call_skey_set(")
    prefix = r"""
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define __user
#define SUPER_KEY_LEN 64
#define EINVAL 22
#define E2BIG 7
#define EFAULT 14
static const char *user_source;
static const char *committed_source;
static char committed[SUPER_KEY_LEN] = "unchanged";
static long compat_strncpy_from_user(char *dst, const char *src, size_t size)
{
    if (!src || src == (const char *)-1) return -EFAULT;
    size_t n = strnlen(src, size);
    if (n == size) return (long)size;
    memcpy(dst, src, n + 1);
    return (long)n;
}
static void reset_superkey(const char *key)
{
    committed_source = key;
    strncpy(committed, key, sizeof(committed) - 1);
    committed[sizeof(committed) - 1] = 0;
}
"""
    tests = r"""
int main(void)
{
    char valid[] = "new-super-key";
    user_source = valid;
    if (call_skey_set(valid) != 0 || strcmp(committed, valid) ||
        committed_source == user_source) {
        fprintf(stderr, "valid key was not committed from the bounded kernel copy\n");
        return 1;
    }
    puts("[PASS] valid SuperKey update commits the kernel copy");

    strcpy(committed, "unchanged");
    committed_source = 0;
    if (call_skey_set((char *)-1) != -EFAULT ||
        strcmp(committed, "unchanged") || committed_source) {
        fprintf(stderr, "copy fault modified the active SuperKey\n");
        return 1;
    }
    puts("[PASS] user-copy fault leaves active SuperKey unchanged");

    if (call_skey_set("") != -EINVAL || strcmp(committed, "unchanged")) {
        fprintf(stderr, "empty key was accepted\n");
        return 1;
    }
    puts("[PASS] empty SuperKey is rejected");

    char oversized[SUPER_KEY_LEN];
    memset(oversized, 'X', sizeof(oversized));
    if (call_skey_set(oversized) != -E2BIG || strcmp(committed, "unchanged")) {
        fprintf(stderr, "unterminated oversized key was accepted\n");
        return 1;
    }
    puts("[PASS] unterminated oversized SuperKey is rejected");
    return 0;
}
"""
    code = prefix + "\n" + function + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-skey-set-") as tmp:
        cfile = Path(tmp) / "skey_set.c"
        binary = Path(tmp) / "skey_set"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] runtime SuperKey update input fixture")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
