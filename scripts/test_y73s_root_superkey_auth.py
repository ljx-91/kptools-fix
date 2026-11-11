#!/usr/bin/env python3
"""Compile and execute the real KPIMG auth_superkey() with the real SHA-256."""
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

    predata = (ROOT / "kernel/base/predata.c").read_text(encoding="utf-8")
    sha = (ROOT / "kernel/base/sha256.c").read_text(encoding="utf-8")
    auth = extract_function(predata, "int auth_superkey(")
    sha = sha.replace('#include "sha256.h"', "", 1)

    prefix = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sha256.h>

#define SUPER_KEY_LEN 64
#define ROOT_SUPER_KEY_HASH_LEN 32

static char *superkey;
static char *root_superkey;
static bool enable_root_key;
static bool root_superkey_is_set;

static size_t lib_strnlen(const char *s, size_t n) { return strnlen(s, n); }
static int lib_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static void reset_superkey(const char *key)
{
    memset(superkey, 0, SUPER_KEY_LEN);
    strncpy(superkey, key, SUPER_KEY_LEN - 1);
}
"""
    tests = r"""
int main(void)
{
    char generated[SUPER_KEY_LEN] = "abcdefghijklmnop";
    char root_hash[ROOT_SUPER_KEY_HASH_LEN] = {0};
    BYTE expected[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    const char *known = "testtest123";

    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)known, strlen(known));
    sha256_final(&ctx, expected);
    if (memcmp(expected, "\x62\x6a\xa6\x01\x00\xe3\x8a\x2b"
                        "\x0a\x8c\x9b\x35\x12\x11\x6b\xfb"
                        "\x3f\xf9\xdb\x5b\x98\x6b\x21\xb2"
                        "\x7c\x29\x89\xe0\x11\x62\x94\x35", 32)) {
        fprintf(stderr, "known SHA-256 fixture mismatch\n");
        return 1;
    }
    memcpy(root_hash, expected, sizeof(root_hash));

    superkey = generated;
    root_superkey = root_hash;
    root_superkey_is_set = true;
    enable_root_key = true;
    if (auth_superkey(known) != 0) {
        fprintf(stderr, "root SuperKey authentication failed\n");
        return 1;
    }
    if (strcmp(superkey, known) || enable_root_key) {
        fprintf(stderr, "root SuperKey was not migrated to active key\n");
        return 1;
    }
    puts("[PASS] Y73S reported -S testtest123 root verifier authenticates and migrates");

    if (auth_superkey(known) != 0 || auth_superkey("wrong-key") == 0) {
        fprintf(stderr, "post-migration direct key check failed\n");
        return 1;
    }
    puts("[PASS] migrated SuperKey accepts exact value and rejects wrong value");

    if (auth_superkey(NULL) == 0) {
        fprintf(stderr, "NULL key unexpectedly authenticated\n");
        return 1;
    }
    char unterminated[SUPER_KEY_LEN];
    memset(unterminated, 'A', sizeof(unterminated));
    if (auth_superkey(unterminated) == 0) {
        fprintf(stderr, "unterminated key unexpectedly authenticated\n");
        return 1;
    }
    puts("[PASS] NULL and unterminated key inputs fail closed");

    char plain[SUPER_KEY_LEN] = "plain-key";
    superkey = plain;
    root_superkey_is_set = false;
    enable_root_key = false;
    if (auth_superkey("plain-key") != 0 || auth_superkey("plain-key-extra") == 0) {
        fprintf(stderr, "plain embedded SuperKey exact-match check failed\n");
        return 1;
    }
    puts("[PASS] plain embedded SuperKey requires exact length and contents");
    return 0;
}
"""
    code = prefix + "\n" + auth + "\n" + sha + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-superkey-") as tmp:
        cfile = Path(tmp) / "superkey_auth.c"
        binary = Path(tmp) / "superkey_auth"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(ROOT / "kernel/include"), str(cfile),
                        "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] runtime root-SuperKey authentication fixture")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
