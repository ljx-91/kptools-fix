#!/usr/bin/env python3
"""Audit the APatch/KPIMG root-SuperKey hash path and bounded key input."""
from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def body(source, signature):
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


def need(ok, message):
    if not ok:
        raise AssertionError(message)
    print("[PASS] " + message)


def main():
    predata = read("kernel/base/predata.c")
    auth = body(predata, "int auth_superkey(")
    init = body(predata, "void predata_init(")
    patch = read("tools/patch.c")
    patch_buf = body(patch, "int patch_update_img_buf(")
    supercall = read("kernel/patch/common/supercall.c")
    before = body(supercall, "static void before(")

    need("if (!key || !superkey)" in auth,
         "SuperKey verifier rejects NULL input and missing preset")
    need("key_len = lib_strnlen(key, SUPER_KEY_LEN);" in auth and
         "if (key_len >= SUPER_KEY_LEN) goto out;" in auth,
         "SuperKey verifier rejects unterminated/overlong input")
    need("preset_len = lib_strnlen(superkey, SUPER_KEY_LEN);" in auth and
         "rc = key_len != preset_len;" in auth,
         "direct SuperKey comparison requires exact string length")
    need("if (!enable_root_key || !root_superkey_is_set || !root_superkey) goto out;" in auth,
         "root-hash fallback requires explicit root-key mode and a populated verifier")
    need("sha256_update(&ctx, (const BYTE *)key, key_len);" in auth and
         "lib_memcmp(root_superkey, hash, len)" in auth,
         "runtime root-key verification hashes the bounded input with SHA-256")
    need("if (!superkey_is_user_set)" in init and
         "enable_root_key = true;" in init and
         "root_superkey_is_set = *(uint64_t *)root_superkey;" in init,
         "root-key mode enables verifier fallback when no plain key is embedded")

    need("sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));" in patch_buf and
         "memcpy(setup->root_superkey, buf, len);" in patch_buf,
         "kptools -S hashes the supplied key into the embedded root verifier")
    need("syscall_argn(args, 0)" in before and
         "compat_strncpy_from_user(key, key_user, MAX_KEY_LEN)" in before and
         "is_authed = !auth_superkey(key);" in before,
         "supercall authenticates the bounded first syscall argument")

    known = hashlib.sha256(b"testtest123").hexdigest()
    need(known == "626aa60100e38a2b0a8c9b3512116bfb3ff9db5b986b21b27c2989e011629435",
         "reported Y73s -S testtest123 verifier matches SHA-256 exactly")
    need(re.search(r"if \(!rc && first_time\).*?reset_superkey\(key\).*?enable_root_key = false;",
                   auth, re.S) is not None,
         "first successful root-key authentication migrates to the active SuperKey")

    print("[PASS] APatch root-SuperKey source contract complete")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
