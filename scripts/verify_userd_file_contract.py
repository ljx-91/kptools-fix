#!/usr/bin/env python3
"""Fail-closed source checks for userd file and directory parsing."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def body(src, signature):
    start = src.find(signature)
    if start < 0:
        raise AssertionError(f"missing function {signature}")
    brace = src.find("{", start)
    depth = 0
    for pos in range(brace, len(src)):
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
            if depth == 0:
                return src[brace + 1:pos]
    raise AssertionError(f"unterminated function {signature}")


def need(pattern, src, message):
    if not re.search(pattern, src, re.S):
        raise AssertionError(message)


def main():
    src = (ROOT / "kernel/patch/android/userd.c").read_text(encoding="utf-8")
    reader = body(src, "static const void *kernel_read_file(")
    need(r"file_size\s*<\s*0.*?file_size\s*>\s*max_file_size", reader,
         "userd file reader must reject negative and oversized file lengths")
    need(r"vmalloc\(\(size_t\)file_size\s*\+\s*1\)", reader,
         "userd file allocation must use a validated size")
    need(r"kernel_read\([\s\S]*?\)\s*!=\s*file_size", reader,
         "userd file reader must reject short reads")
    need(r"\*len\s*=\s*file_size", reader,
         "userd must publish length only after a complete read")

    lookup = body(src, "static int lookup_package_list_uid(")
    need(r"!package_name\s*\|\|\s*!trusted_uid_out", lookup,
         "package lookup must validate required pointers before reading")
    need(r"kvfree\(content\)", lookup,
         "package lookup must free the file buffer on early errors")

    path_lookup = body(src, "static int find_trusted_manager_apk_path(")
    need(r"index\s*>=\s*\(int\)\(sizeof\(trusted_managers\)\s*/\s*sizeof\(trusted_managers\[0\]\)\)", path_lookup,
         "trusted-manager index must be bounded by the table")
    for sig in ("static bool apk_inner_actor(", "static int apk_inner_actor_int(",
                "static bool apk_outer_actor(", "static int apk_outer_actor_int("):
        actor = body(src, sig)
        need(r"namelen\s*<=\s*0.*?namelen\s*>\s*NAME_MAX", actor,
             "APK directory entry name length must be validated")

    print("[PASS] userd file reads enforce size and exact-read bounds")
    print("[PASS] package lookup validates pointers and frees buffers")
    print("[PASS] trusted manager table and directory names are bounded")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
