#!/usr/bin/env python3
"""Regression checks for bounded user strings in LKM KPM supercalls."""
from pathlib import Path

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


kpm = read("lkm/kpm/kpm.c")
dispatch = read("lkm/supercall/dispatch.c")
copy = body(kpm, "static long kp_copy_user_string(")

checks = {
    "bounded copy rejects missing source and invalid destination":
        "!src" in copy and "!dst_size" in copy and "return -EINVAL;" in copy,
    "bounded copy rejects strings without an in-range NUL":
        "(size_t)len >= dst_size" in copy and "return -ENAMETOOLONG;" in copy,
    "accepted strings are explicitly terminated":
        "dst[len] = '\\0';" in copy,
    "KPM path uses the bounded string helper":
        "kp_copy_user_string(path, sizeof(path), upath)" in
        body(kpm, "long kp_kpm_load_sc("),
    "optional KPM args are copied only when supplied and checked":
        "if (uargs)" in body(kpm, "long kp_kpm_load_sc(") and
        "kp_copy_user_string(args, KPM_ARGS_LEN, uargs)" in
        body(kpm, "long kp_kpm_load_sc(") and "if (arglen < 0)" in
        body(kpm, "long kp_kpm_load_sc("),
    "KPM control name and args are bounded and non-empty":
        "kp_copy_user_string(name, sizeof(name), uname)" in
        body(kpm, "long kp_kpm_control_sc(") and
        "kp_copy_user_string(ctl_args, KPM_CTL_ARGS_LEN, uctl_args)" in
        body(kpm, "long kp_kpm_control_sc(") and "if (!arglen)" in
        body(kpm, "long kp_kpm_control_sc("),
    "unload and info names use bounded copies":
        "kp_copy_user_string(name, sizeof(name), uname)" in
        body(kpm, "long kp_kpm_unload_sc(") and
        "kp_copy_user_string(name, sizeof(name), uname)" in
        body(kpm, "long kp_kpm_info_sc("),
    "no unchecked strncpy_from_user remains in KPM handlers":
        kpm.count("strncpy_from_user(") == 1,
    "feature-control name rejects overlong user input":
        "(size_t)len >= sizeof(name)" in body(dispatch, "long kp_control_feature_sc(") and
        "return -ENAMETOOLONG;" in body(dispatch, "long kp_control_feature_sc(") and
        "name[len] = '\\0';" in body(dispatch, "long kp_control_feature_sc("),
    "KPM list and info validate output buffers":
        "!names || len <= 0" in body(kpm, "long kp_kpm_list_sc(") and
        "!out_info || out_len <= 0" in body(kpm, "long kp_kpm_info_sc("),
}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
