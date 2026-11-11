#!/usr/bin/env python3
"""Fail-closed source checks for the Vivo Y73s 4.14.141 CFI slowpath hook."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def body(source: str, signature: str) -> str:
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


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)
    print("[PASS] " + message)


def main() -> None:
    source = (ROOT / "kernel/patch/common/secpass.c").read_text(encoding="utf-8")
    fn = body(source, "int bypass_kcfi()")
    slow_cb = body(source, "static void replace__cfi_slowpath(")
    report_cb = body(source, "static enum bug_trap_type replace_report_cfi_failure(")

    require("kallsyms_lookup_name(\"__cfi_slowpath_diag\")" in fn and
            "kallsyms_lookup_name(\"__cfi_slowpath\")" in fn,
            "runtime resolver prefers diagnostic slowpath and falls back to the legacy 4.14 slowpath")
    require("if (!backup__cfi_slowpath)" in fn and
            "cfi_slowpath_hooked = true;" in fn,
            "slowpath counts as installed only after hook success and a non-null original trampoline")
    require("if (!cfi_slowpath_hooked)" in fn and
            "rc = -ENOSYS;" in fn,
            "Y73S refuses to mark CFI ready when the required 4.14 slowpath is absent")
    require(fn.rfind("cfi_bypass = cfi_slowpath_hooked || report_cfi_failure_hooked;") >
            fn.find("if (!cfi_slowpath_hooked)"),
            "CFI-ready state is published only after the Y73S slowpath gate")
    require("if (!backup__cfi_slowpath) __builtin_trap();" in slow_cb,
            "slowpath callback cannot make a null indirect call")
    require("if (!target || !backup_report_cfi_failure)" in report_cb,
            "optional report callback validates both target and original trampoline")
    require("report_cfi_failure_hooked = true;" in fn,
            "newer report helper is tracked separately and cannot substitute for Y73S slowpath")
    print("[PASS] Y73S CFI slowpath contract")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        raise SystemExit(1)
