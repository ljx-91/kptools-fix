#!/usr/bin/env python3
"""Guard LKM manager identity, syscall publication order and KPM auth boundary."""
from pathlib import Path
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


def require(ok, message):
    if not ok:
        raise AssertionError(message)
    print("[PASS] " + message)


def main():
    sc = read("lkm/supercall/supercall.c")
    manager_only = body(sc, "static bool kp_supercall_manager_only(")
    kpm_cmds = (
        "SUPERCALL_KPM_LOAD", "SUPERCALL_KPM_UNLOAD",
        "SUPERCALL_KPM_CONTROL", "SUPERCALL_KPM_NUMS",
        "SUPERCALL_KPM_LIST", "SUPERCALL_KPM_INFO",
    )
    for cmd in kpm_cmds:
        require(cmd in manager_only, f"{cmd} is restricted to trusted manager")

    regs = body(sc, "static long kp_supercall_handler(const struct pt_regs *regs)")
    require("bool is_manager = kp_is_manager_uid(uid);" in regs and
            "bool is_allowed = kp_is_su_allow_uid(uid);" in regs,
            "pt_regs backend distinguishes manager from SU allowlist")
    require("kp_supercall_manager_only(cmd) && !is_manager" in regs and
            "return -EPERM;" in regs,
            "pt_regs backend rejects KPM commands from non-manager SU apps")
    require("if (!is_manager && !is_allowed)" in regs and
            "kp_orig_truncate_regs(regs)" in regs,
            "untrusted pt_regs callers retain original truncate behavior")

    legacy = body(sc, "static long kp_supercall_handler_legacy(")
    require("kp_supercall_manager_only(cmd) && !is_manager" in legacy and
            "return -EPERM;" in legacy,
            "legacy 4.14 backend enforces identical manager-only KPM policy")
    require("if (!is_manager && !is_allowed)" in legacy and
            "kp_call_original_truncate_args(arg0, arg1)" in legacy,
            "untrusted legacy callers retain original truncate behavior")

    init = body(read("lkm/core/init.c"), "int __init kernelpatch_init(void)")
    manager_pos = init.find("kp_manager_init();")
    rename_pos = init.find("hook_rename_lsm();")
    publish_pos = init.find("kp_supercall_install();")
    require(manager_pos >= 0 and rename_pos > manager_pos and
            publish_pos > rename_pos,
            "manager scan and packages.list refresh hook precede syscall publication")
    unwind = init.split("err_unwind:", 1)[1]
    require("BUG_ON(hook_rename_lsm_exit());" in unwind,
            "init failure removes manager refresh hook before module image release")

    manager = read("lkm/manager/manager.c")
    apk = read("lkm/manager/apk_sign.c")
    require('"/data/app"' in manager and '"/data/system/packages.list"' in manager,
            "manager identity derives from installed APK and Android packages.list")
    require("kp_manager_apk_match(path)" in manager and
            "kp_lookup_package_uid(pkg, use_tmp)" in manager,
            "manager UID is crowned only after trusted APK certificate match")
    require("O_NOFOLLOW" in apk and "v2_valid" in apk and
            "v3_blocks || v31_blocks" in apk,
            "APK trust parser uses bounded no-follow reads and rejects unsupported signature combinations")

    print("[PASS] LKM manager authentication contract complete")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
