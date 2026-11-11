#!/usr/bin/env python3
"""Fail-closed Y73S syscall-45 target selection contract.

The Y73S 4.14.141 image has a short sys_truncate CFI alias adjacent to other
CFI entries. KPIMG must select the real SyS_truncate.cfi body when it needs an
inline hook and must not fall back to patching the short alias.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:pos]
    raise AssertionError(f"unterminated body: {signature}")


def before(source, first, second, message):
    a, b = source.find(first), source.find(second)
    if a < 0 or b < 0 or a >= b:
        raise AssertionError(message)


def main():
    syscall_c = read("kernel/patch/common/syscall.c")
    sysname_c = read("kernel/patch/common/sysname.c")
    kp_supercall = read("kernel/patch/common/supercall.c")
    lkm_supercall = read("lkm/supercall/supercall.c")
    hook_c = read("kernel/base/hook.c")
    lkm_init = read("lkm/core/init.c")
    resolver = function_body(syscall_c, "uintptr_t syscalln_name_addr(")
    branch_abs = function_body(hook_c, "int32_t branch_absolute(")
    relo_ldr = function_body(hook_c, "static __noinline hook_err_t relo_ldr(")
    branch_once = function_body(hook_c, "static uint64_t branch_func_addr_once(")
    hook_prepare = function_body(hook_c, "hook_err_t hook_prepare(")
    lkm_install = function_body(lkm_supercall, "static int kp_install_inline_supercall(")

    checks = {
        "Y73S-only syscall-45 inline path is gated to native no-wrapper kernels":
            "#if defined(KP_TARGET_Y73S)" in resolver and
            "!is_compat && !has_syscall_wrapper && nr == 45" in resolver,
        "Y73S syscall 45 resolves the verified implementation body":
            'kallsyms_lookup_name("SyS_truncate.cfi")' in resolver,
        "missing Y73S implementation symbol fails closed":
            "if (!y73s_truncate)\n            return 0;" in resolver,
        "Y73S implementation is cached before generic alias lookup":
            "syscall_name_table[nr].addr = y73s_truncate;" in resolver and
            resolver.index("return y73s_truncate;") < resolver.index("const char *name = 0;"),
        "generic syscall table's syscall 45 alias remains unchanged":
            '[45] = { "sys_truncate", 0 }' in sysname_c,
        "KPIMG supercall keeps the six-register legacy ABI":
            "hook_syscalln_override(__NR_supercall, 6, before, 0, 0)" in kp_supercall,
        "LKM 4.14 path selects the same implementation body":
            '"SyS_truncate.cfi"' in lkm_supercall and
            "KP_SUPERCALL_BACKEND_INLINE_ARGS" in lkm_supercall,
        "Y73S profile define is wired into the KPIMG build":
            "ifdef Y73S_TARGET" in read("kernel/Makefile") and
            "-DKP_TARGET_Y73S=1" in read("kernel/Makefile"),
        "KPIMG inline branch uses a literal-backed four-word absolute stub":
            "buf[0] = 0x58000051; // LDR X17, #8" in branch_abs and
            "buf[1] = 0xd61f0220; // BR X17" in branch_abs and
            "buf[2] = addr & 0xFFFFFFFF;" in branch_abs,
        "LKM relocation rejects a literal that points into the overwritten prologue":
            "is_in_tramp(hook, addr) && type != INST_PRFM_LIT" in relo_ldr and
            "return -HOOK_BAD_RELO;" in relo_ldr,
        "LKM aborts initialization when its inline supercall cannot be installed":
            "rc = kp_supercall_install();" in lkm_init and
            "if (rc)\n\t\tgoto err_unwind;" in lkm_init,
        "KPIMG-patched syscall body makes standalone LKM reject rather than stack a second hook":
            "uint64_t ret = addr;" in branch_once and
            "(inst & MASK_B) == INST_B" in branch_once and
            "inst == ARM64_BTI_C" in branch_once and
            "0x58000051; // LDR X17, #8" in branch_abs and
            "return 4;" in branch_abs and
            "branch_absolute(hook->tramp_insts, hook->replace_addr)" in hook_prepare and
            "for (int i = 0; i < hook->tramp_insts_num; i++)" in hook_prepare and
            "if (relo_res) {\n            return -HOOK_BAD_RELO;" in hook_prepare and
            "is_in_tramp(hook, addr) && type != INST_PRFM_LIT" in relo_ldr and
            "return -HOOK_BAD_RELO;" in relo_ldr and
            "hook_rc = hook((void *)addr, handler, backup);" in lkm_install and
            "return -EIO;" in lkm_install and
            "if (rc)\n\t\tgoto err_unwind;" in lkm_init,

    }

    for label, ok in checks.items():
        print(("PASS" if ok else "FAIL") + ": " + label)
    if not all(checks.values()):
        raise SystemExit(1)
    print(f"Y73S syscall-45 contract: {len(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    main()
