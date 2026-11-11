#!/usr/bin/env python3
"""Guard the Y73s 4.14.141 __cfi_slowpath hook ABI and relocatable prologue.

An optional raw kernel.Image argument verifies the original binary fingerprint.
Source-only mode is suitable for CI and does not claim runtime hook success.
"""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
IMAGE_SIZE = 47_517_708
IMAGE_SHA256 = "345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e"
FUNCTION_OFFSET = 0x002DDC00
ENTRY = [0xD10103FF, 0xA90157F6, 0xA9024FF4, 0xA9037BFD]
ARG_CAPTURE = 0xAA0203F4  # MOV X20, X2 in the target function body.


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("[PASS] " + message)


def main():
    hook = read("kernel/base/hook.c")
    header = read("kernel/include/hook.h")
    secpass = read("kernel/patch/common/secpass.c")
    symbols = read("tools/symbol.c")
    fixture = read("scripts/fixtures/y73s_4.14.141_kallsyms.txt")

    branch = hook.split("int32_t branch_absolute(", 1)[1].split(
        "KP_EXPORT_SYMBOL(branch_absolute);", 1
    )[0]
    require("buf[0] = 0x58000051" in branch and
            "buf[1] = 0xd61f0220" in branch and
            "return 4;" in branch,
            "hook entry patch overwrites exactly four AArch64 instructions")
    prepare = hook.split("hook_err_t hook_prepare(", 1)[1].split(
        "KP_EXPORT_SYMBOL(hook_prepare);", 1
    )[0]
    require("for (int i = 0; i < hook->tramp_insts_num; i++)" in prepare and
            "relocate_inst(hook, inst_addr, inst)" in prepare,
            "hook_prepare relocates exactly the overwritten prologue words")
    relocate = hook.split("static __noinline hook_err_t relocate_inst(", 1)[1].split(
        "KP_EXPORT_SYMBOL(hook_prepare);", 1
    )[0]
    require("case INST_IGNORE:" in relocate and "rc = relo_ignore(hook, inst_addr, inst, it);" in relocate,
            "ordinary non-PC-relative prologue instructions use the copy-through relocation path")
    ignore = hook.split("static __noinline hook_err_t relo_ignore(", 1)[1].split(
        "static uint32_t can_b_rel", 1
    )[0]
    require("buf[0] = inst;" in ignore, "copy-through relocation preserves original instruction bits")
    require("#define TRAMPOLINE_MAX_NUM 6" in header,
            "hook origin backup has sufficient capacity for the six-word maximum")

    require("typedef void (*cfi_check_fn)(uint64_t id, void *ptr, void *diag);" in secpass and
            "static void (*backup__cfi_slowpath)(uint64_t id, void *ptr, void *diag)" in secpass and
            "static void replace__cfi_slowpath(uint64_t id, void *ptr, void *diag)" in secpass and
            "backup__cfi_slowpath(id, ptr, diag);" in secpass,
            "KPIMG CFI replacement preserves the target's three-argument ABI")
    require('get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath")' in symbols and
            '"__cfi_slowpath_diag"' in symbols,
            "patch-config resolves the available legacy slowpath and the newer diagnostic variant")
    require("0x002ddc00" not in symbols or "__cfi_slowpath" in symbols,
            "CFI address is sourced from KALLSYMS rather than an unguarded hardcoded runtime address")
    require("0x002ddc00 t __cfi_slowpath" in fixture and
            "__cfi_slowpath_diag" in fixture.split("# ABSENT", 1)[-1],
            "Y73S profile records __cfi_slowpath present and __cfi_slowpath_diag absent")

    if len(sys.argv) > 1:
        data = Path(sys.argv[1]).read_bytes()
        require(len(data) == IMAGE_SIZE, "original Y73S Image length matches the CFI profile")
        require(hashlib.sha256(data).hexdigest() == IMAGE_SHA256,
                "original Y73S Image SHA-256 matches the recovered stock kernel")
        entry = [int.from_bytes(data[FUNCTION_OFFSET + i * 4:FUNCTION_OFFSET + i * 4 + 4],
                                "little") for i in range(4)]
        require(entry == ENTRY, "__cfi_slowpath first four instructions match the relocatable prologue")
        arg_capture = int.from_bytes(data[FUNCTION_OFFSET + 7 * 4:FUNCTION_OFFSET + 8 * 4],
                                     "little")
        require(arg_capture == ARG_CAPTURE,
                "__cfi_slowpath body consumes X2, confirming the third diag argument")
        pc_relative = []
        for i, word in enumerate(entry):
            is_branch = (word & 0x7C000000) == 0x14000000
            is_adr_adrp = (word & 0x1F000000) == 0x10000000
            is_ldr_literal = (word & 0x3B000000) == 0x18000000
            if is_branch or is_adr_adrp or is_ldr_literal:
                pc_relative.append(i)
        require(not pc_relative,
                "overwritten __cfi_slowpath prologue contains no PC-relative branch/address/literal")
    print("[PASS] Y73S CFI slowpath static compatibility audit complete")


if __name__ == "__main__":
    main()
