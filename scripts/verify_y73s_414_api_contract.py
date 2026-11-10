#!/usr/bin/env python3
"""Source-level compatibility guards for the Y73S Linux 4.14.141 baseline.

This is not a substitute for compiling against the vendor KDIR. It guards
known 4.14 ARM64 API/export differences that can be checked from source.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("[PASS] " + message)


patch = read("lkm/infra/patch_memory.c")
resolver = read("lkm/infra/symbol_resolver.c")
kbuild = read("lkm/Kbuild")
init = read("lkm/core/init.c")
secpass = read("lkm/infra/secpass.c")
hook_runtime = read("lkm/hook/hook_runtime.c")
kpm = read("lkm/kpm/module.c")

# In upstream v4.14.141 ARM64:
# - __flush_dcache_area is declared/implemented but not exported;
# - flush_icache_range is exported from arch/arm64/mm/flush.c;
# - kallsyms_lookup_name is GPL-exported.
old_cache = patch.split("#else", 1)[1].split("#endif", 1)[0]
require("kp_flush_dcache_area_fn" in old_cache and
        'kp_resolve_symbol("__flush_dcache_area")' in patch,
        "4.14 non-exported __flush_dcache_area is runtime-resolved")
require("if (!kp_flush_dcache_area_fn)" in patch and
        "return -ENOSYS;" in patch,
        "4.14 dcache resolver failure is fail-closed before patch use")
require(re.search(r'__attribute__\(\(no_sanitize\("cfi"\)\)\)\s+static void kp_flush_dcache_legacy',
                  patch) is not None and
        "kp_flush_dcache_area_fn((void *)start, len)" in patch,
        "raw assembly dcache entry bypasses invalid indirect CFI type check")
require("flush_icache_range((start), (end))" in old_cache and
        "__flush_icache_range" not in old_cache,
        "4.14 I-cache path uses exported flush_icache_range")
require("return kallsyms_lookup_name(name);" in resolver,
        "symbol resolver bootstrap is kallsyms_lookup_name (verified GPL export on 4.14.141)")
require("MODULE_LICENSE(\"GPL\")" in init,
        "LKM license permits GPL-only kallsyms_lookup_name")

# Newer APIs must remain isolated behind version checks so 4.14 never
# parses/includes headers or struct members introduced in later kernels.
require(re.search(r"#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6,\s*11,\s*0\).*?#include <linux/execmem.h>",
                  hook_runtime, re.S) is not None,
        "hook execmem header/type is guarded for kernels before 6.11")
require(re.search(r"#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6,\s*11,\s*0\).*?#include <linux/execmem.h>",
                  kpm, re.S) is not None,
        "KPM execmem header/type is guarded for kernels before 6.11")
require(re.search(r"#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6,\s*4,\s*0\).*?struct module_memory",
                  secpass, re.S) is not None,
        "new module_memory layout is guarded; 4.14 uses core_layout")
require("#ifdef MODULE_IMPORT_NS" in init,
        "module namespace import is omitted on 4.14 where API is absent")

# 4.14 has a folded P4D compatibility layer (asm-generic/pgtable-nop4d.h);
# p4d_t/p4d_offset are valid there and must not be replaced by an unsafe
# hand-written PGD->PUD cast.
require("p4d_offset(pgd, addr)" in patch and
        "p4d_offset(pgd, addr)" in hook_runtime and
        "p4d_offset(pgd, addr)" in kpm,
        "all three ARM64 page-table walkers retain generic folded-P4D API")

# The legacy cache API selector is based on the presence of
# __flush_dcache_area; this is present in upstream 4.14.141 and selects the
# runtime-resolved legacy path.
require("grep -q __flush_dcache_area" in kbuild and
        "KP_NEW_DCACHE_FLUSH" in kbuild,
        "Kbuild selects the legacy cache path for the 4.14 header baseline")

print("[PASS] Y73S 4.14.141 source compatibility contract")
