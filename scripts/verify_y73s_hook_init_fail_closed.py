#!/usr/bin/env python3
"""Static contracts for the Y73s split Hook control/code backend."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

start = read("kernel/base/start.c")
hmem = read("kernel/base/hmem.c")
hmem_h = read("kernel/base/hmem.h")
hook_h = read("kernel/include/hook.h")
hook_c = read("kernel/base/hook.c")
fphook_c = read("kernel/base/fphook.c")
exec_alloc = read("kernel/base/exec_alloc.c")
kpmalloc_h = read("kernel/include/kpmalloc.h")
cache_s = read("kernel/base/cache.S")

checks = {
    "hook arena is mapped writable non-executable":
        "Hook RW-NX:" in start and
        bool(re.search(r"\*pte\s*=\s*\(\*pte\s*\|\s*PTE_DBM\s*\|\s*PTE_SHARED\s*\|\s*PTE_PXN\)\s*&\s*~PTE_RDONLY", start)),
    "hook_mem_add result is captured":
        bool(re.search(r"int\s+hook_mem_rc\s*=\s*hook_mem_add\s*\(\s*_kp_hook_start\s*,\s*HOOK_ALLOC_SIZE\s*\)\s*;", start)),
    "initialization failure is reported":
        "Hook engine disabled: hook_mem_add failed (%d)\\n" in start,
    "allocator refuses use before initialization":
        bool(re.search(r"void\s*\*hook_mem_zalloc\s*\([^)]*\)\s*\{\s*[^}]*!hook_locks_ready", hmem, re.S)),
    "origin lookup refuses use before initialization":
        bool(re.search(r"void\s*\*hook_get_mem_from_origin\s*\([^)]*\)\s*\{\s*[^}]*!hook_locks_ready", hmem, re.S)),
    "public inline chain ABI still embeds transit array":
        bool(re.search(r"typedef\s+struct\s+_hook_chain\s*\{[^}]*uint32_t\s+transit\[TRANSIT_INST_NUM\]", hook_h, re.S)),
    "public FP chain ABI still embeds transit array":
        bool(re.search(r"typedef\s+struct\s+_fphook_chain\s*\{[^}]*uint32_t\s+transit\[TRANSIT_INST_NUM\]", hook_h, re.S)),
    "inline backend no longer recovers owner from transit":
        "local_container_of(transit, hook_chain_t, transit)" not in hook_c,
    "FP backend no longer recovers owner from transit":
        "local_container_of(transit, fp_hook_chain_t, transit)" not in fphook_c,
    "control records track separate relocation and transit pages":
        "void *exec_relo;" in hmem and "void *exec_transit;" in hmem and
        "hook_mem_set_relo" in hmem_h and "hook_mem_set_transit" in hmem_h,
    "generated code is allocated from executable page allocator":
        "kp_malloc_exec(sizeof(hook->relo_insts))" in hook_c and
        hook_c.count("kp_malloc_exec(64)") >= 1 and "kp_malloc_exec(64)" in fphook_c,
    "all generated code paths seal RX before publication":
        "kp_exec_seal(exec_relo)" in hook_c and
        "kp_exec_seal(transit)" in hook_c and
        "kp_exec_seal(transit)" in fphook_c,
    "generated inline code is D-cache-cleaned to PoU before RX sealing":
        "#define KP_HOOK_FLUSH_ICACHE_RANGE(start, end)" in hook_c and
        "flush_icache_range((unsigned long)(start), (unsigned long)(end))" in hook_c and
        "KP_HOOK_FLUSH_ICACHE_RANGE((unsigned long)exec_relo" in hook_c and
        "KP_HOOK_FLUSH_ICACHE_RANGE((unsigned long)transit" in hook_c,
    "flush_icache_range cleans D-cache to PoU and invalidates I-cache":
        bool(re.search(r"ENTRY\(flush_icache_range\)(.*?)ENDPROC\(flush_icache_range\)", cache_s, re.S)) and
        bool(re.search(r"dc\s+cvau", re.search(r"ENTRY\(flush_icache_range\)(.*?)ENDPROC\(flush_icache_range\)", cache_s, re.S).group(1))) and
        bool(re.search(r"ic\s+ivau", re.search(r"ENTRY\(flush_icache_range\)(.*?)ENDPROC\(flush_icache_range\)", cache_s, re.S).group(1))) and
        bool(re.search(r"dsb\s+ish", re.search(r"ENTRY\(flush_icache_range\)(.*?)ENDPROC\(flush_icache_range\)", cache_s, re.S).group(1))) and
        bool(re.search(r"isb", re.search(r"ENTRY\(flush_icache_range\)(.*?)ENDPROC\(flush_icache_range\)", cache_s, re.S).group(1))),
    "generated FP transit code is D-cache-cleaned to PoU before RX sealing":
        "flush_icache_range((unsigned long)transit" in fphook_c and
        "flush_icache_all();\n    if (kp_exec_seal(transit))" not in fphook_c,
    "RX seal applies read-only and clears PXN":
        "exec_set_uniform_protection(a, address" in exec_alloc and
        "KP_EXEC_RX" in exec_alloc and
        "int kp_exec_seal(void *ptr)" in exec_alloc and
        "int kp_exec_seal(void *ptr);" in kpmalloc_h,
    "failed unpublished records release executable pages":
        "if (warp->using == 3)" in hmem and
        "if (exec_relo) (void)kp_free_exec(exec_relo);" in hmem and
        "if (exec_transit) (void)kp_free_exec(exec_transit);" in hmem,
    "retired records retain executable pages for delayed arrivals":
        bool(re.search(r"void\s+hook_mem_retire\s*\([^)]*\)\s*\{[^}]*__atomic_store_n\(&warp->using,\s*2", hmem, re.S)) and
        "kp_free_exec" not in re.search(r"void\s+hook_mem_retire\s*\([^)]*\)\s*\{(.*?)\n\}", hmem, re.S).group(1),
    "callback retirement remains reader-gated in inline backend":
        "hook_chain_reader_exit(hook_chain, 0)" in hook_c and
        "hook_chain_pin_callbacks(hook_chain, 0" in hook_c,
    "callback retirement remains reader-gated in FP backend":
        "hook_chain_reader_exit(hook_chain, 1)" in fphook_c and
        "hook_chain_pin_callbacks(hook_chain, 1" in fphook_c,
    "all four inline transit ABI entry points remain":
        all(name in hook_c for name in ("_transit0(", "_transit4(", "_transit8(", "_transit12(")),
    "all four FP transit ABI entry points remain":
        all(name in fphook_c for name in ("_fp_transit0(", "_fp_transit4(", "_fp_transit8(", "_fp_transit12(")),
    "12-argument callback layout remains public":
        "uint64_t args[12];" in hook_h and
        "hook_chain12_callback" in hook_h and
        "hook_wrap12(" in hook_h and "fp_hook_wrap12(" in hook_h,
    "integer literal relocation loads the literal at the correct PC-relative offset":
        "buf[0] = 0x58000080u | rt; // LDR Xt, #16" in hook_c and
        "buf[0] = 0x58000060u | rt" not in hook_c,
    "SIMD literal relocation loads the literal at the correct PC-relative offset":
        "buf[1] = 0x580000B1; // LDR X17, #20" in hook_c and
        "buf[1] = 0x58000091" not in hook_c,
    "SIMD literal relocation restores X16/X17 and balances SP":
        "buf[3] = 0xA8C147F0; // LDP X16, X17, [SP], #0x10" in hook_c and
        "buf[3] = 0xF85F83F1" not in hook_c,
    "legacy structure transit capacity remains unchanged":
        "#define TRANSIT_INST_NUM 0x70" in hook_h,
}

failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
if failed:
    sys.exit(1)
print(f"PASS: {len(checks)} Y73s split Hook backend contracts")
