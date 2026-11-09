#!/usr/bin/env python3
"""Fail-closed source regression checks for the Y73S early mapping path.

This complements, but does not replace, target-kernel disassembly/ABI review.
It intentionally checks the runtime source's ordering and failure guards.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text, signature):
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function signature: {signature}")
    brace = text.find("{", start)
    if brace < 0:
        raise AssertionError(f"missing function body: {signature}")
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos]
    raise AssertionError(f"unterminated function body: {signature}")


def require(pattern, text, message):
    if not re.search(pattern, text, re.S):
        raise AssertionError(message)


def before(text, first, second, message):
    a, b = text.find(first), text.find(second)
    if a < 0 or b < 0 or a >= b:
        raise AssertionError(message)


def main():
    map_c = source("kernel/base/map.c")
    symbol_c = source("tools/symbol.c")
    hotpatch_c = source("kernel/base/hotpatch.c")
    hook_c = source("kernel/base/hook.c")
    patch_c = source("kernel/patch/patch.c")

    # The known-bad memblock_alloc_try_nid fallback returns a kernel VA on
    # the supplied Y73S binary. It must never be selected as a PA allocator.
    resolver = function_body(symbol_c, "int fillin_map_symbol(")
    if '"memblock_alloc_try_nid"' in resolver:
        raise AssertionError("unsafe memblock_alloc_try_nid fallback reintroduced")
    if "MAP_SYM_MEMBLOCK_ALLOC_TRY_NID" in map_c or "MAP_SYM_MEMBLOCK_ALLOC_TRY_NID" in symbol_c:
        raise AssertionError("unsafe virtual-return allocator enum reintroduced")
    require(r'"memblock_find_in_range"', resolver,
            "resolver must support the binary-verified physical range finder")
    require(r'"memblock_phys_alloc_try_nid"', resolver,
            "resolver may use only the explicitly physical allocator as fallback")

    # A range finder does not reserve. The exact selected PA must be reserved
    # before it is exposed to page-table construction or image relocation.
    alloc = function_body(map_c, "static uint64_t map_phys_alloc(")
    require(r"memblock_find_in_range_f[^;]*\)\(\s*0,\s*0,\s*size,\s*align\)",
            alloc, "physical range finder arguments changed")
    find_call = alloc.find("0, 0, size, align")
    reserve_call = alloc.find("(pa, size)")
    if find_call < 0 or reserve_call <= find_call:
        raise AssertionError("range result must be reserved before it is returned")
    require(r"if\s*\(\(\(memblock_reserve_f\).*?\)\(pa,\s*size\)\)\s*return 0;",
            alloc, "reservation failure must reject the physical allocation")
    require(r"return pa;", alloc, "physical allocator must return the reserved PA")

    # The target's 5-argument nopanic virtual allocator is only a probe after
    # Linux 4.14 paging_init has established the linear map.
    probe = function_body(map_c, "static void __noinline detect_y73s_linear_voffset(")
    require(r"memblock_virt_alloc_try_nid_f[^;]*\)\(\s*page_size,\s*page_size,\s*detect_phys,\s*detect_phys \+ page_size,\s*NUMA_NO_NODE\)",
            probe, "linear-map probe ABI/arguments changed")
    require(r"if\s*\(still_free\)\s*__builtin_trap\(\);", probe,
            "probe must reject allocator fallback to another physical page")
    require(r"if\s*\(\(\(memblock_free_f\).*?\)\(detect_phys,\s*page_size\)\)\s*__builtin_trap\(\);",
            probe, "probe reservation release failure must be detected")

    paging = function_body(map_c, "void __noinline _paging_init(")
    before(paging, "((paging_init_f)(paging_init_va))();",
           "detect_y73s_linear_voffset(data);",
           "linear-map probe must run after the original paging_init returns")
    require(r"if\s*\(!start_pa\s*\|\|\s*\(start_pa\s*&\s*\(page_size\s*-\s*1\)\).*?__builtin_trap\(\);",
            paging, "main destination PA must be nonzero, aligned, and bounded")
    before(paging, "if (!start_pa", "memblock_mark_nomap_f",
           "destination PA must be validated before NOMAP")
    require(r"memblock_mark_nomap_f[^;]*\)\(start_pa,\s*all_size\)\)\s*__builtin_trap\(\);",
            paging, "NOMAP failure must stop before mapping/copying")

    pte = function_body(map_c, "static uint64_t __noinline get_or_create_pte(")
    require(r"pxd_pa\s*=\s*map_phys_alloc\(data,\s*page_size,\s*page_size\);\s*if\s*\(!pxd_pa\)\s*__builtin_trap\(\);",
            pte, "page-table allocation must be checked before descriptor creation")

    # Y73S KALLSYMS lacks cpu_online_mask/nr_cpu_ids. The callback must
    # therefore never call num_online_cpus() or inspect unresolved cpumask state.
    callback = function_body(hotpatch_c, "static int hotpatch_cb(void *arg)")
    for forbidden in ("num_online_cpus", "cpu_online_mask", "nr_cpu_ids", "atomic_inc"):
        if forbidden in callback:
            raise AssertionError(f"hotpatch callback must not depend on {forbidden}")
    hotpatch_fn = function_body(hotpatch_c, "int hotpatch(void *addrs[], uint32_t values[], int cnt)")
    require(r"stop_machine\(hotpatch_cb,\s*&patch,\s*NULL\)", hotpatch_fn,
            "Y73S hotpatch must coordinate CPUs with stop_machine(..., NULL)")
    require(r"!kfunc\(stop_machine\).*?is_interrupt_masked\(\).*?return -EOPNOTSUPP;",
            hotpatch_fn, "missing stop_machine/interrupt state must fail closed")
    require(r"is_interrupt_masked\(\)\s*&&\s*!hotpatch_early_boot", hotpatch_fn,
            "IRQ-masked patching may only use the explicit early-boot window")
    patch_fn = function_body(patch_c, "int patch()")
    require(r"hotpatch_set_early_boot\(1\)", patch_fn,
            "initial pre-rest_init hooks must enable the early-boot window")
    before(patch_fn, "hotpatch_set_early_boot(1)", "hook_wrap4",
           "early-boot mode must be active before rest_init hook installation")
    before(function_body(patch_c, "static void before_rest_init("),
           "android_user_init()", "hotpatch_set_early_boot(0)",
           "early-boot mode must remain active through pre-rest_init hook setup")
    if "hotpatch_cb(&patch)" in hotpatch_fn:
        raise AssertionError("uncoordinated direct hotpatch callback fallback reintroduced")

    install = function_body(hook_c, "int hook_install(hook_t *hook)")
    require(r"return hotpatch\(", install, "hook_install must propagate hotpatch status")
    hook_fn = function_body(hook_c, "hook_err_t hook(void *func, void *replace, void **backup)")
    require(r"patch_rc\s*=\s*hook_install\(hook\)", hook_fn,
            "hook() must inspect hook_install result")
    require(r"patch_rc == -EUCLEAN", hook_fn,
            "uncertain rollback must retain trampoline storage")
    unhook_fn = function_body(hook_c, "void unhook(void *func)")
    before(unhook_fn, "hook_mem_claim_retire(hook)", "hook_uninstall(hook)",
           "unhook must reserve the registry entry before restoring text")
    require(r"if \(!rc\)\\s*hook_mem_retire\(hook\);\\s*else\\s*hook_mem_cancel_retire\(hook\);",
            unhook_fn, "failed unhook must cancel retirement and retain the live trampoline")


    # Worst case: six instruction slots * eight emitted words, plus jump-back.
    hook_h = source("kernel/include/hook.h")
    require(r"#define RELOCATE_INST_NUM \(TRAMPOLINE_MAX_NUM \* 8 \+ 4\)", hook_h,
            "relocation buffer is smaller than the conservative worst-case bound")
    branch_range = function_body(hook_c, "static uint32_t can_b_rel(")
    require(r"src_addr \& 0x3", branch_range,
            "relative branch source must be instruction-aligned")
    require(r"dst_addr \& 0x3", branch_range,
            "relative branch target must be instruction-aligned")
    require(r"0x07fffffcULL", branch_range,
            "positive A64 B range must exclude +128 MiB")
    require(r"-0x08000000LL", branch_range,
            "negative A64 B range must include -128 MiB")
    if "B_REL_RANGE" in branch_range:
        raise AssertionError("symmetric A64 branch range check reintroduced")

    patch_text = function_body(hotpatch_c, "int hotpatch_nosync(")
    before(patch_text, "*(uint32_t *)tp = value;", "__flush_dcache_area",
           "instruction writes must be cleaned from D-cache before I-cache invalidation")
    before(patch_text, "__flush_dcache_area", "flush_icache_all",
           "global I-cache invalidation must follow D-cache clean")
    require(r"__flush_dcache_area\(\(void \*\)tp,\s*sizeof\(uint32_t\)\)",
            patch_text, "instruction patch must clean the modified D-cache line")

    print("[PASS] instruction patch cleans D-cache before global I-cache invalidation")
    print("[PASS] Y73S allocator dispatch excludes virtual-return fallback")
    print("[PASS] physical ranges are reserved before use")
    print("[PASS] linear-map probe ordering and reservation checks")
    print("[PASS] destination and intermediate page-table allocation guards")
    print("[PASS] hotpatch avoids unresolved CPU-mask symbols and fails closed")
    print("[PASS] early-boot stop_machine window is explicitly scoped")
    print("[PASS] hook install/uninstall propagate patch failures safely")
    adr_relocator = function_body(hook_c, "static __noinline hook_err_t relo_adr(")
    require(r"if\s*\(is_in_tramp\(hook,\s*addr\)\)\s*return -HOOK_BAD_RELO;", adr_relocator,
            "ADR references into overwritten prologue must fail closed")
    require(r"if\s*\(is_page_in_tramp\(hook,\s*addr\)\)\s*return -HOOK_BAD_RELO;", adr_relocator,
            "ADRP pages overlapping overwritten prologue must fail closed")
    page_guard = function_body(hook_c, "static int is_page_in_tramp(")
    require(r"page_addr < tramp_end && page_addr \+ 0x1000ULL > tramp_start", page_guard,
            "ADRP overlap guard must cover the complete architectural 4-KiB page")

    # Branch thunk chains can be cyclic or malformed; callers must reject failure.
    branch_resolver = function_body(hook_c, "uint64_t branch_func_addr(uint64_t addr)")
    require(r"uint64_t visited\[8\]", branch_resolver,
            "entry thunk resolution must have a finite hop budget")
    require(r"visited\[j\] == addr", branch_resolver,
            "entry thunk resolver must detect cycles")
    require(r"is_bad_address\(\(void \*\)addr\)", branch_resolver,
            "entry thunk resolver must validate each address before dereference")
    require(r"return 0;", branch_resolver,
            "malformed or cyclic thunk chains must fail closed")
    require(r"is_bad_address\(\(void \*\)origin_addr\)", hook_fn,
            "hook() must reject failed entry resolution")
    wrap_fn = function_body(hook_c, "hook_err_t hook_wrap(")
    require(r"is_bad_address\(\(void \*\)origin\)", wrap_fn,
            "hook_wrap() must reject failed entry resolution")
    unwrap_fn = function_body(hook_c, "int hook_unwrap_remove(")
    require(r"is_bad_address\(\(void \*\)origin\)", unwrap_fn,
            "hook_unwrap_remove() must reject failed entry resolution")

    unhook_fn = function_body(hook_c, "void unhook(")
    require(r"is_bad_address\(func\)", unhook_fn,
            "unhook() must reject a null or invalid original function")
    require(r"is_bad_address\(\(void \*\)origin\)", unhook_fn,
            "unhook() must reject failed entry resolution")
    require(r"hook_install\(&chain->hook\)", wrap_fn,
            "hook_wrap() must call and check the underlying patch operation")
    require(r"patch_rc == -EUCLEAN", wrap_fn,
            "hook_wrap() must retain chain storage after uncertain rollback")
    require(r"err = -HOOK_PATCH_FAILED", wrap_fn,
            "hook_wrap() must report ordinary patch failure")
    require(r"hook_uninstall\(&chain->hook\)", unwrap_fn,
            "hook_unwrap_remove() must check the underlying restore operation")
    before(unwrap_fn, "hook_mem_claim_retire(chain)", "hook_uninstall(&chain->hook)",
           "hook_unwrap_remove() must reserve the registry entry before restoring text")
    require(r"if\s*\(!rc\)\s*hook_mem_retire\(chain\);\s*else\s*hook_mem_cancel_retire\(chain\);",
            unwrap_fn, "failed chain restore must cancel retirement and retain the live trampoline")
    if "hook_chain_install(chain)" in wrap_fn or "hook_chain_uninstall(chain)" in unwrap_fn:
        raise AssertionError("unchecked hook-chain patch helper reintroduced")

    print("[PASS] relocation buffer bound and A64 branch range/alignment")
    print("[PASS] hook-chain install/restore failures are propagated safely")
    print("[PASS] ADR and overlapping ADRP references into overwritten prologue fail closed")
    print("[PASS] ARM64 entry thunk resolver is bounded and fail-closed")
    # Credential/task-extension hardening: slot identity is published only
    # after its payload is initialized, and all mutable policy flag accesses
    # are single-copy accesses. These checks guard the recently audited races.
    taskext_h = source("kernel/patch/include/taskext.h")
    taskob_c = source("kernel/patch/common/taskob.c")
    accctl_c = source("kernel/patch/common/accctl.c")
    taskcred_c = source("kernel/patch/ksyms/task_cred.c")

    valid_ext = function_body(taskext_h, "static inline bool task_ext_valid(")
    require(r"if\s*\(!ext\s*\|\|\s*IS_ERR\(ext\)\)", valid_ext,
            "task_ext_valid must reject null and error pointers")
    require(r"READ_ONCE\(ext->size\)", valid_ext,
            "task_ext_valid must read the published size once")
    require(r"size\s*!=\s*task_ext_size", valid_ext,
            "task_ext_valid must reject malformed extension sizes")
    require(r"READ_ONCE\(ext->_magic\)", valid_ext,
            "task_ext_valid must read the in-structure magic once")

    create_ext = function_body(taskob_c, "static struct task_ext *task_ext_create(")
    before(create_ext, "task_ext_reset(ret)", "WRITE_ONCE(task_ext_slots[i].task, task)",
           "task extension must be initialized before publishing its task key")
    before(create_ext, "WRITE_ONCE(ret->sel_allow", "WRITE_ONCE(task_ext_slots[i].task, task)",
           "inherited policy flags must be initialized before publishing the task key")
    require(r"if\s*\(sel_allow\)\s*WRITE_ONCE\(ret->sel_allow,\s*true\)", create_ext,
            "existing task extension must preserve inherited SELinux allow state")
    lookup_ext = function_body(taskob_c, "struct task_ext *kf_get_task_ext(")
    require(r"READ_ONCE\(task_ext_slots\[i\]\.task\)", lookup_ext,
            "task extension lookup must read the published key once")
    before(lookup_ext, "if (slot_task != task) continue;", "dsb(ish);",
           "task extension identity read must follow matching published task key")
    require(r"READ_ONCE\(task_ext_slots\[i\]\.ext\.pid\)", lookup_ext,
            "task extension lookup must read PID identity once")

    prepare_ext = function_body(taskob_c, "static void prepare_task_ext(")
    require(r"READ_ONCE\(old_ext->sel_allow\)", prepare_ext,
            "fork inheritance must read mutable SELinux flag once")
    require(r"task_ext_create\(new,\s*sel_allow,\s*priv_sel_allow\)", prepare_ext,
            "fork inheritance must initialize child policy before publication")

    commit_su = function_body(accctl_c, "int commit_common_su(")
    before(commit_su, "rc = commit_creds(new)", "WRITE_ONCE(ext->sel_allow",
           "SELinux bypass flag must not publish before credential commit")
    require(r"if\s*\(unlikely\(!ext_ok\)\).*?goto out;", commit_su,
            "credential transition must fail closed without a valid task extension")
    slow_audit = function_body(accctl_c, "static int slow_avc_audit_replace(")
    require(r"READ_ONCE\(ext->sel_allow\).*?READ_ONCE\(ext->priv_sel_allow\)", slow_audit,
            "slow AVC hook must use single-copy policy flag reads")
    require(r"READ_ONCE\(ext->sel_allow\).*?READ_ONCE\(ext->priv_sel_allow\)",
            function_body(accctl_c, "static int avc_denied_replace("),
            "AVC hook must use single-copy policy flag reads")
    task_su_fn = function_body(accctl_c, "int task_su(")
    require(r"return -EOPNOTSUPP;", task_su_fn,
            "cross-task credential mutation must remain unsupported")

    require(r"cred_size\s*\?\s*cred_size\(new_cred\)\s*:\s*0", taskcred_c,
            "cap_ambient scan must fail closed when slab object size is unavailable")
    require(r"if\s*\(ambient_scan_len\s*>\s*CRED_MAX_SIZE\)\s*ambient_scan_len\s*=\s*CRED_MAX_SIZE;",
            taskcred_c, "cap_ambient scan must be bounded by both allocator size and scratch limit")
    if "cred_size(new_cred) : CRED_MAX_SIZE" in taskcred_c:
        raise AssertionError("unbounded slab credential scan fallback reintroduced")

    require(r"task_struct_offset\.seccomp_offset\s*=\s*-1;", taskcred_c,
            "unused seccomp offset must remain explicitly disabled")
    if "int mode_back = *modep" in taskcred_c or "*modep = 1158" in taskcred_c:
        raise AssertionError("raw seccomp probing of scratch task_struct must not return")
    resolve_current_fn = function_body(taskcred_c, "int resolve_current(")
    require(r"!init_task\s*\|\|\s*!is_kimg_range\(\(uintptr_t\)init_task\)", resolve_current_fn,
            "resolve_current must fail closed before dereferencing an unresolved init_task")

    print("[PASS] task_ext null/size/magic validation and publication ordering")
    print("[PASS] task_ext mutable policy flags use READ_ONCE/WRITE_ONCE")
    print("[PASS] credential commit gates SELinux state; cross-task SU stays disabled")
    print("[PASS] seccomp state is preserved without raw task_struct probing")

    # Kstorage user buffers must be validated, and faultable user copies must
    # happen after leaving the RCU read-side critical section.
    kstorage_c = source("kernel/patch/common/kstorage.c")
    sucompat_c = source("kernel/patch/common/sucompat.c")
    write_store = function_body(kstorage_c, "int write_kstorage(")
    require(r"offset\s*<\s*0.*?len\s*<\s*0", write_store,
            "kstorage writes must reject negative offsets and lengths")
    before(write_store, "kp_private_spin_lock(lock)", "hlist_for_each_entry_rcu",
           "kstorage update lookup must be serialized with remove/replace writers")
    read_store = function_body(kstorage_c, "int read_kstorage(")
    require(r"offset\s*<\s*0.*?len\s*<\s*0", read_store,
            "kstorage reads must reject negative offsets and lengths")
    if read_store.rfind("rcu_read_unlock();") > read_store.find("compat_copy_to_user"):
        raise AssertionError("kstorage user copy must happen after RCU unlock")
    list_store = function_body(kstorage_c, "int list_kstorage_ids(")
    if list_store.rfind("rcu_read_unlock();") > list_store.find("compat_copy_to_user"):
        raise AssertionError("kstorage ID user copy must happen after RCU unlock")
    uid_cb = function_body(sucompat_c, "static int allow_uids_cb(")
    if "compat_copy_to_user" in uid_cb:
        raise AssertionError("SU UID callback must not fault user pages under RCU")
    uid_list = function_body(sucompat_c, "int su_allow_uids(")
    before(uid_list, "on_each_kstorage_elem", "compat_copy_to_user",
           "SU UID list must snapshot under RCU and copy to user afterwards")

    print("[PASS] kstorage range checks and RCU-safe user-copy ordering")
    print("[PASS] SU UID enumeration no longer copies to user inside RCU")
    require(r"ks->dlen\s*<\s*sizeof\(uid_t\)", sucompat_c,
            "SU membership lookup must validate stored record length")
    require(r"kstorage->dlen\s*<\s*sizeof\(struct su_profile\)", sucompat_c,
            "SU UID enumeration must validate stored profile length")
    require(r"ks->dlen\s*<\s*sizeof\(struct su_profile\)", sucompat_c,
            "SU profile lookup must validate stored profile length")
    add_profile = function_body(sucompat_c, "int su_add_allow_uid(")
    require(r"strncpy\(profile\.scontext,\s*scontext,\s*sizeof\(profile\.scontext\)\s*-\s*1\)",
            add_profile, "SU context copy must not read a fixed-size span past a short string")
    require(r"profile\.scontext\[sizeof\(profile\.scontext\)\s*-\s*1\]\s*=\s*'\\0'",
            add_profile, "SU context copy must always terminate the stored string")

    print("[PASS] SU profile record sizes and bounded SELinux context copy")

    print("[NOTE] Source checks do not independently prove binary ABI or device boot")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(2)
