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

hook_runtime = read("lkm/hook/hook_runtime.c")
kpm = read("lkm/kpm/module.c")
sucompat = read("lkm/supercall/sucompat_hook.c")
kstorage = read("lkm/supercall/kstorage.c")
supercall = read("lkm/supercall/supercall.c")
hook_runtime = read("lkm/hook/hook_runtime.c")
hook_engine = read("lkm/hook/hook_engine.c")
patch_memory = read("lkm/infra/patch_memory.c")
secpass = read("lkm/infra/secpass.c")
accctl = read("lkm/supercall/accctl.c")
sucompat_hook = read("lkm/supercall/sucompat_hook.c")
su_source = read("lkm/supercall/su.c")
sucompat_source = read("lkm/supercall/sucompat.c")
init_source = read("lkm/core/init.c")

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
old_cache_code = re.sub(r"/\*.*?\*/|//[^\n]*", "", old_cache, flags=re.S)
require(not re.search(r"(?<![A-Za-z0-9_])__flush_dcache_area\s*\(", old_cache_code),
        "4.14 LKM has no direct relocation against non-exported __flush_dcache_area")
require("return kallsyms_lookup_name(name);" in resolver,
        "symbol resolver bootstrap is kallsyms_lookup_name (verified GPL export on 4.14.141)")
require("MODULE_LICENSE(\"GPL\")" in init,
        "LKM license permits GPL-only kallsyms_lookup_name")

# Additional direct kernel APIs used by the LKM were checked against the
# v4.14.141 export table/source: strscpy, strncpy_from_user, filp_open,
# filp_close, vmalloc, vfree and kernel_read are available to modules.
require("#include <linux/ptrace.h>" in sucompat and
        "current_user_stack_pointer()" in sucompat,
        "4.14 generic ptrace header provides current_user_stack_pointer")
require("strscpy(" in sucompat and "strncpy_from_user(" in sucompat,
        "4.14 string and user-string helpers used by sucompat are available")
require("filp_open(" in kpm and "kernel_read(" in kpm and
        "filp_close(" in kpm,
        "4.14 KPM file read path uses available file APIs")
require("vmalloc(" in kstorage and "vfree(" in kstorage,
        "4.14 KStorage allocation uses exported vmalloc/vfree")

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

# Exact Y73S 4.14.141 symbol profile: data symbols sys_call_table/init_mm are
# absent, while text SyS_truncate.cfi and module_alloc/module_memfree exist.
require('kp_install_inline_supercall("SyS_truncate.cfi"' in supercall and
        'kp_install_inline_supercall("sys_truncate"' not in supercall,
        "Y73S supercall hooks the CFI implementation, not the 4-byte syscall stub")
require("static long kp_supercall_handler_legacy(long arg0, long arg1," in supercall,
        "4.14 syscall handler uses ordinary ARM64 argument ABI with x0-x5")
require("kp_syscall_table_init()" not in init_source,
        "Y73S init no longer fails on hidden sys_call_table data symbol")
require("kp_phys_from_virt_no_init_mm" in patch_memory and
        "virt_addr_valid((void *)addr)" in patch_memory and
        "virt_to_phys((void *)addr)" in patch_memory and
        "vmalloc_to_page((void *)addr)" in patch_memory and
        "page_to_phys(page)" in patch_memory,
        "4.14 patching translates kernel image, linear-map, vmalloc and module pages without init_mm")
require("kp_hook_module_alloc && kp_hook_module_memfree" in hook_runtime and
        "kp_hook_alloc_backend = KP_HOOK_ALLOC_MODULE" in hook_runtime and
        "if (!kp_hook_init_mm && kp_hook_alloc_backend != KP_HOOK_ALLOC_MODULE)" in hook_runtime and
        "module_memfree()" in hook_runtime and
        "__flush_icache_all" not in hook_runtime,
        "Hook runtime supports PAGE_KERNEL_EXEC module memory without init_mm/global flush")
require("KP_HOOK_FLUSH_ICACHE_RANGE" in hook_engine and
        "flush_icache_range(" in hook_engine,
        "LKM hook engine flushes generated trampoline ranges")
require("kp_exec_backend == KP_EXEC_BACKEND_MODULE" in kpm and
        "flush_icache_range(base, base + size)" in kpm and
        "__flush_icache_all()" in kpm and
        "kp_flush_icache_all_fn" not in kpm,
        "KPM loader uses executable module memory and cross-CPU I-cache broadcast")
require("__flush_icache_all()" in hook_engine and
        "__flush_icache_all()" in patch_memory,
        "Hook trampoline and text patch paths broadcast I-cache invalidation")
require('if (!addr)\n\t\taddr = kallsyms_lookup_name("__cfi_slowpath")' in secpass and
        'if (!cfi_enforcement_hooked && !rc)' in secpass,
        "Y73S CFI bypass falls back to the present __cfi_slowpath when newer CFI hooks are absent")
require('kp_resolve_symbol("security_secctx_to_secid")' in accctl and
        "kp_selinux_cred_offset = 0" in accctl and
        "!defined(CONFIG_SECURITY_APPARMOR)" in accctl and
        "!defined(CONFIG_SECURITY_SMACK)" in accctl and
        "!defined(CONFIG_SECURITY_TOMOYO)" in accctl and
        "selinux_blob_sizes hidden" in accctl,
        "4.14 SELinux translabel resolves secctx dynamically and uses the verified single-LSM cred offset")
require("kp_apply_su_cred" in accctl and
        "prepare_kernel_cred(NULL)" in accctl and
        "put_cred(new)" in accctl,
        "pending exec credentials can be relabeled with a fail-closed kernel-cred fallback")
sucompat_init = sucompat_hook.split("int kp_sucompat_hook_init(void)", 1)[1].split(
    "int kp_sucompat_hook_exit(void)", 1
)[0]
require("kp_syscall_table_init()" in sucompat_init and
        sucompat_init.index("kp_syscall_table_init()") < sucompat_init.index("kp_syscall_hook("),
        "sucompat initializes the syscall table before attempting the syscall hook")
require("return kp_hook_prepare_binprm()" in sucompat_hook and
        "kp_resolve_symbol(\"prepare_binprm.cfi\")" in sucompat_hook and
        'kp_resolve_symbol("open_exec")' in sucompat_hook and
        "kp_open_exec(KP_SH_PATH)" in sucompat_hook,
        "Y73S sucompat falls back to the real 4.14 prepare_binprm text symbol when sys_call_table is hidden")
require("bprm->file = shell_file" in sucompat_hook and
        "bprm->filename = KP_SH_PATH" in sucompat_hook and
        "bprm->interp = KP_SH_PATH" in sucompat_hook and
        "kp_apply_su_cred(&new, 0, sctx)" in sucompat_hook and
        "if (!args->local.data0 || (long)args->ret < 0)" in sucompat_hook and
        "if (supercmd && bprm->argc > 1)" in sucompat_hook and
        "bprm->argc = 1" in sucompat_hook and
        "args->local.data2 = supercmd" in sucompat_hook and
        "task_pt_regs(current)" in sucompat_hook and
        "regs->syscallno == __NR_execve" in sucompat_hook and
        "kp_get_supercmd_sctx(regs, sctx_buf, sizeof(sctx_buf))" in sucompat_hook,
        "prepare_binprm fallback redirects only execs and updates the pending cred after SELinux bprm hooks")
require('kallsyms_lookup_name("module_alloc")' in kpm and
        'kallsyms_lookup_name("module_memfree")' in kpm,
        "KPM runtime resolves the target's executable module allocator/free pair")
require("v &= ~exec_deny_mask" in hook_runtime and
        "v |= KP_HOOK_PTE_UXN" in hook_runtime and
        "v &= ~exec_deny_mask" in kpm and
        "v |= KP_LKM_PTE_UXN" in kpm,
        "kernel executable pages preserve UXN to forbid EL0 execution")

# The legacy cache API selector is based on the presence of
# __flush_dcache_area; this is present in upstream 4.14.141 and selects the
# runtime-resolved legacy path.
require("grep -q __flush_dcache_area" in kbuild and
        "KP_NEW_DCACHE_FLUSH" in kbuild,
        "Kbuild selects the legacy cache path for the 4.14 header baseline")


# Uncertain text patches and active transit readers must not outlive the LKM.
sucompat_exit = sucompat.split("int kp_sucompat_hook_exit(void)", 1)[1]
sucompat_install = sucompat.split("static int kp_hook_prepare_binprm(void)", 1)[1].split(
    "/* ---- getname_flags", 1
)[0]
require(sucompat_install.index("kp_prepare_binprm_addr = addr") <
        sucompat_install.index("return hook_wrap1(") and
        "return hook_wrap1(" in sucompat_install,
        "prepare_binprm target is recorded before patching so uncertain installs remain cleanable")
unwrap_wait = sucompat.split("static int kp_unwrap_wait(", 1)[1].split(
    "/* ---- getname_flags", 1
)[0]
require("kp_unwrap_wait(" in sucompat_exit and
        "hook_unwrap(" not in sucompat_exit and
        "hook_unwrap_remove(" in unwrap_wait and
        "while (rc == -EBUSY)" in unwrap_wait and
        "cond_resched();" in unwrap_wait and
        "if (!unhook_rc || unhook_rc == -ENOENT)" in sucompat_exit and
        "return rc;" in sucompat_exit,
        "sucompat teardown retries active transit readers and retains live-hook state on failure")
init_body = init_source
require(init_body.index("sucompat_installed = true;") <
        init_body.index("rc = kp_sucompat_hook_init();") and
        "BUG_ON(kp_sucompat_hook_exit());" in init_body,
        "LKM init rollback and module exit fail closed if sucompat hooks cannot be retired")


# Credential changes must be bounded and namespace-valid on the 4.14 path.
require("strnlen(sctx, SUPERCALL_SCONTEXT_LEN)" in accctl and
        "sid = 0;" in accctl and
        "secctx_to_secid failed:" in accctl and
        "strlen(sctx)" not in accctl,
        "SELinux context parsing is bounded for the fixed-size UAPI field and initializes failure diagnostics")
require("uid_valid(kuid)" in accctl and "gid_valid(kgid)" in accctl and
        "rc = su_cred(new, to_uid);" in accctl,
        "SU credential preparation rejects unmapped uid/gid values before installing credentials")
task_su_body = accctl.split("int kp_task_su(", 1)[1]
require("return -EOPNOTSUPP;" in task_su_body and
        "rcu_assign_pointer(task->cred" not in task_su_body and
        "rcu_assign_pointer(task->real_cred" not in task_su_body,
        "unsafe cross-task credential replacement is disabled fail-closed")
commit_su = accctl.split("int kp_commit_su(", 1)[1].split("int kp_task_su(", 1)[0]
require(commit_su.index("kp_apply_su_cred(&new, to_uid, sctx)") <
        commit_su.index("current_thread_info()->flags &= ~_TIF_SECCOMP"),
        "seccomp is changed only after credential preparation succeeds")


# Fixed-size SU profiles originate in user memory and in KStorage.
su_sc = su_source.split("long kp_su_sc(", 1)[1].split("long kp_su_task_sc(", 1)[0]
su_grant = su_source.split("long kp_su_grant_uid_sc(", 1)[1].split("long kp_su_revoke_uid_sc(", 1)[0]
su_task = su_source.split("long kp_su_task_sc(", 1)[1].split("long kp_su_grant_uid_sc(", 1)[0]
require("memchr(profile->scontext" in su_sc and
        "sizeof(profile->scontext)" in su_sc and
        "memchr(profile->scontext" in su_grant and
        "sizeof(profile->scontext)" in su_grant,
        "user-provided fixed-size SU profile contexts must be NUL-terminated before string use")
require("return -EOPNOTSUPP;" in su_task and "memdup_user(" not in su_task,
        "disabled cross-task SU rejects before copying or parsing an unused user profile")
add_allow = sucompat_source.split("int kp_su_add_allow_uid(", 1)[1].split("int kp_su_remove_allow_uid(", 1)[0]
profile_read = sucompat_source.split("int kp_su_allow_uid_profile(", 1)[1].split("/* APatch module exclude", 1)[0]
default_sctx = sucompat_hook.split("static const char *kp_default_sctx(", 1)[1].split("static long kp_execve_handler(", 1)[0]
require("strnlen(scontext, sizeof(profile.scontext))" in add_allow and
        "sctx_len >= sizeof(profile.scontext)" in add_allow,
        "allowlist storage rejects oversized SELinux context strings instead of truncating")
require("ks->dlen != sizeof(*out_profile)" in profile_read and
        "!out_profile" in profile_read,
        "SU profile retrieval validates output pointer and exact KStorage record size")
require("strnlen(profile.scontext, sizeof(profile.scontext))" in default_sctx and
        "memcpy(sctx, profile.scontext, sctx_len + 1)" in default_sctx,
        "default SELinux context copy is bounded by the stored fixed-size profile")


su_list = su_source.split("long kp_su_allow_uid_list_sc(", 1)[1].split("long kp_su_allow_uid_profile_sc(", 1)[0]
require("if (max < 0)" in su_list and "if (max && !uids)" in su_list and
        "uid_t list[128] = { 0 };" in su_list and
        "if (n && copy_to_user(" in su_list,
        "SU allowlist copy rejects negative lengths, validates the pointer and initializes the bounded output array")

print("[PASS] Y73S 4.14.141 source compatibility contract")
