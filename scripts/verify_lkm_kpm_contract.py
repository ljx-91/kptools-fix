#!/usr/bin/env python3
"""Fail-closed source contract checks for the independent LKM KPM loader."""
from pathlib import Path
import re
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


def require(pattern, source, message):
    if not re.search(pattern, source, re.S):
        raise AssertionError(message)


def main():
    module = read("lkm/kpm/module.c")
    relo = read("lkm/kpm/relo.c")
    header = read("lkm/kpm/module.h")
    workflow = read(".github/workflows/build.yml")
    hook_source = read("kernel/base/hook.c")
    hook_header = read("kernel/include/hook.h")
    secpass = read("lkm/infra/secpass.c")
    core_init = read("lkm/core/init.c")

    elf = body(module, "static int elf_header_check(")
    for token in ("ELFMAG", "ELFCLASS64", "ELFDATA2LSB", "EV_CURRENT",
                  "e_ehsize", "ET_REL", "EM_AARCH64", "e_shentsize",
                  "e_shstrndx", "kp_elf_range_valid"):
        require(re.escape(token), elf, f"LKM ELF header validation missing {token}")

    rewrite = body(module, "static int rewrite_section_headers(")
    require(r"shstr->sh_type\s*!=\s*SHT_STRTAB", rewrite,
            "LKM section-name table type must be checked")
    require(r"kp_elf_range_valid\(info->len", rewrite,
            "LKM section file ranges must be checked")
    require(r"kp_elf_string_valid\(info->secstrings", rewrite,
            "LKM section names must be NUL-bounded")
    require(r"sh_addralign\s*>\s*1", rewrite,
            "LKM section alignment must be validated")

    setup = body(module, "static int setup_load_info(")
    require(r"relsec->sh_type\s*==\s*SHT_RELA[\s\S]*?relsec->sh_entsize\s*!=\s*sizeof\(Elf64_Rela\)[\s\S]*?relsec->sh_size\s*%\s*sizeof\(Elf64_Rela\)", setup,
            "original RELA entry size and extent must be validated before layout")
    for pattern, message in (
        (r"symsec->sh_entsize\s*!=\s*sizeof\(Elf_Sym\)", "symbol entry size"),
        (r"symsec->sh_size\s*%\s*sizeof\(Elf_Sym\)", "symbol table divisibility"),
        (r"strsec->sh_type\s*!=\s*SHT_STRTAB", "symbol string-table type"),
        (r"kp_elf_string_valid\(info->strtab", "symbol-name string bounds"),
        (r"syms\[n\]\.st_shndx\s*>=\s*info->hdr->e_shnum", "symbol section index"),
    ):
        require(pattern, setup, f"LKM parser must validate {message}")

    layout = body(module, "static int layout_sections(")
    require(r"get_offset\(&mod->size", layout, "LKM section layout must use checked offsets")
    require(r"section->sh_entsize\s*==\s*~0UL", layout,
            "LKM layout must reject unplaced allocatable sections")
    offset = body(module, "static int get_offset(")
    require(r"align\s*&\s*\(align\s*-\s*1\)", offset,
            "LKM layout must validate power-of-two alignment")
    require(r"UINT_MAX\s*-\s*start", offset,
            "LKM layout must guard section-size addition overflow")
    move = body(module, "static int move_module(")
    require(r"shdr->sh_size\s*>\s*mod->size\s*-\s*shdr->sh_entsize", move,
            "LKM section copy must be bounded by allocated image")

    dispatch = body(module, "static int apply_relocations(")
    require(r"infosec\s*>=\s*info->hdr->e_shnum", dispatch,
            "LKM relocation target index must be bounded")
    require(r"sh_link\s*!=\s*info->index.sym", dispatch,
            "LKM relocation symbol-table link must be checked")
    require(r"kp_apply_relocate\(", dispatch,
            "LKM REL dispatch must fail closed through its helper")

    data = body(relo, "static int reloc_data(")
    require(r"len\s*==\s*64", data, "LKM 64-bit relocation mask must be explicit")
    require(r"~0ULL", data, "LKM 64-bit relocation mask must avoid full-width shifts")
    require(r"1ULL\s*<<\s*len", data, "LKM narrow mask must use a 64-bit unsigned shift")
    if re.search(r"\(1\s*<<\s*len\)", data):
        raise AssertionError("undefined signed 32-bit relocation shift reintroduced")

    # setup_load_info validates the original ELF sh_entsize before
    # layout_symtab repurposes that field as a destination offset.
    require(r"symsec->sh_entsize\s*!=\s*sizeof\(Elf_Sym\)", setup,
            "original ELF symbol entry size must be validated before layout")
    rela = body(relo, "int kp_apply_relocate_add(")
    if "rsec->sh_entsize" in rela:
        raise AssertionError("RELA apply must not inspect sh_entsize after layout repurposes it")
    if re.search(r"symsec->sh_entsize\s*!=", rela):
        raise AssertionError("RELA must not treat the rewritten in-image symbol offset as ELF sh_entsize")
    for pattern, message in (
        (r"sh_size\s*%\s*sizeof\(Elf64_Rela\)", "RELA table divisibility"),
        (r"symidx\s*>=\s*nsym", "RELA symbol index"),
        (r"r_offset\s*>\s*target->sh_size", "RELA target offset"),
        (r"width\s*>\s*target->sh_size\s*-\s*rel\[i\]\.r_offset", "RELA write width"),
        (r"backup\s*=\s*vmalloc", "RELA transaction snapshot"),
        (r"goto rollback", "RELA rollback path"),
        (r"memcpy\(\(void \*\)target->sh_addr,\s*backup", "RELA rollback restore"),
    ):
        require(pattern, rela, f"LKM relocation must validate {message}")

    rel = body(relo, "int kp_apply_relocate(")
    require(r"return\s*-EOPNOTSUPP", rel,
            "unsupported LKM REL must fail closed, never report success")

    # flush_icache_range cleans the written range to PoU; __flush_icache_all()
    # uses ARM64 IC IALLUIS and broadcasts I-cache invalidation to all
    # inner-shareable PEs. This avoids resolving a non-existent 4.14 symbol.
    flush = body(module, "static void kp_flush_kpm_icache(")
    require(r"flush_icache_range\s*\(\s*base\s*,\s*base\s*\+\s*size\s*\)", flush,
            "KPM publication must clean the generated code range")
    require(r"__flush_icache_all\s*\(\s*\)", flush,
            "KPM publication must broadcast I-cache invalidation to all PEs")
    if "kp_flush_icache_all_fn" in module:
        raise AssertionError("KPM must not resolve flush_icache_all as a kallsyms symbol")
    init = body(module, "int kp_kpm_init(")
    require(r"kp_module_alloc\s*&&\s*kp_module_memfree", init,
            "KPM loader must select the executable module allocator")
    require(r"kp_flush_kpm_icache\(words,\s*KP_CALLBACK_TRAMP_SLOT_SIZE\)", module,
            "callback trampoline writes must use the shared I-cache flush helper")

    registry = body(module, "static struct kp_module *kp_module_get(")
    require(r"spin_lock_irqsave", registry, "LKM module lookup must hold registry lock")
    require(r"mod->state\s*!=\s*KP_MODULE_LIVE", registry,
            "LKM external calls must reject non-live modules")
    load = body(module, "long kp_load_module(")
    require(r"spin_lock_irqsave[\s\S]*?kp_find_module_locked[\s\S]*?list_add_tail",
            load, "LKM name reservation must be serialized before init")
    require(r"mod->state\s*=\s*KP_MODULE_LOADING", load,
            "LKM registry must publish LOADING state")
    unload = body(module, "long kp_unload_module(")
    require(r"KP_MODULE_EXITING\s*&&\s*!mod->exit_called", unload,
            "concurrent LKM unload must not call exit twice")
    require(r"mod->active_calls\s*\|\|\s*mod->hook_refs", unload,
            "LKM unload must retain images while callbacks or hooks reference them")
    require(r"KP_MODULE_EXITING", header, "LKM lifecycle states must be declared")
    require(r"kp_kpm_owner_pin|kp_hook_owner_register", module,
            "LKM must expose callback owner pinning")

    # Executable-memory permission changes are architecture-sensitive. Keep
    # the page-table walk and all runtime prerequisites fail-closed.
    pte = body(module, "static int kp_update_bti_gp(")
    for pattern, message in (
        (r"size\s*>\s*ULONG_MAX\s*-\s*base", "PTE range overflow"),
        (r"pgd_none\(\*pgd\)|pgd_bad\(\*pgd\)", "PGD validity"),
        (r"p4d_none\(\*p4d\)|p4d_bad\(\*p4d\)", "P4D validity"),
        (r"pud_none\(\*pud\)|pud_bad\(\*pud\)|pud_sect\(\*pud\)", "PUD validity"),
        (r"pmd_none\(\*pmd\)|pmd_bad\(\*pmd\)|pmd_sect\(\*pmd\)", "PMD validity"),
        (r"pte_lockptr\(kp_kpm_init_mm,\s*pmd\)", "PTE lock"),
        (r"pte_present\(\*pte\)", "present PTE"),
        (r"set_pte_at\(kp_kpm_init_mm", "PTE update"),
        (r"flush_tlb_kernel_range\(addr,\s*addr\s*\+\s*PAGE_SIZE\)", "kernel TLB invalidation"),
    ):
        require(pattern, pte, f"KPM executable PTE walk must validate {message}")

    free_exec = body(module, "static void kp_free_exec(")
    require(r"if\s*\(kp_restore_nx_gp\(", free_exec,
            "KPM executable pages must be restored before release")
    require(r"return;", free_exec,
            "KPM pages must be retained if NX/BTI restoration fails")

    no_mm = body(module, "static bool kp_kpm_can_skip_init_mm(")
    require(r"#if\s+defined\(PTE_GP\)[\s\S]*?return\s+false[\s\S]*?KP_EXEC_BACKEND_MODULE[\s\S]*?KP_EXEC_BACKEND_EXECMEM",
            no_mm, "init_mm bypass is limited to non-BTI executable allocators")
    init_runtime = body(module, "int kp_kpm_init(")
    require(r"!kp_kpm_init_mm\s*&&\s*!kp_kpm_can_skip_init_mm\(\)",
            init_runtime, "without init_mm only verified executable backends are allowed")
    require(r"kp_module_alloc\s*&&\s*kp_module_memfree", init_runtime,
            "matched module allocator/free pair")
    require(r"kp_execmem_alloc\s*&&\s*kp_execmem_free", init_runtime,
            "matched execmem allocator/free pair")
    require(r"kp_set_memory_x\s*&&\s*kp_set_memory_nx", init_runtime,
            "vmalloc fallback requires both executable and NX transitions")
    require(r"perm_rc\s*=\s*kp_clear_bti_gp", init_runtime,
            "callback trampoline permission validation")
    require(r"if\s*\(perm_rc\)[\s\S]*?kp_callback_tramp\s*=\s*NULL",
            init_runtime, "disable unsafe callback trampoline")

    load_gate = body(module, "long kp_load_module(")
    require(r"kp_exec_backend\s*==\s*KP_EXEC_BACKEND_NONE[\s\S]*?!kp_kpm_init_mm\s*&&\s*!kp_kpm_can_skip_init_mm\(\)",
            load_gate, "KPM loading must fail closed unless the allocator supports safe no-init_mm execution")

    # A target with Clang CFI must never expose KPM entry points unless the
    # slowpath bypass needed for unregistered KPM text was installed.
    secpass = read("lkm/infra/secpass.c")
    bypass = body(secpass, "int kp_bypass_kcfi(void)")
    require(r"cfi_enforcement_hooked", bypass,
            "CFI bypass must track successful enforcement-hook installation")
    require(r"#ifdef CONFIG_CFI_CLANG[\s\S]*?!cfi_enforcement_hooked",
            bypass, "Clang CFI builds must require an enforcing slowpath hook")
    require(r"if\s*\(rc\)[\s\S]*?kp_bypass_kcfi_exit\(\)[\s\S]*?return rc",
            bypass, "partial CFI hook installation must be rolled back on failure")
    require(r"if\s*\(!rc\)[\s\S]*?rc = hook_rc",
            bypass, "CFI hook failures must not be overwritten by later hook attempts")

    core_init = read("lkm/core/init.c")
    # Linux 4.14 predates module namespaces; the import must be conditional
    # on the target headers defining MODULE_IMPORT_NS, not only kernel version.
    require(r"#ifdef\s+MODULE_IMPORT_NS[\s\S]*?MODULE_IMPORT_NS\(",
            core_init, "legacy kernels without MODULE_IMPORT_NS must still compile")
    require(r"#if\s+LINUX_VERSION_CODE\s*>=\s*KERNEL_VERSION\(6,\s*13,\s*0\)[\s\S]*?MODULE_IMPORT_NS\(\"VFS_internal",
            core_init, "new module namespace API must use the string form")

    init_entry = body(core_init, "int __init kernelpatch_init(")
    require(r"#ifdef CONFIG_CFI_CLANG[\s\S]*?KPM loader disabled: CFI bypass is unavailable",
            init_entry, "Clang CFI builds must disable KPM when CFI bypass setup fails")
    require(r"else\s*\{[\s\S]*?rc = kp_kpm_init\(\)",
            init_entry, "Clang CFI builds may initialize KPM only after bypass success")

    # module_init() failure does not call module_exit(); hooks installed by
    # a partially completed init must be explicitly unwound before returning.
    # CFI bypass setup is attempted before the only remaining fallible
    # publication steps. Its teardown is unconditional: secpass tracks each
    # installed target internally, including uncertain patch outcomes.
    require(r"BUG_ON\(kp_bypass_kcfi_exit\(\)\)", init_entry,
            "failed LKM init must fail closed if any CFI hook cannot be removed")
    require(r"bool\s+supercall_installed\s*=\s*false", init_entry,
            "LKM init must track whether the supercall hook was installed")
    require(r"bool\s+sucompat_installed\s*=\s*false", init_entry,
            "LKM init must track whether the sucompat hook was installed")
    require(r"kp_supercall_install\(\)[\s\S]*?if\s*\(rc\)\s*goto\s+err_unwind",
            init_entry, "supercall install failure must enter init rollback")
    require(r"kp_sucompat_hook_init\(\)[\s\S]*?if\s*\(rc\)\s*goto\s+err_unwind",
            init_entry, "sucompat install failure must enter init rollback")
    require(r"err_unwind:[\s\S]*?if\s*\(supercall_installed\)\s*kp_supercall_uninstall\(\)[\s\S]*?if\s*\(sucompat_installed\)\s*BUG_ON\(kp_sucompat_hook_exit\(\)\)[\s\S]*?if\s*\(kpm_initialized\)\s*kp_kpm_exit\(\)[\s\S]*?BUG_ON\(kp_bypass_kcfi_exit\(\)\)[\s\S]*?return rc",
            init_entry, "failed module init must unwind supercall, sucompat and KPM, then fail closed on CFI teardown")

    # If a later init stage fails, release the private KPM trampoline before
    # the loader frees the LKM. The supercall must be the final fallible step.
    require(r"kp_kpm_init\(\)[\s\S]*?else\s+kpm_initialized\s*=\s*true",
            init_entry, "successful KPM init must be tracked for rollback")
    require(r"kp_sucompat_hook_init\(\)[\s\S]*?kp_supercall_install\(\)",
            init_entry, "supercall must be published after the other fallible hook setup")
    require(r"kp_supercall_install\(\)[\s\S]*?kp_manager_init\(\)",
            init_entry, "no fallible init stage may follow publication of the supercall")
    require(r"if\s*\(kpm_initialized\)\s*kp_kpm_exit\(\)",
            init_entry, "failed LKM init must release a successfully initialized private KPM runtime")
    kpm_exit = body(module, "void kp_kpm_exit(void)")
    require(r"WRITE_ONCE\(kp_kpm_ready,\s*false\)[\s\S]*?kp_free_exec\(kp_callback_tramp,\s*kp_callback_tramp_size\)",
            kpm_exit, "KPM rollback must disable callbacks before freeing its trampoline")
    require(r"kp_callback_tramp\s*=\s*NULL[\s\S]*?kp_exec_backend\s*=\s*KP_EXEC_BACKEND_NONE",
            kpm_exit, "KPM rollback must clear stale runtime pointers and allocator state")

    # CFI teardown must know whether original kernel text was restored.
    checked_unhook = body(hook_source, "int unhook_checked(void *func)")
    require(r"hook_uninstall\(hook\)[\s\S]*?if\s*\(!rc\)[\s\S]*?return\s+rc",
            checked_unhook, "checked unhook must propagate text restoration failures")
    require(r"int\s+unhook_checked\(void\s*\*func\)", hook_header,
            "checked unhook API must be declared for LKM callers")
    legacy_unhook = body(hook_source, "void unhook(void *func)")
    require(r"unhook_checked\(func\)", legacy_unhook,
            "legacy unhook API must delegate to checked implementation")
    module_target = body(secpass, "static bool kp_target_in_module(unsigned long target)")
    require(r"THIS_MODULE->mem\[MOD_TEXT\]", module_target,
            "modern module CFI allowlist must cover executable text only")
    require(r"core_layout\.text_size", module_target,
            "legacy module CFI allowlist must match the registered text extent")
    require(r"MOD_TEXT", module_target,
            "module CFI allowlist must select the text memory type")
    require(r"return\s+THIS_MODULE->core_layout\.base", module_target,
            "legacy CFI allowlist must use the bounded executable text range")
    if re.search(r"MOD_MEM_NUM_TYPES|core_layout\.size|init_layout", module_target):
        raise AssertionError("module CFI allowlist must not trust data or init allocation ranges")

    cfi_exit = body(secpass, "int kp_bypass_kcfi_exit(void)\n{")
    require(r"unhook_checked\(\(void\s*\*\)kp_find_check_fn_addr\)",
            cfi_exit, "find_check_fn teardown must check patch restoration")
    require(r"unhook_checked\(\(void\s*\*\)kp_report_cfi_failure_addr\)",
            cfi_exit, "report_cfi_failure teardown must check patch restoration")
    require(r"unhook_checked\(\(void\s*\*\)kp_cfi_slowpath_addr\)",
            cfi_exit, "CFI slowpath teardown must check patch restoration")
    require(r"kp_find_check_fn_addr\s*=\s*0",
            cfi_exit, "CFI hook state may be cleared only after successful or absent removal")
    cfi_install = body(secpass, "int kp_bypass_kcfi(void)")
    require(r"kp_find_check_fn_addr\s*=\s*addr[\s\S]*?hook\(",
            cfi_install, "uncertain CFI hook installs must retain their target address for rollback")
    require(r"kp_cfi_slowpath_addr\s*=\s*addr[\s\S]*?hook\(",
            cfi_install, "uncertain slowpath installs must retain their target address for rollback")
    init_exit = body(core_init, "static void __exit kernelpatch_exit(void)")
    require(r"BUG_ON\(kp_bypass_kcfi_exit\(\)\)",
            init_exit, "module unload must fail closed if CFI text restoration fails")
    require(r"err_unwind:[\s\S]*?BUG_ON\(kp_bypass_kcfi_exit\(\)\)",
            core_init, "module init failure must not return while a CFI branch may remain installed")

    unload_gate = body(module, "long kp_unload_module(")
    require(r"mod->active_calls\s*\|\|\s*mod->hook_refs[\s\S]*?return\s*-EBUSY",
            unload_gate, "KPM image must remain resident while callbacks or hooks reference it")

    require(r"y73s-cred-layout-guards-20261108", workflow,
            "LKM contract workflow must trigger on the selected Y73S branch")
    require(r"verify_lkm_kpm_contract\.py", workflow,
            "selected branch CI must execute the LKM contract verifier")
    require(r'GITHUB_REF_NAME[\s\S]*?y73s-cred-layout-guards-20261108[\s\S]*?export Y73S_TARGET=1',
            workflow, "selected branch KPIMG build must enable the Y73S target profile")

    print("[PASS] LKM ELF header, section and symbol bounds")
    print("[PASS] checked LKM section layout and copy extents")
    print("[PASS] bounded RELA metadata, symbols, targets and rollback")
    print("[PASS] unsupported REL fails closed; 64-bit shifts are defined")
    print("[PASS] cross-CPU I-cache flush required for KPM and trampolines")
    print("[PASS] serialized registry, callback pins and unload lifetime")
    print("[PASS] selected Y73S branch runs the independent LKM contract")
    

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        raise SystemExit(1)
