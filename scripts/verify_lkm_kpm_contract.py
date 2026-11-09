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
    if re.search(r"symsec->sh_entsize\s*!=", rela):
        raise AssertionError("RELA must not treat the rewritten in-image symbol offset as ELF sh_entsize")
    for pattern, message in (
        (r"sh_entsize\s*!=\s*sizeof\(Elf64_Rela\)", "RELA entry size"),
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

    # Executable KPM and trampoline code may run on any CPU. Require the
    # kernel's architecture-aware inner-shareable I-cache flush, not local
    # "ic iallu" invalidation.
    flush = body(module, "static void kp_flush_kpm_icache(")
    require(r"kp_flush_icache_all_fn\s*\(\s*\)", flush,
            "KPM publication must call the kernel-wide I-cache flush")
    if re.search(r'ic\s+iallu', flush):
        raise AssertionError("local-only I-cache invalidation is insufficient for KPM publication")
    init = body(module, "int kp_kpm_init(")
    require(r"!kp_flush_icache_all_fn", init,
            "KPM loader must fail closed when flush_icache_all is unavailable")
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

    init_runtime = body(module, "int kp_kpm_init(")
    for pattern, message in (
        (r"if\s*\(!kp_kpm_init_mm\)", "init_mm"),
        (r"if\s*\(!kp_flush_icache_all_fn\)", "cross-CPU I-cache flush"),
        (r"kp_module_alloc\s*&&\s*kp_module_memfree", "matched module allocator/free pair"),
        (r"kp_execmem_alloc\s*&&\s*kp_execmem_free", "matched execmem allocator/free pair"),
        (r"else if\s*\(kp_set_memory_x\)", "permission-capable vmalloc fallback"),
        (r"perm_rc\s*=\s*kp_clear_bti_gp", "callback trampoline PTE verification"),
        (r"if\s*\(perm_rc\)[\s\S]*?kp_callback_tramp\s*=\s*NULL", "disable unsafe callback trampoline"),
    ):
        require(pattern, init_runtime, f"KPM runtime initialization must require {message}")

    load_gate = body(module, "long kp_load_module(")
    require(r"kp_exec_backend\s*==\s*KP_EXEC_BACKEND_NONE\s*\|\|\s*!kp_kpm_init_mm",
            load_gate, "KPM loading must fail closed without verified allocator and init_mm")

    unload_gate = body(module, "long kp_unload_module(")
    require(r"mod->active_calls\s*\|\|\s*mod->hook_refs[\s\S]*?return\s*-EBUSY",
            unload_gate, "KPM image must remain resident while callbacks or hooks reference it")

    legacy_pgtable = read("lkm/include/kp_lkm.h")
    require(r"LINUX_VERSION_CODE\\s*<\\s*KERNEL_VERSION\\(5,\\s*8,\\s*0\\)", legacy_pgtable,
            "legacy ARM64 must define a version-gated folded p4d bridge")
    require(r"typedef\\s+pgd_t\\s+p4d_t", legacy_pgtable,
            "Linux 4.14 ARM64 must map folded p4d to pgd_t")
    require(r"#define\\s+p4d_offset\\(pgd,\\s*address\\)\\s+\\(\\(p4d_t\\s*\\*\\)\\(pgd\\)\\)", legacy_pgtable,
            "legacy folded p4d offset must preserve the direct PGD-to-PUD walk")
    require(r"#define\\s+p4d_none\\(p4d\\)\\s+\\(0\\)", legacy_pgtable,
            "folded p4d entries must never be reported absent")
    require(r"#define\\s+p4d_bad\\(p4d\\)\\s+\\(0\\)", legacy_pgtable,
            "folded p4d entries must never be reported bad")

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
