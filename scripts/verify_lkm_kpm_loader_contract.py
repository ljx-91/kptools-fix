#!/usr/bin/env python3
"""Fail-closed source checks for the separate LKM KPM ELF loader."""
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


def need(pattern, source, message):
    if not re.search(pattern, source, re.S):
        raise AssertionError(message)


def main():
    module = read("lkm/kpm/module.c")
    relo = read("lkm/kpm/relo.c")

    header = body(module, "static int elf_header_check(")
    for token in ("ELFCLASS64", "ELFDATA2LSB", "EI_VERSION",
                  "e_ehsize", "e_shentsize", "e_shstrndx",
                  "kp_elf_range_valid"):
        need(re.escape(token), header, f"ELF header validation missing {token}")

    ranges = body(module, "static int rewrite_section_headers(")
    need(r"shstr->sh_type\s*!=\s*SHT_STRTAB", ranges, "section-name table type")
    need(r"kp_elf_range_valid\(info->len", ranges, "section file extent bounds")
    need(r"kp_elf_string_valid\(info->secstrings", ranges, "section name termination")
    need(r"sh_addralign.*sh_addralign\s*-\s*1", ranges, "section alignment")

    setup = body(module, "static int setup_load_info(")
    for pattern, message in [
        (r"symsec->sh_entsize\s*!=\s*sizeof\(Elf_Sym\)", "symbol entry size"),
        (r"symsec->sh_link\s*>=\s*info->hdr->e_shnum", "symbol string-table index"),
        (r"strsec->sh_type\s*!=\s*SHT_STRTAB", "symbol string-table type"),
        (r"kp_elf_string_valid\(info->strtab", "symbol name bounds"),
        (r"st_shndx\s*==\s*SHN_XINDEX", "extended symbol index rejection"),
        (r"info->info.base\[info->info.size\s*-\s*1\]\s*!=\s*'\\0'", ".kpm.info termination"),
    ]:
        need(pattern, setup, f"setup_load_info must validate {message}")

    layout = body(module, "static int layout_sections(")
    need(r"get_offset\(", layout, "checked section reservation")
    need(r"kp_align_module_size\(", layout, "checked page alignment")
    sym_layout = body(module, "static int layout_symtab(")
    need(r"UINT_MAX\s*-\s*info->symoffs", sym_layout, "symbol table extent")
    need(r"UINT_MAX\s*-\s*info->stroffs", sym_layout, "string table extent")

    move = body(module, "static int move_module(")
    need(r"shdr->sh_entsize\s*>\s*mod->size", move, "destination offset")
    need(r"shdr->sh_size\s*>\s*mod->size\s*-\s*shdr->sh_entsize", move, "destination section extent")

    dispatch = body(module, "static int apply_relocations(")
    need(r"infosec\s*>=\s*info->hdr->e_shnum", dispatch, "relocation target index")
    need(r"sh_link\s*!=\s*info->index.sym", dispatch, "relocation symbol-table link")

    load = body(module, "long kp_load_module(")
    need(r"len\s*<=\s*0", load, "non-positive in-memory image length")
    path_load = body(module, "long kp_load_module_path(")
    need(r"len\s*<=\s*0\s*\|\|\s*len\s*>\s*INT_MAX", path_load,
         "oversized on-disk image length")

    trampoline = body(module, "int kp_kpm_safe_kallsyms_on_each_symbol(")
    need(r"kp_callback_tramp_slot_alloc", trampoline, "exclusive callback trampoline slot")
    need(r"branch_off\s*>=\s*\(1L\s*<<\s*27\)", trampoline,
         "AArch64 branch immediate range check")
    need(r"kp_callback_tramp_slot_free\(slot\)", trampoline,
         "callback trampoline slot release")

    module_header = read("lkm/kpm/module.h")
    for token in ("KP_MODULE_LOADING", "KP_MODULE_LIVE",
                  "KP_MODULE_UNLOADING", "KP_MODULE_EXITING",
                  "active_calls"):
        need(re.escape(token), module_header, f"module lifecycle definition missing {token}")

    lookup = body(module, "static struct kp_module *kp_module_get(")
    need(r"spin_lock_irqsave", lookup, "module lookup lock")
    need(r"state\s*!=\s*KP_MODULE_LIVE", lookup, "only LIVE modules may be acquired")
    need(r"active_calls\+\+", lookup, "active callback reference acquisition")

    put = body(module, "static void kp_module_put(")
    need(r"spin_lock_irqsave", put, "module reference release lock")
    need(r"active_calls--", put, "active callback reference release")

    unload = body(module, "long kp_unload_module(")
    for pattern, message in [
        (r"KP_MODULE_UNLOADING", "unload state transition"),
        (r"active_calls", "unload active-call check"),
        (r"return\s+-EBUSY", "nonblocking unload retry"),
        (r"KP_MODULE_EXITING", "serialized exit callback"),
        (r"list_del_init", "registry unlink"),
    ]:
        need(pattern, unload, f"unload must implement {message}")
    if "rcu_read_lock" in unload:
        raise AssertionError("unload must not execute exit/free inside an RCU read section")

    reserve = body(module, "long kp_load_module(")
    need(r"KP_MODULE_LOADING", reserve, "load-name reservation state")
    need(r"kp_find_module_locked", reserve, "duplicate-load serialization")
    need(r"mod->state\s*=\s*KP_MODULE_LIVE", reserve, "publish only after successful init")

    ctl0 = body(module, "long kp_module_control0(")
    need(r"kstrdup\(ctl_args", ctl0, "call-local control argument copy")
    need(r"kp_module_get\(", ctl0, "control0 module reference")
    need(r"kp_module_put\(", ctl0, "control0 module reference release")
    if "mod->ctl_args" in ctl0:
        raise AssertionError("control0 must not share mutable module->ctl_args")

    ctl1 = body(module, "long kp_module_control1(")
    need(r"kp_module_get\(", ctl1, "control1 module reference")
    need(r"kp_module_put\(", ctl1, "control1 module reference release")

    events = body(module, "long kp_notify_modules_event(")
    for pattern, message in [
        (r"kcalloc", "event snapshot allocation"),
        (r"active_calls\+\+", "event snapshot reference acquisition"),
        (r"kp_module_put\(", "event callback reference release"),
    ]:
        need(pattern, events, f"event fanout must provide {message}")

    cfi = body(module, "bool kp_kpm_cfi_allowed_addr(")
    need(r"spin_lock_irqsave", cfi, "CFI range traversal lock")
    need(r"pos->text_size", cfi, "CFI range must exclude non-executable module data")
    if "rcu_read_lock" in module:
        raise AssertionError("LKM module registry must not mix plain list writers with RCU readers")

    owner_register = body(module, "int kp_hook_owner_register(")
    need(r"pos->text_size", owner_register,
         "hook callback owner must resolve only to executable text")
    owner_lookup = body(module, "static struct kp_module *kp_module_get_by_addr(")
    need(r"pos->text_size", owner_lookup,
         "kallsyms callback owner must resolve only to executable text")
    for token in ("KP_MODULE_LOADING", "KP_MODULE_LIVE", "KP_MODULE_UNLOADING"):
        need(re.escape(token), owner_lookup, f"kallsyms owner lookup must allow {token}")
    if "KP_MODULE_EXITING" in owner_lookup:
        raise AssertionError("new callback pins must be rejected during EXITING")

    exec_alloc = body(module, "static void *kp_malloc_exec(")
    exec_free = body(module, "static void kp_free_exec(")
    permissions = body(module, "static int kp_clear_bti_gp(")
    kpm_init = body(module, "int kp_kpm_init(void)")
    need(r"switch\s*\(kp_exec_backend\)", exec_alloc,
         "executable allocator must use the selected backend")
    need(r"KP_EXEC_BACKEND_MODULE", exec_alloc, "module allocator backend")
    need(r"KP_EXEC_BACKEND_EXECMEM", exec_alloc, "execmem allocator backend")
    need(r"KP_EXEC_BACKEND_VMALLOC", exec_alloc, "vmalloc allocator backend")
    for token in ("KP_EXEC_BACKEND_MODULE", "KP_EXEC_BACKEND_EXECMEM",
                  "KP_EXEC_BACKEND_VMALLOC"):
        need(re.escape(token), exec_free, f"matching executable free backend {token}")
    need(r"kp_module_alloc\s*&&\s*kp_module_memfree", kpm_init,
         "module allocator/free pair")
    need(r"kp_execmem_alloc\s*&&\s*kp_execmem_free", kpm_init,
         "execmem allocator/free pair")
    need(r"!kp_kpm_init_mm", kpm_init, "init_mm must be available for permission verification")
    need(r"pte_lockptr", permissions, "PTE permission updates must hold the page-table lock")
    need(r"set_pte_at", permissions, "PTE permission update must use set_pte_at")
    need(r"KP_LKM_PTE_PXN.*?KP_LKM_PTE_UXN.*?KP_LKM_PTE_GP", permissions,
         "clear PXN/UXN/BTI GP bits")
    need(r"return\s+-EFAULT", permissions, "unmapped or unsupported PTEs must fail closed")
    need(r"kp_clear_bti_gp\(\(unsigned long\)mod->start,\s*mod->size\)", load,
         "verify KPM image permissions before init")
    need(r"if\s*\(rc\).*?goto free;", load,
         "permission verification failure must prevent KPM init")

    safe_iter = body(module, "int kp_kpm_safe_kallsyms_on_each_symbol(")
    need(r"kp_module_get_by_addr", safe_iter, "kallsyms callback owner acquisition")
    need(r"kp_module_put\(owner\)", safe_iter, "kallsyms callback owner release")

    data = body(relo, "static int reloc_data(")
    need(r"len\s*==\s*64", data, "explicit 64-bit relocation width")
    need(r"1ULL\s*<<\s*len", data, "unsigned 64-bit narrow mask")
    if re.search(r"\(1\s*<<\s*len\)", data):
        raise AssertionError("undefined 32-bit full-width shift reintroduced")

    rela = body(relo, "int kp_apply_relocate_add(")
    for pattern, message in [
        (r"rsec->sh_type\s*!=\s*SHT_RELA", "RELA section type"),
        (r"rsec->sh_entsize\s*!=\s*sizeof\(Elf64_Rela\)", "RELA entry size"),
        (r"symidx\s*>=\s*nsym", "RELA symbol index"),
        (r"rel\[i\]\.r_offset\s*>\s*target->sh_size", "RELA target offset"),
        (r"width\s*>\s*target->sh_size\s*-\s*rel\[i\]\.r_offset", "RELA write extent"),
    ]:
        need(pattern, rela, f"RELA loader must validate {message}")

    need(r"backup\s*=\s*vmalloc\(target->sh_size", rela,
         "RELA application must snapshot target section before writes")
    need(r"memcpy\(backup,\s*\(void \*\)target->sh_addr", rela,
         "RELA transaction must preserve original target bytes")
    need(r"goto rollback", rela, "late relocation failures must roll back")
    need(r"memcpy\(\(void \*\)target->sh_addr,\s*backup", rela,
         "RELA rollback must restore the complete target section")
    need(r"vfree\(backup\)", rela, "RELA snapshot must be released")
    if data.find("return -ERANGE") > data.find("*(s16 *)place"):
        raise AssertionError("data relocation must check overflow before writing")

    rel = body(relo, "int kp_apply_relocate(")
    need(r"return\s*-EOPNOTSUPP", rel, "unimplemented REL must fail closed")

    print("[PASS] LKM ELF64 header, section table and string bounds")
    print("[PASS] LKM symbol table, names and section indexes")
    print("[PASS] LKM checked section layout and destination copy extents")
    print("[PASS] LKM RELA metadata, symbol and target bounds")
    print("[PASS] LKM input-size and concurrent callback trampoline guards")
    print("[PASS] KPM registry reservation, state transitions and active-call lifetime")
    print("[PASS] KPM event snapshots, call-local control args and CFI callback owner pinning")
    print("[PASS] unimplemented REL fails closed")
    print("[PASS] 64-bit relocation mask avoids undefined shifts")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
