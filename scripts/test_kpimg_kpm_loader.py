#!/usr/bin/env python3
"""Host-execute the KPIMG KPM metadata parser and post-layout RELA dispatcher."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def extract_function(source, signature):
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise RuntimeError(f"unterminated function: {signature}")


def main():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("no host C compiler")
    source = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")
    signatures = (
        "static bool elf_range_valid(",
        "static bool elf_string_valid(",
        "static void set_load_error(",
        "static char *get_next_modinfo(",
        "static char *get_modinfo(",
        "static int find_sec(",
        "static void *get_sh_base(",
        "static unsigned long get_sh_size(",
        "static int rewrite_section_headers(",
        "static int setup_load_info(",
        "static int apply_relocations(",
    )
    functions = [extract_function(source, sig) for sig in signatures]
    prefix = r"""
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;
struct module { int unused; };
struct load_info {
    struct {
        const char *base;
        unsigned long size;
        const char *name, *version, *license, *author, *description;
        char error_msg[128];
    } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct { unsigned int sym, str, mod, info; } index;
};
#define logke(...) ((void)0)
#define logkd(...) ((void)0)
#define logki(...) ((void)0)
static int relocation_calls;
static int relocation_result;
static int apply_relocate_add(Elf_Shdr *sections, const char *strtab,
                              unsigned int sym, unsigned int rel,
                              struct module *mod)
{
    (void)sections; (void)strtab; (void)sym; (void)rel; (void)mod;
    relocation_calls++;
    return relocation_result;
}
"""
    tests = r"""
#define IMAGE_SIZE 2048
#define SHOFF 64
#define SHNUM 8
static unsigned char image[IMAGE_SIZE];
static const char section_names[] =
    "\0.shstrtab\0.kpm.init\0.kpm.exit\0.kpm.info\0.strtab\0.symtab\0.rela.init\0";
static const char symbol_names[] = "\0foo\0";
static const char metadata[] = "name=fixture\0version=1.0\0";

static unsigned int name_offset(const char *name)
{
    const char *p = section_names + 1;
    while (p < section_names + sizeof(section_names) && *p) {
        if (!strcmp(p, name)) return (unsigned int)(p - section_names);
        p += strlen(p) + 1;
    }
    return 0xffffffffU;
}

static void reset_fixture(struct load_info *info)
{
    Elf_Ehdr *eh;
    Elf_Shdr *sh;
    Elf_Sym *syms;
    memset(image, 0, sizeof(image));
    memset(info, 0, sizeof(*info));
    eh = (Elf_Ehdr *)image;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_type = ET_REL;
    eh->e_machine = EM_AARCH64;
    eh->e_version = EV_CURRENT;
    eh->e_ehsize = sizeof(*eh);
    eh->e_shoff = SHOFF;
    eh->e_shentsize = sizeof(Elf_Shdr);
    eh->e_shnum = SHNUM;
    eh->e_shstrndx = 1;
    sh = (Elf_Shdr *)(image + SHOFF);

    sh[1].sh_name = name_offset(".shstrtab");
    sh[1].sh_type = SHT_STRTAB;
    sh[1].sh_offset = 1024;
    sh[1].sh_size = sizeof(section_names);
    sh[1].sh_addralign = 1;
    memcpy(image + 1024, section_names, sizeof(section_names));

    sh[2].sh_name = name_offset(".kpm.init");
    sh[2].sh_type = SHT_PROGBITS;
    sh[2].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh[2].sh_offset = 1200;
    sh[2].sh_size = 16;
    sh[2].sh_addralign = 16;

    sh[3].sh_name = name_offset(".kpm.exit");
    sh[3].sh_type = SHT_PROGBITS;
    sh[3].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh[3].sh_offset = 1216;
    sh[3].sh_size = 16;
    sh[3].sh_addralign = 16;

    sh[4].sh_name = name_offset(".kpm.info");
    sh[4].sh_type = SHT_PROGBITS;
    sh[4].sh_flags = SHF_ALLOC;
    sh[4].sh_offset = 1248;
    sh[4].sh_size = 32;
    sh[4].sh_addralign = 1;
    memcpy(image + 1248, metadata, sizeof(metadata));

    sh[5].sh_name = name_offset(".strtab");
    sh[5].sh_type = SHT_STRTAB;
    sh[5].sh_offset = 1280;
    sh[5].sh_size = sizeof(symbol_names);
    sh[5].sh_addralign = 1;
    memcpy(image + 1280, symbol_names, sizeof(symbol_names));

    sh[6].sh_name = name_offset(".symtab");
    sh[6].sh_type = SHT_SYMTAB;
    sh[6].sh_offset = 1320;
    sh[6].sh_size = 2 * sizeof(Elf_Sym);
    sh[6].sh_link = 5;
    sh[6].sh_entsize = sizeof(Elf_Sym);
    sh[6].sh_addralign = 8;
    syms = (Elf_Sym *)(image + 1320);
    syms[1].st_name = 1;
    syms[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    syms[1].st_shndx = 2;
    syms[1].st_size = 4;

    sh[7].sh_name = name_offset(".rela.init");
    sh[7].sh_type = SHT_RELA;
    sh[7].sh_offset = 1400;
    sh[7].sh_size = sizeof(Elf64_Rela);
    sh[7].sh_link = 6;
    sh[7].sh_info = 2;
    sh[7].sh_entsize = sizeof(Elf64_Rela);
    sh[7].sh_addralign = 8;

    info->hdr = eh;
    info->len = sizeof(image);
}

static int setup(struct load_info *info)
{
    reset_fixture(info);
    return setup_load_info(info);
}

static int expect_setup_error(const char *label, void (*mutate)(struct load_info *))
{
    struct load_info info;
    int rc;
    reset_fixture(&info);
    mutate(&info);
    rc = setup_load_info(&info);
    if (!rc) {
        fprintf(stderr, "%s: malformed input accepted\n", label);
        return 1;
    }
    puts(label);
    return 0;
}

static void bad_info_type(struct load_info *info)
{ ((Elf_Shdr *)(image + SHOFF))[4].sh_type = SHT_NOBITS; }
static void empty_info(struct load_info *info)
{ ((Elf_Shdr *)(image + SHOFF))[4].sh_size = 0; }
static void unterminated_info(struct load_info *info)
{ image[1248 + 31] = 'X'; }
static void nonexec_init(struct load_info *info)
{ ((Elf_Shdr *)(image + SHOFF))[2].sh_flags = SHF_ALLOC; }
static void empty_name(struct load_info *info)
{ memcpy(image + 1248, "name=\0version=1.0\0", 18); }
static void empty_version(struct load_info *info)
{ memcpy(image + 1248, "name=fixture\0version=\0", 22); }
static void bad_rela_entsize(struct load_info *info)
{ ((Elf_Shdr *)(image + SHOFF))[7].sh_entsize = 1; }
static void bad_rela_size(struct load_info *info)
{ ((Elf_Shdr *)(image + SHOFF))[7].sh_size--; }
static void bad_symstr_first_byte(struct load_info *info)
{ image[1280] = 'X'; }
static void multiple_symtabs(struct load_info *info)
{
    Elf_Ehdr *eh = (Elf_Ehdr *)image;
    Elf_Shdr *sh = (Elf_Shdr *)(image + SHOFF);
    eh->e_shnum = 9;
    sh[8] = sh[6];
    sh[8].sh_offset = 1440;
}

int main(void)
{
    int failed = 0;
    struct load_info info;
    struct module mod = {0};
    Elf_Shdr *sh;

    if (setup(&info) || strcmp(info.info.name, "fixture") ||
        strcmp(info.info.version, "1.0") || !info.info.base ||
        !info.info.license == 0) {
        fprintf(stderr, "valid KPIMG metadata fixture rejected or parsed incorrectly: %s\n",
                info.info.error_msg);
        return 1;
    }
    puts("[PASS] KPIMG valid metadata, symbols and RELA accepted");

    failed |= expect_setup_error("[PASS] non-PROGBITS .kpm.info rejected", bad_info_type);
    failed |= expect_setup_error("[PASS] empty .kpm.info rejected", empty_info);
    failed |= expect_setup_error("[PASS] unterminated .kpm.info rejected", unterminated_info);
    failed |= expect_setup_error("[PASS] non-executable .kpm.init rejected", nonexec_init);
    failed |= expect_setup_error("[PASS] empty module name rejected", empty_name);
    failed |= expect_setup_error("[PASS] empty module version rejected", empty_version);
    failed |= expect_setup_error("[PASS] malformed RELA entry size rejected before layout", bad_rela_entsize);
    failed |= expect_setup_error("[PASS] non-integral RELA size rejected before layout", bad_rela_size);
    failed |= expect_setup_error("[PASS] non-NUL symbol string table rejected", bad_symstr_first_byte);
    failed |= expect_setup_error("[PASS] multiple SYMTAB sections rejected", multiple_symtabs);

    if (setup(&info)) return 1;
    sh = info.sechdrs;
    sh[7].sh_entsize = ~0UL; /* layout_sections() rewrites this field */
    relocation_calls = 0;
    if (apply_relocations(&mod, &info) || relocation_calls != 1) {
        fprintf(stderr, "post-layout RELA was rejected: calls=%d\n", relocation_calls);
        return 1;
    }
    puts("[PASS] valid RELA still dispatches after sh_entsize is repurposed");

    if (setup(&info)) return 1;
    info.sechdrs[7].sh_type = SHT_REL;
    relocation_calls = 0;
    if (apply_relocations(&mod, &info) != -ENOEXEC || relocation_calls) return 1;
    puts("[PASS] unsupported REL remains fail-closed");

    if (setup(&info)) return 1;
    info.sechdrs[7].sh_info = 99;
    if (apply_relocations(&mod, &info) != -ENOEXEC) return 1;
    puts("[PASS] invalid RELA target section rejected");

    if (setup(&info)) return 1;
    info.sechdrs[7].sh_link = 5;
    if (apply_relocations(&mod, &info) != -ENOEXEC) return 1;
    puts("[PASS] mismatched RELA symbol-table link rejected");
    return failed;
}
"""
    code = prefix + "\n" + "\n".join(functions) + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kpimg-kpm-loader-") as tmp:
        cfile = Path(tmp) / "kpimg_loader.c"
        binary = Path(tmp) / "kpimg_loader"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-function",
                        "-Wno-sign-compare", str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] production KPIMG KPM parser and relocation dispatcher executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
