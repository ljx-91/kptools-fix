#!/usr/bin/env python3
"""Execute the production KPIMG setup_load_info() parser on synthetic ELF64 files."""
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
        "static int elf_header_check(",
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
#define elf_check_arch(hdr) ((hdr)->e_machine == EM_AARCH64)
#define logke(...) ((void)0)
#define logkd(...) ((void)0)
"""
    tests = r"""
#define IMAGE_SIZE 2048
#define SHOFF 64
#define SHNUM 8
static unsigned char image[IMAGE_SIZE];
static const char section_names[] =
    "\0.shstrtab\0.kpm.init\0.kpm.exit\0.kpm.info\0.strtab\0.symtab\0.rela.init\0";
static const char symbol_names[] = "\0foo\0";
static const char module_info[] = "name=fixture\0version=1.0\0";

static unsigned int name_offset(const char *name)
{
    const char *p = section_names + 1;
    const char *end = section_names + sizeof(section_names);
    while (p < end && *p) {
        if (!strcmp(p, name))
            return (unsigned int)(p - section_names);
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
    sh[4].sh_size = sizeof(module_info);
    sh[4].sh_addralign = 1;
    memcpy(image + 1248, module_info, sizeof(module_info));

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
    syms[1].st_value = 0;
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

static int run_case(const char *name, int expected)
{
    struct load_info info;
    int rc;
    reset_fixture(&info);
    rc = elf_header_check(&info);
    if (!rc) rc = setup_load_info(&info);
    if ((rc == 0) != (expected == 0)) {
        fprintf(stderr, "%s: expected %d-class result, got %d (%s)\n",
                name, expected, rc, info.info.error_msg);
        return 1;
    }
    if (!rc && (!info.index.sym || info.index.sym != 6 ||
                info.index.str != 5 || strcmp(info.info.name, "fixture") ||
                strcmp(info.info.version, "1.0"))) {
        fprintf(stderr, "%s: parser output indices/info mismatch\n", name);
        return 1;
    }
    puts(name);
    return 0;
}

int main(void)
{
    int failed = 0;
    struct load_info info;
    Elf_Sym *syms;

    failed |= run_case("[PASS] KPIMG valid metadata, SYMTAB/STRTAB and RELA accepted", 0);

    reset_fixture(&info);
    ((Elf_Ehdr *)image)->e_shoff = SHOFF + 1;
    if (elf_header_check(&info) == 0) return 1;
    puts("[PASS] unaligned section-header table rejected");

    reset_fixture(&info);
    ((Elf_Ehdr *)image)->e_shstrndx = SHN_UNDEF;
    if (elf_header_check(&info) == 0) return 1;
    puts("[PASS] undefined section-name table index rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[2].sh_offset++;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] misaligned file-backed section rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    memcpy(image + 1248, "name=\0version=1.0\0", sizeof("name=\0version=1.0\0"));
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] empty module name rejected by bounded modinfo parser");

    reset_fixture(&info);
    elf_header_check(&info);
    memcpy(image + 1248, "name=fixture\0version=\0", sizeof("name=fixture\0version=\0"));
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] empty module version rejected by bounded modinfo parser");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[6].sh_entsize = 1;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] incorrect SYMTAB entry size rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[6].sh_size--;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] non-integral SYMTAB size rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[6].sh_link = 4;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] SYMTAB link to non-STRTAB rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    syms = (Elf_Sym *)(image + 1320);
    syms[1].st_name = 99;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] symbol name offset outside STRTAB rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[5].sh_size = 4;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] unterminated symbol name rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    syms = (Elf_Sym *)(image + 1320);
    syms[1].st_shndx = 99;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] out-of-range ordinary symbol section index rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    syms = (Elf_Sym *)(image + 1320);
    syms[1].st_shndx = SHN_XINDEX;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] SHN_XINDEX rejected");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[7].sh_entsize = 1;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] incorrect RELA entry size rejected before layout");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[7].sh_size--;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] non-integral RELA size rejected before layout");

    reset_fixture(&info);
    elf_header_check(&info);
    info.sechdrs[6].sh_link = 99;
    if (setup_load_info(&info) == 0) return 1;
    puts("[PASS] out-of-range SYMTAB string-table link rejected");

    return failed;
}
"""
    code = prefix + "\n".join(functions) + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kpimg-setup-load-info-") as tmp:
        cfile = Path(tmp) / "setup_load_info.c"
        binary = Path(tmp) / "setup_load_info"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-type-limits",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] production KPIMG setup_load_info parser executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
