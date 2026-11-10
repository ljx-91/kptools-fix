#!/usr/bin/env python3
"""Host-execute both production KPM simplify_symbols() implementations."""
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

    lkm_source = (ROOT / "lkm/kpm/module.c").read_text(encoding="utf-8")
    kpimg_source = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")
    lkm_fn = extract_function(lkm_source, "static int simplify_symbols(struct kp_module *")
    kpimg_fn = extract_function(kpimg_source, "static int simplify_symbols(struct module *")
    lkm_fn = lkm_fn.replace("simplify_symbols(", "simplify_symbols_lkm(", 1)
    lkm_fn = lkm_fn.replace("set_load_error(", "set_load_error_lkm(")
    kpimg_fn = kpimg_fn.replace("simplify_symbols(", "simplify_symbols_kpimg(", 1)
    kpimg_fn = kpimg_fn.replace("set_load_error(", "set_load_error_kpimg(")

    prefix = r"""
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef Elf64_Sym Elf_Sym;
typedef Elf64_Shdr Elf_Shdr;
struct kp_module { int unused; };
struct module { int unused; };

struct kp_load_info {
    struct { char error_msg[128]; } info;
    const Elf64_Ehdr *hdr;
    Elf_Shdr *sechdrs;
    char *strtab;
    struct { unsigned int sym, str, mod, info; } index;
};
struct load_info {
    struct { char error_msg[128]; } info;
    const Elf64_Ehdr *hdr;
    Elf_Shdr *sechdrs;
    char *strtab;
    struct { unsigned int sym, str, mod, info; } index;
};

#define logkd(...) ((void)0)
#define logke(...) ((void)0)
static void set_load_error_lkm(struct kp_load_info *info, const char *msg)
{
    if (!info->info.error_msg[0])
        snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", msg);
}
static void set_load_error_kpimg(struct load_info *info, const char *msg)
{
    if (!info->info.error_msg[0])
        snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", msg);
}
static unsigned long kp_kpm_symbol_lookup(const char *name)
{
    return !strcmp(name, "kp_only") ? 0x11110000UL : 0;
}
static unsigned long kallsyms_lookup_name(const char *name)
{
    return !strcmp(name, "kernel_only") ? 0x22220000UL : 0;
}
static unsigned long symbol_lookup_name(const char *name)
{
    if (!strcmp(name, "kp_only")) return 0x11110000UL;
    if (!strcmp(name, "kernel_only")) return 0x22220000UL;
    return 0;
}
"""
    tests = r"""
static const char names[] =
    "\0defined\0absolute\0kp_only\0kernel_only\0missing\0common\0badidx\0";
static Elf64_Ehdr ehdr;
static Elf_Shdr sections[4];
static Elf64_Sym symbols[3];
static char strtab[sizeof(names)];

static unsigned int name_offset(const char *name)
{
    const char *p = names + 1;
    while (p < names + sizeof(names) && *p) {
        if (!strcmp(p, name)) return (unsigned int)(p - names);
        p += strlen(p) + 1;
    }
    return 0;
}

static void reset_fixture(void)
{
    memset(&ehdr, 0, sizeof(ehdr));
    memset(sections, 0, sizeof(sections));
    memset(symbols, 0, sizeof(symbols));
    memcpy(strtab, names, sizeof(names));
    ehdr.e_shnum = 4;
    sections[1].sh_type = SHT_SYMTAB;
    sections[1].sh_addr = (unsigned long)symbols;
    sections[1].sh_size = 2 * sizeof(symbols[0]);
    sections[2].sh_addr = 0x100000UL;
    sections[2].sh_size = 16;
    symbols[1].st_name = name_offset("defined");
    symbols[1].st_shndx = 2;
    symbols[1].st_value = 4;
    symbols[1].st_size = 8;
}

static int run_lkm_case(const char *label, const char *name,
                        unsigned int shndx, unsigned long value,
                        unsigned long size, unsigned long secbase,
                        unsigned long secsize, int expected_rc,
                        unsigned long expected_value)
{
    struct kp_load_info info;
    int rc;
    reset_fixture();
    memset(&info, 0, sizeof(info));
    info.hdr = &ehdr;
    info.sechdrs = sections;
    info.strtab = strtab;
    info.index.sym = 1;
    symbols[1].st_name = name_offset(name);
    symbols[1].st_shndx = shndx;
    symbols[1].st_value = value;
    symbols[1].st_size = size;
    sections[2].sh_addr = secbase;
    sections[2].sh_size = secsize;
    rc = simplify_symbols_lkm(NULL, &info);
    if (rc != expected_rc || symbols[1].st_value != expected_value) {
        fprintf(stderr, "LKM %s: rc=%d value=%#llx expected rc=%d value=%#llx (%s)\n",
                label, rc, (unsigned long long)symbols[1].st_value,
                expected_rc, (unsigned long long)expected_value, info.info.error_msg);
        return 1;
    }
    puts("[PASS] LKM simplify_symbols: case");
    return 0;
}

static int run_kpimg_case(const char *label, const char *name,
                          unsigned int shndx, unsigned long value,
                          unsigned long size, unsigned long secbase,
                          unsigned long secsize, int expected_rc,
                          unsigned long expected_value)
{
    struct load_info info;
    int rc;
    reset_fixture();
    memset(&info, 0, sizeof(info));
    info.hdr = &ehdr;
    info.sechdrs = sections;
    info.strtab = strtab;
    info.index.sym = 1;
    symbols[1].st_name = name_offset(name);
    symbols[1].st_shndx = shndx;
    symbols[1].st_value = value;
    symbols[1].st_size = size;
    sections[2].sh_addr = secbase;
    sections[2].sh_size = secsize;
    rc = simplify_symbols_kpimg(NULL, &info);
    if (rc != expected_rc || symbols[1].st_value != expected_value) {
        fprintf(stderr, "KPIMG %s: rc=%d value=%#llx expected rc=%d value=%#llx (%s)\n",
                label, rc, (unsigned long long)symbols[1].st_value,
                expected_rc, (unsigned long long)expected_value, info.info.error_msg);
        return 1;
    }
    puts("[PASS] KPIMG simplify_symbols: case");
    return 0;
}

#define CASE(label, name, shndx, value, size, base, secsize, rc, out) do { \
    failed |= run_lkm_case(label, name, shndx, value, size, base, secsize, rc, out); \
    failed |= run_kpimg_case(label, name, shndx, value, size, base, secsize, rc, out); \
} while (0)

int main(void)
{
    int failed = 0;
    CASE("defined offset", "defined", 2, 4, 8, 0x100000UL, 16, 0, 0x100004UL);
    CASE("zero-sized symbol at section end", "defined", 2, 16, 0, 0x100000UL, 16, 0, 0x100010UL);
    CASE("symbol starts beyond section", "defined", 2, 17, 0, 0x100000UL, 16, -ENOEXEC, 17);
    CASE("symbol extent crosses section", "defined", 2, 12, 8, 0x100000UL, 16, -ENOEXEC, 12);
    CASE("runtime address addition overflows", "defined", 2, 4, 1, ULONG_MAX - 3, 16, -ENOEXEC, 4);
    CASE("absolute symbol remains absolute", "absolute", SHN_ABS, 0xdeadbeefUL, 4, 0, 16, 0, 0xdeadbeefUL);
    CASE("KP compatibility symbol lookup", "kp_only", SHN_UNDEF, 7, 0, 0, 16, 0, 0x11110000UL);
    CASE("kernel kallsyms fallback", "kernel_only", SHN_UNDEF, 7, 0, 0, 16, 0, 0x22220000UL);
    CASE("unknown undefined symbol rejected", "missing", SHN_UNDEF, 7, 0, 0, 16, -ENOENT, 7);
    CASE("common symbol rejected", "common", SHN_COMMON, 16, 4, 0, 16, -ENOEXEC, 16);
    CASE("invalid section index rejected", "badidx", 99, 0, 1, 0x100000UL, 16, -ENOEXEC, 0);
    return failed;
}
"""
    code = prefix + "\n" + lkm_fn + "\n" + kpimg_fn + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kp-simplify-symbols-") as tmp:
        cfile = Path(tmp) / "simplify_symbols.c"
        binary = Path(tmp) / "simplify_symbols"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-function",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] both production KPM simplify_symbols() functions executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
