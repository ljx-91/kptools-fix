#!/usr/bin/env python3
"""Host-execute production KPM section layout and image-copy functions."""
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
    lkm = (ROOT / "lkm/kpm/module.c").read_text(encoding="utf-8")
    kpimg = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")

    specs = [
        (lkm, "static int get_offset(unsigned int *size,", "get_offset_lkm"),
        (lkm, "static int kp_align_module_size(", "kp_align_module_size_lkm"),
        (lkm, "static int layout_sections(struct kp_module *", "layout_sections_lkm"),
        (lkm, "static int move_module(struct kp_module *", "move_module_lkm"),
        (kpimg, "static long get_offset(struct module *", "get_offset_kpimg"),
        (kpimg, "static int align_module_size(", "align_module_size_kpimg"),
        (kpimg, "static int layout_sections(struct module *", "layout_sections_kpimg"),
        (kpimg, "static int move_module(struct module *", "move_module_kpimg"),
    ]
    functions = []
    for source, signature, new_name in specs:
        fn = extract_function(source, signature)
        original = signature.split("(")[0].split()[-1]
        functions.append(fn.replace(original + "(", new_name + "(", 1))

    prefix = r"""
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Ehdr Elf_Ehdr;
typedef void mod_initcall_t(void);
typedef void mod_exitcall_t(void);
typedef void mod_ctl0call_t(void);
typedef void mod_ctl1call_t(void);
typedef void mod_eventcall_t(void);
#define PAGE_SIZE 4096U
#define ARCH_SHF_SMALL 0
static unsigned int page_size = PAGE_SIZE;
#define logki(...) ((void)0)
#define logkd(...) ((void)0)
static int fail_alloc;
static void *kp_malloc_exec(unsigned int size)
{
    return fail_alloc ? NULL : malloc(size);
}
struct kp_module {
    unsigned int size, text_size, ro_size;
    void *start;
    mod_initcall_t *init;
    mod_exitcall_t *exit;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_eventcall_t *event;
    struct { const char *base, *name, *version, *license, *author, *description; } info;
};
struct module {
    unsigned int size, text_size, ro_size;
    void *start;
    mod_initcall_t *init;
    mod_exitcall_t *exit;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_eventcall_t *event;
    struct { const char *base, *name, *version, *license, *author, *description; } info;
};
struct kp_load_info {
    struct { const char *base; unsigned long size; const char *name, *version, *license, *author, *description; } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings;
};
struct load_info {
    struct { const char *base; unsigned long size; const char *name, *version, *license, *author, *description; } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings;
};
"""
    tests = r"""
#define IMAGE_SIZE 512
static unsigned char image[IMAGE_SIZE];
static Elf_Ehdr ehdr;
static Elf_Shdr sections[7];
static const char section_names[] =
    "\0.kpm.init\0.kpm.exit\0.rodata\0.data\0.bss\0.kpm.info\0";
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

static void reset_fixture(void)
{
    memset(image, 0, sizeof(image));
    memset(&ehdr, 0, sizeof(ehdr));
    memset(sections, 0, sizeof(sections));
    ehdr.e_shnum = 7;
#define SETSEC(i, name, type, flags, off, size, align) do { \
    sections[i].sh_name = name_offset(name); \
    sections[i].sh_type = type; \
    sections[i].sh_flags = flags; \
    sections[i].sh_offset = off; \
    sections[i].sh_size = size; \
    sections[i].sh_addralign = align; \
    sections[i].sh_addr = type == SHT_NOBITS ? 0 : (unsigned long)(image + (off)); \
} while (0)
    SETSEC(1, ".kpm.init", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 128, 4, 16);
    SETSEC(2, ".kpm.exit", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 144, 4, 16);
    SETSEC(3, ".rodata", SHT_PROGBITS, SHF_ALLOC, 160, 4, 8);
    SETSEC(4, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 168, 4, 8);
    SETSEC(5, ".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 0, 8, 8);
    SETSEC(6, ".kpm.info", SHT_PROGBITS, SHF_ALLOC, 176, 32, 1);
#undef SETSEC
    memcpy(image + 128, "INIT", 4);
    memcpy(image + 144, "EXIT", 4);
    memcpy(image + 160, "RODT", 4);
    memcpy(image + 168, "DATA", 4);
    memcpy(image + 176, metadata, sizeof(metadata));
}

static void init_lkm_info(struct kp_load_info *info)
{
    memset(info, 0, sizeof(*info));
    info->hdr = &ehdr;
    info->len = sizeof(image);
    info->sechdrs = sections;
    info->secstrings = (char *)section_names;
    info->info.base = (char *)image + 176;
    info->info.name = info->info.base + 5;
    info->info.version = info->info.base + 21;
}
static void init_kpimg_info(struct load_info *info)
{
    memset(info, 0, sizeof(*info));
    info->hdr = &ehdr;
    info->len = sizeof(image);
    info->sechdrs = sections;
    info->secstrings = (char *)section_names;
    info->info.base = (char *)image + 176;
    info->info.name = info->info.base + 5;
    info->info.version = info->info.base + 21;
}

static int test_lkm_valid(void)
{
    struct kp_module mod = {0};
    struct kp_load_info info;
    int rc;
    reset_fixture(); init_lkm_info(&info);
    rc = layout_sections_lkm(&mod, &info);
    if (rc || mod.size != 12288 || mod.text_size != 4096 || mod.ro_size != 8192)
        return fprintf(stderr, "LKM layout rc=%d size=%u text=%u ro=%u\n",
                       rc, mod.size, mod.text_size, mod.ro_size), 1;
    rc = move_module_lkm(&mod, &info);
    if (rc || !mod.start || memcmp(mod.start, "INIT", 4) ||
        memcmp((char *)mod.start + sections[2].sh_entsize, "EXIT", 4) ||
        memcmp((char *)mod.start + sections[3].sh_entsize, "RODT", 4) ||
        memcmp((char *)mod.start + sections[4].sh_entsize, "DATA", 4) ||
        memcmp((char *)mod.start + sections[6].sh_entsize, metadata, sizeof(metadata)) ||
        memcmp((char *)mod.start + sections[5].sh_entsize, "\0\0\0\0\0\0\0\0", 8) ||
        mod.init != (mod_initcall_t *)mod.start ||
        mod.exit != (mod_exitcall_t *)((char *)mod.start + sections[2].sh_entsize) ||
        strcmp(mod.info.name, "fixture") || strcmp(mod.info.version, "1.0")) {
        fprintf(stderr, "LKM move/copy/metadata validation failed rc=%d\n", rc);
        free(mod.start); return 1;
    }
    free(mod.start);
    puts("[PASS] LKM layout and final section copy");
    return 0;
}

static int test_kpimg_valid(void)
{
    struct module mod = {0};
    struct load_info info;
    int rc;
    reset_fixture(); init_kpimg_info(&info);
    rc = layout_sections_kpimg(&mod, &info);
    if (rc || mod.size != 12288 || mod.text_size != 4096 || mod.ro_size != 8192)
        return fprintf(stderr, "KPIMG layout rc=%d size=%u text=%u ro=%u\n",
                       rc, mod.size, mod.text_size, mod.ro_size), 1;
    rc = move_module_kpimg(&mod, &info);
    if (rc || !mod.start || memcmp(mod.start, "INIT", 4) ||
        memcmp((char *)mod.start + sections[2].sh_entsize, "EXIT", 4) ||
        memcmp((char *)mod.start + sections[3].sh_entsize, "RODT", 4) ||
        memcmp((char *)mod.start + sections[4].sh_entsize, "DATA", 4) ||
        memcmp((char *)mod.start + sections[6].sh_entsize, metadata, sizeof(metadata)) ||
        memcmp((char *)mod.start + sections[5].sh_entsize, "\0\0\0\0\0\0\0\0", 8) ||
        mod.init != (mod_initcall_t *)mod.start ||
        mod.exit != (mod_exitcall_t *)((char *)mod.start + sections[2].sh_entsize) ||
        strcmp(mod.info.name, "fixture") || strcmp(mod.info.version, "1.0")) {
        fprintf(stderr, "KPIMG move/copy/metadata validation failed rc=%d\n", rc);
        free(mod.start); return 1;
    }
    free(mod.start);
    puts("[PASS] KPIMG layout and final section copy");
    return 0;
}

static int test_bad_alignment(void)
{
    struct kp_module lm = {0}; struct module km = {0};
    struct kp_load_info li; struct load_info ki;
    int a, b;
    reset_fixture(); init_lkm_info(&li); init_kpimg_info(&ki);
    sections[1].sh_addralign = 3;
    a = layout_sections_lkm(&lm, &li);
    b = layout_sections_kpimg(&km, &ki);
    if (a != -ENOEXEC || b != -ENOEXEC) {
        fprintf(stderr, "bad alignment accepted: LKM=%d KPIMG=%d\n", a, b);
        return 1;
    }
    puts("[PASS] both loaders reject non-power-of-two section alignment");
    return 0;
}

static int test_bad_destination_bounds(void)
{
    struct kp_module lm = {0}; struct module km = {0};
    struct kp_load_info li; struct load_info ki;
    int a, b;
    reset_fixture(); init_lkm_info(&li); init_kpimg_info(&ki);
    lm.size = km.size = 64;
    lm.start = malloc(64); km.start = malloc(64);
    if (!lm.start || !km.start) return 1;
    sections[1].sh_entsize = 63;
    a = move_module_lkm(&lm, &li);
    b = move_module_kpimg(&km, &ki);
    free(lm.start); free(km.start);
    if (a != -ENOEXEC || b != -ENOEXEC) {
        fprintf(stderr, "bad destination accepted: LKM=%d KPIMG=%d\n", a, b);
        return 1;
    }
    puts("[PASS] both loaders reject destination copy overflow");
    return 0;
}

static int test_allocation_failure(void)
{
    struct kp_module lm = {0}; struct module km = {0};
    struct kp_load_info li; struct load_info ki;
    int a, b;
    reset_fixture(); init_lkm_info(&li); init_kpimg_info(&ki);
    lm.size = km.size = 64;
    fail_alloc = 1;
    a = move_module_lkm(&lm, &li);
    b = move_module_kpimg(&km, &ki);
    fail_alloc = 0;
    if (a != -ENOMEM || b != -ENOMEM) {
        fprintf(stderr, "allocation failure mismatch: LKM=%d KPIMG=%d\n", a, b);
        return 1;
    }
    puts("[PASS] both loaders fail cleanly on executable allocation failure");
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= test_lkm_valid();
    failed |= test_kpimg_valid();
    failed |= test_bad_alignment();
    failed |= test_bad_destination_bounds();
    failed |= test_allocation_failure();
    return failed;
}
"""
    code = prefix + "\n" + "\n".join(functions) + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kp-layout-copy-") as tmp:
        cfile = Path(tmp) / "layout_copy.c"
        binary = Path(tmp) / "layout_copy"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-function",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] both production KPM layout/copy paths executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
