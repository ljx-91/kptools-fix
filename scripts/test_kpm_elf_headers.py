#!/usr/bin/env python3
"""Execute the real KPM ELF header and section-table validators in a Host C harness."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"function not found: {signature}")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError(f"function body not found: {signature}")
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise RuntimeError(f"unterminated function: {signature}")


def main() -> int:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("no host C compiler (cc/gcc) available")
    source = (ROOT / "lkm/kpm/module.c").read_text(encoding="utf-8")
    functions = [
        extract_function(source, "static bool kp_elf_range_valid("),
        extract_function(source, "static bool kp_elf_string_valid("),
        extract_function(source, "static void set_load_error("),
        extract_function(source, "static int rewrite_section_headers("),
        extract_function(source, "static int elf_header_check("),
    ]
    prefix = r"""
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
struct kp_load_info {
    struct { char error_msg[128]; } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings;
};
"""
    tests = r"""
#define IMAGE_SIZE 512
static unsigned char image[IMAGE_SIZE];

static void make_valid(struct kp_load_info *info)
{
    Elf_Ehdr *eh;
    Elf_Shdr *sh;
    static const char names[] = "\0.shstrtab\0.text\0";
    memset(image, 0, sizeof(image));
    eh = (Elf_Ehdr *)image;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_type = ET_REL;
    eh->e_machine = EM_AARCH64;
    eh->e_version = EV_CURRENT;
    eh->e_ehsize = sizeof(*eh);
    eh->e_shoff = 64;
    eh->e_shentsize = sizeof(Elf_Shdr);
    eh->e_shnum = 3;
    eh->e_shstrndx = 1;
    sh = (Elf_Shdr *)(image + eh->e_shoff);
    sh[1].sh_name = 1;
    sh[1].sh_type = SHT_STRTAB;
    sh[1].sh_offset = 256;
    sh[1].sh_size = sizeof(names);
    sh[1].sh_addralign = 1;
    memcpy(image + sh[1].sh_offset, names, sizeof(names));
    sh[2].sh_name = 11;
    sh[2].sh_type = SHT_PROGBITS;
    sh[2].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh[2].sh_offset = 320;
    sh[2].sh_size = 16;
    sh[2].sh_addralign = 16;
    info->hdr = eh;
    info->len = sizeof(image);
    info->sechdrs = NULL;
    info->secstrings = NULL;
    memset(info->info.error_msg, 0, sizeof(info->info.error_msg));
}

static int check(const char *name, int expected, int rewrite)
{
    struct kp_load_info info = {0};
    int rc;
    make_valid(&info);
    rc = elf_header_check(&info);
    if (!rc && rewrite)
        rc = rewrite_section_headers(&info);
    if ((rc == 0) != (expected == 0)) {
        fprintf(stderr, "%s: expected %d, got %d (%s)\\n",
                name, expected, rc, info.info.error_msg);
        return 1;
    }
    if (!rc && rewrite) {
        if (!info.secstrings ||
            info.sechdrs[2].sh_addr != (unsigned long)image + 320) {
            fprintf(stderr, "%s: rewritten section metadata mismatch\\n", name);
            return 1;
        }
    }
    printf("[PASS] %s\\n", name);
    return 0;
}

int main(void)
{
    int failed = 0;
    struct kp_load_info info;

    failed |= check("valid ELF64 AArch64 ET_REL header and section table", 0, 1);
    make_valid(&info);
    ((Elf_Ehdr *)image)->e_ident[EI_CLASS] = ELFCLASS32;
    if (elf_header_check(&info) == 0) return 1;
    puts("[PASS] non-ELF64 class rejected");

    make_valid(&info);
    ((Elf_Ehdr *)image)->e_shoff++;
    if (elf_header_check(&info) == 0) return 1;
    puts("[PASS] unaligned section-header table rejected");

    make_valid(&info);
    ((Elf_Ehdr *)image)->e_shoff = 480;
    if (elf_header_check(&info) == 0) return 1;
    puts("[PASS] out-of-range section-header table rejected");

    make_valid(&info);
    if (elf_header_check(&info)) return 1;
    info.sechdrs[1].sh_offset = IMAGE_SIZE - 4;
    info.sechdrs[1].sh_size = 16;
    if (rewrite_section_headers(&info) == 0) return 1;
    puts("[PASS] truncated section string table rejected");

    make_valid(&info);
    if (elf_header_check(&info)) return 1;
    info.sechdrs[2].sh_size = 256;
    if (rewrite_section_headers(&info) == 0) return 1;
    puts("[PASS] section data range overflow rejected");

    make_valid(&info);
    if (elf_header_check(&info)) return 1;
    info.sechdrs[2].sh_addralign = 3;
    if (rewrite_section_headers(&info) == 0) return 1;
    puts("[PASS] non-power-of-two section alignment rejected");

    make_valid(&info);
    if (elf_header_check(&info)) return 1;
    info.sechdrs[2].sh_offset = 321;
    if (rewrite_section_headers(&info) == 0) return 1;
    puts("[PASS] misaligned file-backed section rejected");

    make_valid(&info);
    if (elf_header_check(&info)) return 1;
    info.sechdrs[2].sh_name = 99;
    if (rewrite_section_headers(&info) == 0) return 1;
    puts("[PASS] out-of-range section name rejected");

    make_valid(&info);
    if (elf_header_check(&info)) return 1;
    info.sechdrs[2].sh_type = SHT_NOBITS;
    info.sechdrs[2].sh_offset = 0xfffffff0UL;
    info.sechdrs[2].sh_size = 4096;
    if (rewrite_section_headers(&info) != 0 ||
        info.sechdrs[2].sh_addr != 0) return 1;
    puts("[PASS] NOBITS has no file-backed range and receives no input address");
    return failed;
}
"""
    code = prefix + "\n".join(functions) + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kp-elf-header-test-") as tmp:
        cfile = Path(tmp) / "kpm_elf_header_test.c"
        binary = Path(tmp) / "kpm_elf_header_test"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-type-limits",
             str(cfile), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print("[PASS] real KPM ELF header/section validation functions executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
