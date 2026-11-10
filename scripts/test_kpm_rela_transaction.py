#!/usr/bin/env python3
"""Host-execute the production KPM RELA transaction function."""
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
    source = (ROOT / "lkm/kpm/relo.c").read_text(encoding="utf-8")
    signatures = (
        "static u64 do_reloc(",
        "static int reloc_data(",
        "static unsigned int kp_reloc_write_width(",
        "int kp_apply_relocate_add(",
    )
    functions = [extract_function(source, sig) for sig in signatures]
    # R_ARM_NONE aliases R_AARCH64_NONE in some ELF headers.
    functions = [fn.replace("case R_ARM_NONE:\n", "") for fn in functions]
    prefix = r"""
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int16_t s16;
typedef int32_t s32;
#define BIT(n) (1UL << (n))
#define fallthrough __attribute__((fallthrough))
#define pr_err(...) ((void)0)
enum kp_aarch64_reloc_op { RELOC_OP_NONE, RELOC_OP_ABS, RELOC_OP_PREL, RELOC_OP_PAGE };
enum kp_aarch64_insn_imm_type {
 KP_INSN_IMM_16, KP_AARCH64_INSN_IMM_MOVNZ, KP_AARCH64_INSN_IMM_MOVK,
 KP_INSN_IMM_19, KP_INSN_IMM_ADR, KP_INSN_IMM_12, KP_INSN_IMM_14, KP_INSN_IMM_26
};
struct kp_module { int unused; };
static int fail_vmalloc;
static void *vmalloc(size_t n) { return fail_vmalloc ? NULL : malloc(n); }
static void vfree(void *p) { free(p); }
static int reloc_insn_movw(enum kp_aarch64_reloc_op op, void *place, u64 val,
                           int lsb, enum kp_aarch64_insn_imm_type type)
{ (void)op; (void)place; (void)val; (void)lsb; (void)type; return -EOPNOTSUPP; }
static int reloc_insn_imm(enum kp_aarch64_reloc_op op, void *place, u64 val,
                          int lsb, int len, enum kp_aarch64_insn_imm_type type)
{ (void)op; (void)place; (void)val; (void)lsb; (void)len; (void)type; return -EOPNOTSUPP; }
"""
    tests = r"""
#define TARGET_SIZE 32
static unsigned char target[TARGET_SIZE];
static Elf64_Sym symbols[3];
static Elf64_Rela relas[3];
static Elf64_Shdr sections[4];

static void reset_fixture(void)
{
    memset(target, 0xA5, sizeof(target));
    memset(symbols, 0, sizeof(symbols));
    memset(relas, 0, sizeof(relas));
    memset(sections, 0, sizeof(sections));
    symbols[1].st_value = 0x1234;
    symbols[2].st_value = (Elf64_Addr)(uintptr_t)(target + 6) + 32768;
    sections[1].sh_type = SHT_SYMTAB;
    sections[1].sh_size = sizeof(symbols);
    sections[1].sh_addr = (unsigned long)symbols;
    sections[2].sh_type = SHT_PROGBITS;
    sections[2].sh_flags = SHF_ALLOC | SHF_WRITE;
    sections[2].sh_size = sizeof(target);
    sections[2].sh_addr = (unsigned long)target;
    sections[3].sh_type = SHT_RELA;
    sections[3].sh_size = 2 * sizeof(Elf64_Rela);
    sections[3].sh_info = 2;
    sections[3].sh_link = 1;
    sections[3].sh_entsize = ~0UL;
    sections[3].sh_addr = (unsigned long)relas;
    relas[0].r_offset = 0;
    relas[0].r_info = ELF64_R_INFO(1, R_AARCH64_ABS16);
    relas[1].r_offset = 4;
    relas[1].r_info = ELF64_R_INFO(1, R_AARCH64_ABS32);
    fail_vmalloc = 0;
}

static int run_case(const char *name, int expected, int unchanged)
{
    unsigned char before[TARGET_SIZE];
    int rc;
    memcpy(before, target, sizeof(before));
    rc = kp_apply_relocate_add(sections, NULL, 1, 3, NULL);
    if (rc != expected) {
        fprintf(stderr, "%s: expected %d got %d\n", name, expected, rc);
        return 1;
    }
    if (unchanged && memcmp(before, target, sizeof(before))) {
        fprintf(stderr, "%s: target modified on failure\n", name);
        return 1;
    }
    puts(name);
    return 0;
}

int main(void)
{
    int failed = 0;
    uint16_t v16;
    uint32_t v32;

    reset_fixture();
    failed |= run_case("[PASS] multiple valid RELA records applied", 0, 0);
    memcpy(&v16, target, sizeof(v16));
    memcpy(&v32, target + 4, sizeof(v32));
    if (v16 != 0x1234 || v32 != 0x1234) return 1;

    reset_fixture();
    relas[1].r_info = ELF64_R_INFO(1, 0x6fffffffU);
    failed |= run_case("[PASS] unsupported relocation rolls back prior write", -ENOEXEC, 1);

    reset_fixture();
    relas[1].r_info = ELF64_R_INFO(2, R_AARCH64_PREL16);
    relas[1].r_offset = 6;
    failed |= run_case("[PASS] PREL16 overflow rolls back prior write", -ENOEXEC, 1);

    reset_fixture();
    relas[1].r_info = ELF64_R_INFO(99, R_AARCH64_ABS16);
    failed |= run_case("[PASS] invalid symbol index rejected before writes", -ENOEXEC, 1);

    reset_fixture();
    relas[1].r_info = ELF64_R_INFO(1, R_AARCH64_ABS32);
    relas[1].r_offset = TARGET_SIZE - 2;
    failed |= run_case("[PASS] target range rejected before writes", -ENOEXEC, 1);

    reset_fixture();
    relas[1].r_info = ELF64_R_INFO(1, R_AARCH64_JUMP26);
    relas[1].r_offset = 1;
    failed |= run_case("[PASS] unaligned instruction relocation rejected", -ENOEXEC, 1);

    reset_fixture();
    sections[3].sh_size--;
    failed |= run_case("[PASS] malformed RELA size rejected", -ENOEXEC, 1);

    reset_fixture();
    sections[3].sh_type = SHT_REL;
    failed |= run_case("[PASS] REL input rejected", -ENOEXEC, 1);

    reset_fixture();
    fail_vmalloc = 1;
    failed |= run_case("[PASS] backup allocation failure leaves target intact", -ENOMEM, 1);

    reset_fixture();
    sections[3].sh_link = 2;
    failed |= run_case("[PASS] mismatched symbol-table link rejected", -ENOEXEC, 1);
    return failed;
}
"""
    code = prefix + "\n".join(functions) + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kp-rela-transaction-") as tmp:
        cfile = Path(tmp) / "rela_transaction.c"
        binary = Path(tmp) / "rela_transaction"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-Wno-unused-function",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] production KPM RELA transaction function executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
