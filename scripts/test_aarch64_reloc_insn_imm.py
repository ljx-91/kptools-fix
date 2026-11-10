#!/usr/bin/env python3
"""Compile and execute the real reloc_insn_imm bodies extracted from both loaders."""
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


def harness(function: str, kpimg: bool) -> str:
    if kpimg:
        enum_op = "aarch64_reloc_op"
        enum_imm = "aarch64_insn_imm_type"
        encoder = "aarch64_insn_encode_immediate"
        prefix = r"""
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
enum aarch64_reloc_op { RELOC_OP_NONE, RELOC_OP_ABS, RELOC_OP_PREL, RELOC_OP_PAGE };
enum aarch64_insn_imm_type { IMM_TEST };
static u64 do_reloc(enum aarch64_reloc_op op, void *place, u64 val)
{
    return op == RELOC_OP_ABS ? val : val - (u64)(uintptr_t)place;
}
static u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
                                         u32 insn, u64 imm)
{
    (void)type;
    return insn ^ (u32)imm;
}
"""
    else:
        enum_op = "kp_aarch64_reloc_op"
        enum_imm = "kp_aarch64_insn_imm_type"
        encoder = "kp_aarch64_insn_encode_immediate"
        prefix = r"""
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
#define BIT(n) (1U << (n))
enum kp_aarch64_reloc_op { RELOC_OP_NONE, RELOC_OP_ABS, RELOC_OP_PREL, RELOC_OP_PAGE };
enum kp_aarch64_insn_imm_type { IMM_TEST };
static u64 do_reloc(enum kp_aarch64_reloc_op op, void *place, u64 val)
{
    return op == RELOC_OP_ABS ? val : val - (u64)(uintptr_t)place;
}
static u32 kp_aarch64_insn_encode_immediate(enum kp_aarch64_insn_imm_type type,
                                            u32 insn, u64 imm)
{
    (void)type;
    return insn ^ (u32)imm;
}
"""
    call = "reloc_insn_imm(RELOC_OP_ABS, &word, value, lsb, len, IMM_TEST)"
    return prefix + "\n" + function + r"""

static int run_case(const char *name, u64 value, int lsb, int len,
                    int expected, int expect_unchanged)
{
    u32 word = 0x12345678U;
    u32 before = word;
    int rc = """ + call + r""";
    if (rc != expected) {
        fprintf(stderr, "%s: expected rc %d, got %d\n", name, expected, rc);
        return 1;
    }
    if ((word == before) != expect_unchanged) {
        fprintf(stderr, "%s: instruction mutation mismatch: before=%08x after=%08x\n",
                name, before, word);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= run_case("misaligned scaled/branch value rejected without write",
                       3, 2, 26, -ENOEXEC, 1);
    failed |= run_case("aligned in-range immediate encoded",
                       4, 2, 26, 0, 0);
    failed |= run_case("out-of-range immediate rejected without write",
                       16, 0, 2, -ERANGE, 1);
    return failed;
}
"""


def data_harness(function: str, kpimg: bool) -> str:
    enum_op = "aarch64_reloc_op" if kpimg else "kp_aarch64_reloc_op"
    prefix = r"""
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int16_t s16;
typedef int32_t s32;
#define pr_err(...) ((void)0)
enum ENUM_OP { RELOC_OP_NONE, RELOC_OP_ABS, RELOC_OP_PREL, RELOC_OP_PAGE };
static u64 do_reloc(enum ENUM_OP op, void *place, u64 val)
{
    (void)op; (void)place;
    return val;
}
""".replace("ENUM_OP", enum_op)
    return prefix + "\n" + function + r"""

static int run_data_case(const char *name, u64 value, int len, int op,
                         int expected, int unchanged, u64 expected_low)
{
    u64 storage = 0xAABBCCDDEEFF0011ULL;
    u64 before = storage;
    int rc = reloc_data((enum ENUM_OP)op, &storage, value, len);
    if (rc != expected) {
        fprintf(stderr, "%s: expected rc %d, got %d\n", name, expected, rc);
        return 1;
    }
    if (unchanged && storage != before) {
        fprintf(stderr, "%s: failed relocation modified destination\n", name);
        return 1;
    }
    if (!unchanged && (storage & (len == 16 ? 0xffffULL :
                                  len == 32 ? 0xffffffffULL : ~0ULL)) != expected_low) {
        fprintf(stderr, "%s: encoded value mismatch: storage=%016llx\n",
                name, (unsigned long long)storage);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= run_data_case("PREL16 positive maximum accepted", 32767, 16,
                            RELOC_OP_PREL, 0, 0, 32767);
    failed |= run_data_case("PREL16 positive overflow rejected atomically", 32768, 16,
                            RELOC_OP_PREL, -ERANGE, 1, 0);
    failed |= run_data_case("PREL16 negative minimum accepted", (u64)(s64)-32768, 16,
                            RELOC_OP_PREL, 0, 0, 0x8000);
    failed |= run_data_case("ABS16 unsigned maximum accepted", 65535, 16,
                            RELOC_OP_ABS, 0, 0, 65535);
    failed |= run_data_case("ABS16 unsigned overflow rejected atomically", 65536, 16,
                            RELOC_OP_ABS, -ERANGE, 1, 0);
    failed |= run_data_case("unsupported width rejected atomically", 7, 8,
                            RELOC_OP_ABS, -EINVAL, 1, 0);
    return failed;
}
"""


def main() -> int:
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("no host C compiler (cc/gcc) available")
    sources = [
        ("LKM", ROOT / "lkm/kpm/relo.c",
         "static int reloc_insn_imm(enum kp_aarch64_reloc_op"),
        ("KPIMG", ROOT / "kernel/patch/module/relo.c",
         "static int reloc_insn_imm(enum aarch64_reloc_op"),
    ]
    with tempfile.TemporaryDirectory(prefix="kp-reloc-test-") as tmp:
        tmpdir = Path(tmp)
        for label, path, signature in sources:
            source_text = path.read_text(encoding="utf-8")
            imm_function = extract_function(source_text, signature)
            data_signature = "static int reloc_data("
            data_function = extract_function(source_text, data_signature)
            for suffix, code in (
                ("insn", harness(imm_function, label == "KPIMG")),
                ("data", data_harness(data_function, label == "KPIMG")),
            ):
                source = tmpdir / f"{label.lower()}_{suffix}_test.c"
                binary = tmpdir / f"{label.lower()}_{suffix}_test"
                source.write_text(code, encoding="utf-8")
                subprocess.run(
                    [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                     str(source), "-o", str(binary)],
                    check=True,
                )
                subprocess.run([str(binary)], check=True)
    print("[PASS] both loaders' instruction and data relocation helpers executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
