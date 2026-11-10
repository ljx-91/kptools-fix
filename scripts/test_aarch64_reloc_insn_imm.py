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
            function = extract_function(path.read_text(encoding="utf-8"), signature)
            source = tmpdir / f"{label.lower()}_reloc_test.c"
            binary = tmpdir / f"{label.lower()}_reloc_test"
            source.write_text(harness(function, label == "KPIMG"), encoding="utf-8")
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(source), "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)
    print("[PASS] both loader relocation implementations executed in host harness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
