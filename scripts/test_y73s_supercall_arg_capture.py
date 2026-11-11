#!/usr/bin/env python3
"""Execute the real KPIMG syscall_argn helpers against Y73S x0-x5 layouts."""
from pathlib import Path
import shutil
import subprocess
import sys
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

    header = (ROOT / "kernel/patch/include/syscall.h").read_text(encoding="utf-8")
    source = (ROOT / "kernel/patch/common/supercall.c").read_text(encoding="utf-8")
    args_fn = extract_function(header, "static inline uint64_t *syscall_args(")
    argn_fn = extract_function(header, "static inline uint64_t syscall_argn(")
    before_start = source[source.find("static void before("):]
    for n in range(6):
        if f"syscall_argn(args, {n})" not in before_start:
            raise AssertionError(f"supercall before() does not read syscall arg {n}")

    prefix = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct { uint64_t args[8]; } hook_fargs0_t;
struct pt_regs { uint64_t regs[31]; };
static int has_syscall_wrapper;
"""
    tests = r"""
int main(void)
{
    hook_fargs0_t fargs = {0};
    struct pt_regs regs = {0};
    uint64_t expected[6] = {
        0x1111222233334444ULL, 0x1000000000001020ULL,
        0x2222333344445555ULL, 0x3333444455556666ULL,
        0x4444555566667777ULL, 0x5555666677778888ULL
    };

    has_syscall_wrapper = 0; /* Y73S 4.14.141 legacy inline hook */
    for (int i = 0; i < 6; i++) fargs.args[i] = expected[i];
    for (int i = 0; i < 6; i++) {
        if (syscall_argn(&fargs, i) != expected[i]) {
            fprintf(stderr, "legacy x%d argument capture mismatch\n", i);
            return 1;
        }
    }
    puts("[PASS] Y73S legacy inline hook captures key/x0 and command/x1");

    has_syscall_wrapper = 1;
    for (int i = 0; i < 6; i++) regs.regs[i] = expected[i];
    fargs.args[0] = (uint64_t)(uintptr_t)&regs;
    for (int i = 0; i < 6; i++) {
        if (syscall_argn(&fargs, i) != expected[i]) {
            fprintf(stderr, "pt_regs x%d argument capture mismatch\n", i);
            return 1;
        }
    }
    puts("[PASS] pt_regs syscall wrapper captures key/x0 and command/x1");
    return 0;
}
"""
    code = prefix + "\n" + args_fn + "\n" + argn_fn + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-supercall-args-") as tmp:
        cfile = Path(tmp) / "arg_capture.c"
        binary = Path(tmp) / "arg_capture"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] Y73S Supercall argument capture fixture")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("[FAIL]", exc, file=sys.stderr)
        sys.exit(1)
