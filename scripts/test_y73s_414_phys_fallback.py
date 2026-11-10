#!/usr/bin/env python3
"""Execute the production no-init_mm ARM64 physical-address fallback."""
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
    source = (ROOT / "lkm/infra/patch_memory.c").read_text(encoding="utf-8")
    function = extract_function(
        source, "static unsigned long kp_phys_from_virt_no_init_mm("
    )
    prefix = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define KERNEL_START 0x1000UL
#define KERNEL_END   0x2000UL
static bool virt_addr_valid(const void *p)
{
    unsigned long a = (unsigned long)p;
    return a >= 0x8000UL && a < 0x9000UL;
}
static unsigned long virt_to_phys(const void *p)
{
    return (unsigned long)p - 0x1000UL;
}
"""
    tests = r"""
int main(void)
{
    unsigned long pa;

    pa = kp_phys_from_virt_no_init_mm(0x1800UL);
    if (pa != 0x800UL) {
        fprintf(stderr, "kernel image translation wrong: %lx\n", pa);
        return 1;
    }
    puts("[PASS] kernel image text uses ARM64 virt_to_phys mapping");

    pa = kp_phys_from_virt_no_init_mm(0x8120UL);
    if (pa != 0x7120UL) {
        fprintf(stderr, "linear map translation wrong: %lx\n", pa);
        return 1;
    }
    puts("[PASS] valid linear-map address uses virt_to_phys");

    pa = kp_phys_from_virt_no_init_mm(0x4000UL);
    if (pa != 0) {
        fprintf(stderr, "unmapped/vmalloc address accepted: %lx\n", pa);
        return 1;
    }
    puts("[PASS] non-direct-map address rejected without init_mm");

    pa = kp_phys_from_virt_no_init_mm(0x2000UL);
    if (pa != 0) {
        fprintf(stderr, "kernel image end boundary accepted: %lx\n", pa);
        return 1;
    }
    puts("[PASS] kernel image end boundary rejected");
    return 0;
}
"""
    code = prefix + "\n" + function + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-414-phys-") as tmp:
        cfile = Path(tmp) / "phys_fallback.c"
        binary = Path(tmp) / "phys_fallback"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] Y73S 4.14 no-init_mm physical translation fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
