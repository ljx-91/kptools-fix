#!/usr/bin/env python3
"""Host-execute the production KPM NX restoration helper with failure injection."""
from pathlib import Path
import shutil, subprocess, tempfile
ROOT = Path(__file__).resolve().parents[1]

def extract(source, signature):
    start = source.find(signature)
    if start < 0: raise RuntimeError(f"missing function: {signature}")
    brace = source.find("{", start); depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{": depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0: return source[start:pos + 1]
    raise RuntimeError("unterminated function")

def main():
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc: raise SystemExit("no host C compiler")
    src = (ROOT / "lkm/kpm/module.c").read_text(encoding="utf-8")
    fn = extract(src, "static int kp_restore_nx_gp(")
    prefix = r"""
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
static void *kp_kpm_init_mm;
static int nx_result, nx_calls, update_result, update_calls;
static unsigned long last_base, last_size, last_pages;
static int set_nx(unsigned long base, int pages) {
    nx_calls++; last_base = base; last_pages = (unsigned long)pages; return nx_result;
}
static int (*kp_set_memory_nx)(unsigned long, int);
static int kp_update_bti_gp(unsigned long base, unsigned long size, int executable) {
    update_calls++; if (executable) return -EINVAL;
    last_base = base; last_size = size; return update_result;
}
"""
    tests = r"""
static int check(const char *name, int got, int expected) {
    if (got != expected) { fprintf(stderr, "%s: got %d expected %d\\n", name, got, expected); return 1; }
    puts(name); return 0;
}
int main(void) {
    int failed = 0, rc;
    kp_kpm_init_mm = NULL; kp_set_memory_nx = NULL; nx_calls = update_calls = 0;
    rc = kp_restore_nx_gp(0x10000, 8192);
    failed |= check("[PASS] missing set_memory_nx without init_mm fails closed", rc, -ENOSYS);
    if (update_calls) return 1;

    kp_kpm_init_mm = NULL; kp_set_memory_nx = set_nx; nx_result = -EIO; nx_calls = update_calls = 0;
    rc = kp_restore_nx_gp(0x20000, 4096);
    failed |= check("[PASS] failed set_memory_nx without init_mm retains executable memory", rc, -EIO);
    if (nx_calls != 1 || update_calls) return 1;

    kp_kpm_init_mm = NULL; kp_set_memory_nx = set_nx; nx_result = 0; nx_calls = update_calls = 0;
    rc = kp_restore_nx_gp(0x30000, 4097);
    failed |= check("[PASS] successful set_memory_nx authorizes no-init_mm retirement", rc, 0);
    if (nx_calls != 1 || last_base != 0x30000 || last_pages != 2 || update_calls != 1) return 1;

    kp_kpm_init_mm = (void *)1; kp_set_memory_nx = NULL; update_result = -EACCES; update_calls = 0;
    rc = kp_restore_nx_gp(0x40000, 4096);
    failed |= check("[PASS] init_mm PTE fallback reports unverified NX state", rc, -EACCES);
    if (update_calls != 1) return 1;

    kp_kpm_init_mm = (void *)1; kp_set_memory_nx = set_nx; nx_result = -EIO; update_result = 0; nx_calls = update_calls = 0;
    rc = kp_restore_nx_gp(0x50000, 4096);
    failed |= check("[PASS] init_mm PTE verification can recover set_memory_nx failure", rc, 0);
    if (nx_calls != 1 || update_calls != 1) return 1;
    return failed;
}
"""
    code = prefix + "\n" + fn + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kpm-nx-restore-") as tmp:
        c = Path(tmp) / "nx_restore.c"; b = Path(tmp) / "nx_restore"
        c.write_text(code, encoding="utf-8")
        subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", str(c), "-o", str(b)], check=True)
        subprocess.run([str(b)], check=True)
    print("[PASS] production KPM NX restoration helper executed")

if __name__ == "__main__": main()
