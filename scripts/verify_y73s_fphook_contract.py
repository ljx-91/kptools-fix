#!/usr/bin/env python3
"""Source regression checks for function-pointer hook patch failure handling."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
src = (root / "kernel/base/fphook.c").read_text()
hdr = (root / "kernel/include/hook.h").read_text()

checks = {
    "fp_hook returns hotpatch status": "return hotpatch((void **)addrs, values, 2);" in src,
    "fp_unhook returns hotpatch status": "return hotpatch((void **)addrs, values, 2);" in src and
        "int fp_unhook(uintptr_t fp_addr, void *backup)" in src,
    "public declarations return status": "int fp_hook(uintptr_t fp_addr, void *replace, void **backup);" in hdr and
        "int fp_unhook(uintptr_t fp_addr, void *backup);" in hdr,
    "origin backup saved before patch": src.index("*backup = (void *)original;") <
        src.index("return hotpatch((void **)addrs, values, 2);"),
    "chain preparation failure frees allocation": "if (err) {\n            hook_mem_free(chain);\n            return err;" in src,
    "uncertain install retains chain": "patch rollback uncertain" in src and
        "return -HOOK_PATCH_UNCERTAIN;" in src,
    "restore failure retains chain": "if (rc) {\n        logkv(\"Unwrap func pointer:" in src and
        "retaining chain memory" in src,
}
for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
