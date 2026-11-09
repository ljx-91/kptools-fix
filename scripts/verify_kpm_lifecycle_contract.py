#!/usr/bin/env python3
"""Cross-backend KPM lifecycle and asynchronous owner-pin source contracts."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def body(source, signature):
    start = source.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


lkm = read("lkm/kpm/module.c")
lkm_h = read("lkm/kpm/module.h")
kpimg = read("kernel/patch/module/module.c")
kpimg_h = read("kernel/patch/include/module.h")
kpm_api = read("kernel/include/kpmodule.h")
symbols = read("lkm/kpm/symbols.c")

checks = {
    "LKM refuses concurrent exit callback execution":
        "mod->state == KP_MODULE_EXITING && !mod->exit_called" in
        body(lkm, "long kp_unload_module("),
    "KPIMG refuses concurrent exit callback execution":
        "mod->state == KP_MODULE_EXITING && !mod->exit_called" in
        body(kpimg, "long unload_module("),
    "LKM only permits nested kallsyms pins during an existing unload call":
        "!(pos->state == KP_MODULE_UNLOADING && pos->active_calls)" in
        body(lkm, "static struct kp_module *kp_module_get_by_addr("),
    "LKM async owner pin API is declared":
        all(x in lkm_h for x in ("kp_kpm_owner_pin", "kp_kpm_owner_unpin",
                                 "kp_kpm_owner_call_get", "kp_kpm_owner_call_put")),
    "KPIMG async owner pin API is declared":
        all(x in kpimg_h for x in ("kp_kpm_owner_pin", "kp_kpm_owner_unpin",
                                   "kp_kpm_owner_call_get", "kp_kpm_owner_call_put")),
    "KPM public header documents async lifetime protocol":
        all(x in kpm_api for x in ("Explicit lifetime pins for KPM-owned asynchronous work",
                                   "kp_kpm_owner_pin", "kp_kpm_owner_call_get",
                                   "kp_kpm_owner_call_put", "kp_kpm_owner_unpin")),
    "LKM owner pin is exported through KPM symbol table":
        all(('"' + x + '"') in symbols for x in (
            "kp_kpm_owner_pin", "kp_kpm_owner_unpin",
            "kp_kpm_owner_call_get", "kp_kpm_owner_call_put")),
    "LKM persistent owner pin increments hook_refs":
        "pos->hook_refs++" in body(lkm, "int kp_hook_owner_register("),
    "LKM transient callback get pins only LIVE or LOADING":
        "mod->active_calls++" in body(lkm, "int kp_hook_owner_call_get(") and
        "mod->state == KP_MODULE_LIVE || mod->state == KP_MODULE_LOADING" in
        body(lkm, "int kp_hook_owner_call_get("),
    "LKM unload waits for async and hook owner pins":
        "mod->active_calls || mod->hook_refs" in body(lkm, "long kp_unload_module("),
    "KPIMG persistent owner pin increments hook_refs":
        "pos->hook_refs++" in body(kpimg, "int kp_hook_owner_register("),
    "KPIMG transient callback get pins only LIVE or LOADING":
        "mod->active_calls++" in body(kpimg, "int kp_hook_owner_call_get(") and
        "mod->state == KP_MODULE_LIVE || mod->state == KP_MODULE_LOADING" in
        body(kpimg, "int kp_hook_owner_call_get("),
    "KPIMG unload waits for async and hook owner pins":
        "mod->active_calls || mod->hook_refs" in body(kpimg, "long unload_module("),
}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
