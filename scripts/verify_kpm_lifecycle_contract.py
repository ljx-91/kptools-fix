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
    "KPIMG serializes both exit callbacks and executable-image reclamation":
        "mod->state == KP_MODULE_EXITING" in
        body(kpimg, "long unload_module("),
    "KPIMG module metadata has a dedicated quarantine list node":
        "struct list_head quarantine_list;" in kpimg_h and
        "KP_MODULE_QUARANTINED" in kpimg_h,
    "KPIMG name lookup includes quarantined executable images":
        "list_for_each_entry(pos, &quarantined_modules, quarantine_list)" in
        body(kpimg, "static struct module *find_module_locked("),
    "KPIMG load failure retains metadata when executable permission reset fails":
        "mod->state = KP_MODULE_QUARANTINED" in body(kpimg, "long load_module_ex(") and
        "list_add_tail(&mod->quarantine_list, &quarantined_modules)" in
        body(kpimg, "long load_module_ex(") and
        "executable image quarantined after permission reset failure" in
        body(kpimg, "long load_module_ex("),
    "KPIMG normal unload keeps registry metadata until executable free succeeds":
        body(kpimg, "long unload_module(").find("kp_free_exec(mod->start)") <
        body(kpimg, "long unload_module(").find("list_del_init(&mod->list)") and
        "mod->state = KP_MODULE_UNLOADING" in body(kpimg, "long unload_module(") and
        "return free_rc;" in body(kpimg, "long unload_module("),
    "KPIMG quarantined images can be retried without re-running init or exit":
        "mod->state == KP_MODULE_QUARANTINED" in body(kpimg, "long unload_module(") and
        "list_del_init(&mod->quarantine_list)" in body(kpimg, "long unload_module("),
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
    "LKM rejects KPM data/rodata as a callback owner":
        "addr >= image_end" in body(lkm, "int kp_hook_owner_register(") and
        "addr >= text_end" in body(lkm, "int kp_hook_owner_register(") and
        "rc = -EINVAL" in body(lkm, "int kp_hook_owner_register("),
    "KPIMG rejects KPM data/rodata as a callback owner":
        "addr >= image_end" in body(kpimg, "int kp_hook_owner_register(") and
        "addr >= text_end" in body(kpimg, "int kp_hook_owner_register(") and
        "rc = -EINVAL" in body(kpimg, "int kp_hook_owner_register("),
    "LKM transient callback get pins only LIVE or LOADING and checks overflow":
        "mod->active_calls++" in body(lkm, "int kp_hook_owner_call_get(") and
        "mod->state == KP_MODULE_LIVE || mod->state == KP_MODULE_LOADING" in
        body(lkm, "int kp_hook_owner_call_get(") and
        "mod->active_calls != UINT_MAX" in body(lkm, "int kp_hook_owner_call_get("),
    "LKM unload waits for async and hook owner pins":
        "mod->active_calls || mod->hook_refs" in body(lkm, "long kp_unload_module("),
    "KPIMG persistent owner pin increments hook_refs":
        "pos->hook_refs++" in body(kpimg, "int kp_hook_owner_register("),
    "KPIMG transient callback get pins only LIVE or LOADING and checks overflow":
        "mod->active_calls++" in body(kpimg, "int kp_hook_owner_call_get(") and
        "mod->state == KP_MODULE_LIVE || mod->state == KP_MODULE_LOADING" in
        body(kpimg, "int kp_hook_owner_call_get(") and
        "mod->active_calls != UINT_MAX" in body(kpimg, "int kp_hook_owner_call_get("),
    "KPIMG unload waits for async and hook owner pins":
        "mod->active_calls || mod->hook_refs" in body(kpimg, "long unload_module("),
    "LKM file load checks kernel_read return and final position":
        "ssize_t read_len = kernel_read" in body(lkm, "long kp_load_module_path(") and
        "read_len != len || pos != len" in body(lkm, "long kp_load_module_path("),
    "KPIMG file load checks kernel_read return and final position":
        "ssize_t read_len = kernel_read" in body(kpimg, "long load_module_path_event(") and
        "read_len != len || pos != len" in body(kpimg, "long load_module_path_event("),
    "LKM event snapshots roll back references on counter overflow":
        "pos->active_calls == UINT_MAX" in body(lkm, "long kp_notify_modules_event(") and
        "snapshot[i]->active_calls--" in body(lkm, "long kp_notify_modules_event(") and
        "return -EOVERFLOW" in body(lkm, "long kp_notify_modules_event("),
    "KPIMG event snapshots roll back references on counter overflow":
        "pos->active_calls == UINT_MAX" in body(kpimg, "long notify_modules_event(") and
        "snapshot[i]->active_calls--" in body(kpimg, "long notify_modules_event(") and
        "return -EOVERFLOW" in body(kpimg, "long notify_modules_event("),
    "module lookup refuses active-call counter overflow":
        "mod->active_calls == UINT_MAX" in body(lkm, "static struct kp_module *kp_module_get(") and
        "mod->active_calls == UINT_MAX" in body(kpimg, "static struct module *module_get_live("),
}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
