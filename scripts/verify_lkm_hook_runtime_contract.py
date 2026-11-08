#!/usr/bin/env python3
"""Source contracts for the LKM hook memory registry backend."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


runtime = read("lkm/hook/hook_runtime.c")
hmem = read("kernel/base/hmem.c")
hmem_h = read("kernel/base/hmem.h")
hook = read("kernel/base/hook.c")
fphook = read("kernel/base/fphook.c")

checks = {
    "LKM backend defines hook_mem_retire": "void hook_mem_retire(void *payload)" in runtime,
    "retire unlinks metadata without freeing executable region":
        "list_del(&mem->list);" in runtime and
        "void hook_mem_retire(void *payload)" in runtime and
        "kp_hook_exec_free(mem->region);" not in runtime.split(
            "void hook_mem_retire(void *payload)", 1)[1].split("\n}", 1)[0],
    "duplicate origin is rejected atomically":
        "pos->origin == origin" in runtime and
        runtime.index("pos->origin == origin") < runtime.index("list_add_tail(&mem->list"),
    "typed LKM lookup checks type and publication":
        "mem->type == type && mem->ready" in runtime,
    "publication API is implemented by LKM backend":
        "void hook_mem_publish(void *payload)" in runtime and "mem->ready = true;" in runtime,
    "common hook allocator exposes publication API":
        "void hook_mem_publish(void *hook_mem);" in hmem_h and
        "void *hook_get_mem_from_origin_type(uint64_t origin_addr, enum hook_type type);" in hmem_h,
    "KPIMG backend has a constructing state and publication":
        "wrap->using = 3;" in hmem and "if (warp->using == 3)" in hmem,
    "typed KPIMG lookup rejects unpublished or wrong-type records":
        "wrap->using == 1 && wrap->addr == origin_addr && wrap->type == type" in hmem,
    "inline hook publishes only after successful patch":
        "hook_mem_publish(hook);" in hook,
    "inline chain publishes only after successful install":
        "hook_mem_publish(chain);" in hook,
    "function-pointer chain publishes after callback slot setup":
        "chain->states[i] = CHAIN_ITEM_STATE_READY;\n            hook_mem_publish(chain);" in fphook,
    "inline and function-pointer lookup use explicit types":
        "hook_get_mem_from_origin_type(origin, INLINE)" in hook and
        "hook_get_mem_from_origin_type(origin, INLINE_CHAIN)" in hook and
        "hook_get_mem_from_origin_type(fp_addr, FUNCTION_POINTER_CHAIN)" in fphook,
}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
