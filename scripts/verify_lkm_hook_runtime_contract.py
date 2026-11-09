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
        "__atomic_load_n(&wrap->using, __ATOMIC_ACQUIRE) == 1" in hmem and
        "wrap->addr == origin_addr && wrap->type == type" in hmem,
    "inline hook publishes only after successful patch":
        "hook_mem_publish(hook);" in hook,
    "inline chain publishes only after successful install":
        "hook_mem_publish(chain);" in hook,
    "function-pointer chain publishes after callback slot setup":
        fphook.index("err = fp_chain_add_locked(chain, before, after, udata);") <
        fphook.index("hook_mem_publish(chain);"),
    "transit reader lifetime protects retired callback tuples":
        "hook_chain_reader_enter(hook_chain" in hook and
        "hook_chain_reader_exit(hook_chain" in hook and
        "hook_chain_reader_enter(hook_chain" in fphook and
        "hook_chain_reader_exit(hook_chain" in fphook and
        "hook_chain_reap_slots_locked" in hook and
        "hook_chain_reap_slots_locked" in fphook,
    "callback owner refs cover the complete transit invocation":
        "hook_chain_pin_callbacks(hook_chain" in hook and
        "hook_chain_unpin_callbacks(hook_chain" in hook and
        "hook_chain_pin_callbacks(hook_chain" in fphook and
        "hook_chain_unpin_callbacks(hook_chain" in fphook and
        "before_owners" in hook and "after_owners" in hook,
    "transit loops no longer race on chain_items_max":
        "i < hook_chain->chain_items_max" not in hook and
        "i < hook_chain->chain_items_max" not in fphook,
    "KPIMG hook allocator uses a dedicated registry lock":
        "kp_private_spin_lock(&hook_mem_lock)" in hmem and
        "kp_private_spin_lock(&hook_engine_spinlock)" in hmem,
    "LKM hook allocator uses IRQ-safe spinlocks":
        "DEFINE_RAW_SPINLOCK(kp_hook_lock)" in runtime and
        "raw_spin_lock_irqsave(&kp_hook_lock, flags)" in runtime,
    "unregister APIs report busy instead of clearing live tuples":
        "int hook_unwrap_remove(" in hook and
        "return -EBUSY;" in hook and
        "int fp_hook_unwrap(" in fphook and
        "return -EBUSY;" in fphook,
    "KPM module managers provide persistent and transient owner refs":
        "int kp_hook_owner_register(" in read("kernel/patch/module/module.c") and
        "int kp_hook_owner_register(" in read("lkm/kpm/module.c") and
        "hook_refs" in read("kernel/patch/include/module.h") and
        "hook_refs" in read("lkm/kpm/module.h"),
    "function-pointer patch uses atomic exchange and compare-restore":
        "hotpatch_exchange64" in fphook and
        "hotpatch_cmpxchg64" in fphook and
        "kp_patch_exchange64" in read("lkm/infra/patch_memory.c") and
        "kp_patch_cmpxchg64" in read("lkm/infra/patch_memory.c"),
    "inline and function-pointer lookup use explicit types":
        "hook_get_mem_from_origin_type(origin, INLINE)" in hook and
        "hook_get_mem_from_origin_type(origin, INLINE_CHAIN)" in hook and
        "hook_get_mem_from_origin_type(fp_addr, FUNCTION_POINTER_CHAIN)" in fphook,
}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
