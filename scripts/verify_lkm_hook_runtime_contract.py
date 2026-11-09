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
patch_memory = read("lkm/infra/patch_memory.c")

def function_body(source, signature):
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


hotpatch = function_body(runtime, "int hotpatch(void *addrs[], uint32_t values[], int count)")
patch_data = function_body(patch_memory, "static int kp_patch_data(")
patch_exchange = function_body(patch_memory, "int kp_patch_exchange64(")
patch_cmpxchg = function_body(patch_memory, "int kp_patch_cmpxchg64(")
patch_batch = function_body(patch_memory, "static int kp_patch_text_batch_stop(")
patch_text_batch = function_body(patch_memory, "int kp_patch_text_batch(")
hook_make_exec = function_body(runtime, "static int kp_hook_make_exec(")
hook_exec_alloc = function_body(runtime, "static void *kp_hook_exec_alloc(")
hook_runtime_init = function_body(runtime, "int kp_hook_runtime_init(void)")
hook_install = function_body(hook, "int hook_install(")

checks = {
    "LKM hook executable pages clear BTI guard and verify permissions":
        "kp_hook_init_mm" in runtime and
        "pte_lockptr(kp_hook_init_mm, pmd)" in hook_make_exec and
        "set_pte_at(kp_hook_init_mm, addr, pte" in hook_make_exec and
        "KP_HOOK_PTE_PXN" in hook_make_exec and
        "KP_HOOK_PTE_UXN" in hook_make_exec and
        "KP_HOOK_PTE_GP" in hook_make_exec,
    "LKM hook allocator fails closed when executable page setup fails":
        "kp_hook_make_exec(p, alloc_size)" in hook_exec_alloc and
        "kp_hook_exec_free(p);" in hook_exec_alloc and
        'kp_resolve_symbol("init_mm")' in hook_runtime_init and
        "return -ENOSYS;" in hook_runtime_init,
    "LKM trampoline publication flushes instruction cache before patch":
        "kp_hook_flush_icache_all" in hook_runtime_init and
        "return -ENOSYS;" in hook_runtime_init and
        "flush_icache_all();" in hook_install and
        hook_install.index("flush_icache_all();") < hook_install.index("return hotpatch("),
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
    "KPM async owner pin API is public and exported in both loaders":
        "int kp_kpm_owner_pin(unsigned long callback_addr, void **owner);" in
            read("kernel/include/kpmodule.h") and
        "KP_EXPORT_SYMBOL(kp_kpm_owner_pin);" in read("kernel/patch/module/module.c") and
        "kp_kpm_owner_pin" in read("lkm/kpm/symbols.c") and
        "kp_hook_owner_register(callback_addr, owner)" in
            read("kernel/patch/module/module.c") and
        "kp_hook_owner_register(callback_addr, owner)" in read("lkm/kpm/module.c") and
        "kp_hook_owner_call_get(owner)" in read("lkm/kpm/module.c"),
    "function-pointer patch uses atomic exchange and compare-restore":
        "hotpatch_exchange64" in fphook and
        "hotpatch_cmpxchg64" in fphook and
        "kp_patch_exchange64" in read("lkm/infra/patch_memory.c") and
        "kp_patch_cmpxchg64" in read("lkm/infra/patch_memory.c"),
    "inline and function-pointer lookup use explicit types":
        "hook_get_mem_from_origin_type(origin, INLINE)" in hook and
        "hook_get_mem_from_origin_type(origin, INLINE_CHAIN)" in hook and
        "hook_get_mem_from_origin_type(fp_addr, FUNCTION_POINTER_CHAIN)" in fphook,
    "LKM hook text patch delegates the complete instruction set atomically":
        "return kp_patch_text_batch(addrs, values, count);" in hotpatch and
        'kp_resolve_symbol("stop_machine")' in patch_memory and
        "kp_patch_stop_machine(kp_patch_text_batch_stop, &patch, NULL)" in patch_memory,
    "LKM hook text patch snapshots every word before any write":
        "Validate and snapshot every target before modifying the first word." in patch_batch and
        "patch->original[i] = READ_ONCE" in patch_batch,
    "LKM hook text patch rolls back partial writes and reports uncertainty":
        "applied = i + 1" in patch_batch and
        "rollback_failed" in patch_batch and
        "return rollback_failed ? -EUCLEAN : ret;" in patch_batch,
    "LKM hook text patch rejects duplicate and invalid cross-page targets":
        "patch->addrs[j] == patch->addrs[i]" in patch_batch and
        "phy & ~PAGE_MASK" in patch_batch and
        "PAGE_SIZE - sizeof(u32)" in patch_batch,
    "shared FIX_TEXT_POKE0 mapping is serialized":
        "DEFINE_RAW_SPINLOCK(kp_fixmap_patch_lock)" in patch_memory and
        "raw_spin_lock_irqsave(&kp_fixmap_patch_lock, flags)" in patch_memory and
        "raw_spin_unlock_irqrestore(&kp_fixmap_patch_lock, flags)" in patch_memory,
    "stop-machine text patch rejects atomic and interrupt context":
        "in_atomic()" in patch_text_batch and
        "irqs_disabled()" in patch_text_batch and
        "return -EWOULDBLOCK;" in patch_text_batch and
        "kp_patch_stop_machine(kp_patch_text_batch_stop, &patch, NULL)" in patch_text_batch,
    "fixmap data writes reject cross-page and non-word patches":
        "len != sizeof(u32)" in patch_data and
        "((unsigned long)dst & 3)" in patch_data and
        "phy_off > PAGE_SIZE - sizeof(u32)" in patch_data and
        "WRITE_ONCE(*(volatile u32 *)map" in patch_data and
        "READ_ONCE(*(const u32 *)src)" in patch_data,
    "atomic pointer patchers hold the shared fixmap lock":
        "raw_spin_lock_irqsave(&kp_fixmap_patch_lock, flags)" in patch_exchange and
        "raw_spin_unlock_irqrestore(&kp_fixmap_patch_lock, flags)" in patch_exchange and
        "raw_spin_lock_irqsave(&kp_fixmap_patch_lock, flags)" in patch_cmpxchg and
        "raw_spin_unlock_irqrestore(&kp_fixmap_patch_lock, flags)" in patch_cmpxchg,
}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
