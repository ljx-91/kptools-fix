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
hook_engine = read("lkm/hook/hook_engine.c")
fphook = read("kernel/base/fphook.c")
patch_memory = read("lkm/infra/patch_memory.c")
manager = read("lkm/manager/manager.c")
manager_h = read("lkm/manager/manager.h")
init = read("lkm/core/init.c")

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
hook_make_nx = function_body(runtime, "static int kp_hook_make_nx(")
hook_update_exec = function_body(runtime, "static int kp_hook_update_exec(")
hook_exec_free = function_body(runtime, "static void kp_hook_exec_free(void *region, unsigned long size)\n{")
hook_install = function_body(hook, "int hook_install(")
phys_from_virt = function_body(patch_memory, "static unsigned long kp_phys_from_virt(")
manager_exit = function_body(manager, "int hook_rename_lsm_exit(void)")

syscall_unhook = function_body(read("lkm/infra/syscall_table.c"), "int kp_syscall_unhook(")
supercall_uninstall = function_body(read("lkm/supercall/supercall.c"), "int kp_supercall_uninstall(void)")

hook_kbuild = read("lkm/Kbuild")
transit4 = function_body(hook, "uint64_t __attribute__((section(\".transit4.text\")))")
reader_enter = hook.index("hook_chain_reader_enter(hook_chain, 0);", hook.index("_transit4("))
reader_pin = hook.index("hook_chain_pin_callbacks(hook_chain, 0", reader_enter)
reader_unpin = hook.index("hook_chain_unpin_callbacks(hook_chain, 0", reader_pin)
reader_exit = hook.index("hook_chain_reader_exit(hook_chain, 0);", reader_unpin)

checks = {
    "LKM transit object disables CFI, LTO, stack protector and conditional SCS":
        "-fno-sanitize=cfi -fno-stack-protector -fno-jump-tables" in hook_kbuild and
        "-fno-lto" in hook_kbuild and
        "CONFIG_SHADOW_CALL_STACK" in hook_kbuild and
        "CFLAGS_hook/hook_engine.o += -fno-sanitize=shadow-call-stack" in hook_kbuild,
    "LKM chain stub preserves x16 chain pointer and uses x17 for absolute branch":
        "transit[1] = 0x58000070; /* LDR X16, #12 */" in hook_engine and
        "transit[2] = 0x14000004; /* B #16 */" in hook_engine and
        "buf[0] = 0x58000051; // LDR X17, #8" in hook and
        "buf[1] = 0xD65F0220; // RET X17" in hook,
    "transit reader is entered before callback pin and released after callback unpin":
        reader_enter < reader_pin < reader_unpin < reader_exit,
    "Linux 4.14 without PTE_GP uses a zero BTI guard mask":
        "#ifdef PTE_GP" in runtime and "#define KP_HOOK_PTE_GP 0UL" in runtime and
        "#ifdef PTE_GP" in read("lkm/kpm/module.c") and "#define KP_LKM_PTE_GP 0UL" in read("lkm/kpm/module.c"),
    "LKM hook executable pages clear PXN/BTI guard while preserving UXN":
        "kp_hook_init_mm" in runtime and
        "pte_lockptr(kp_hook_init_mm, pmd)" in hook_update_exec and
        "set_pte_at(kp_hook_init_mm, addr, pte" in hook_update_exec and
        "v &= ~exec_deny_mask" in hook_update_exec and
        "v |= KP_HOOK_PTE_UXN" in hook_update_exec and
        "KP_HOOK_PTE_GP" in hook_update_exec,
    "LKM hook allocator fails closed when executable page setup fails":
        "kp_hook_make_exec(p, alloc_size)" in hook_exec_alloc and
        "kp_hook_exec_free(p, alloc_size);" in hook_exec_alloc and
        'kp_resolve_symbol("init_mm")' in hook_runtime_init and
        "return -ENOSYS;" in hook_runtime_init,
    "LKM hook pages are restored to NX/BTI before allocator reuse":
        "kp_hook_set_memory_nx" in runtime and
        "v |= nx_mask;" in hook_update_exec and
        "kp_hook_make_nx(region, size)" in hook_exec_free and
        "permission restore failed; leaking" in hook_exec_free and
        "mem->region_size = PAGE_ALIGN(size)" in runtime and
        "kp_hook_exec_free(mem->region, mem->region_size)" in runtime,
    "LKM trampoline publication broadcasts I-cache invalidation before patch":
        "kp_hook_module_alloc && kp_hook_module_memfree" in hook_runtime_init and
        "KP_HOOK_FLUSH_ICACHE_RANGE" in hook_install and
        "__flush_icache_all();" in hook_engine and
        hook_install.index("KP_HOOK_FLUSH_ICACHE_RANGE") < hook_install.index("return hotpatch("),
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
    "Linux 4.14 PUD block mappings are resolved before pud_bad":
        "pud_sect(*pud)" in phys_from_virt and
        "pud_page_paddr(*pud) & PUD_MASK" in phys_from_virt and
        phys_from_virt.index("pud_sect(*pud)") < phys_from_virt.index("pud_bad(*pud)"),
    "Linux 4.14 PMD block mappings are resolved before pmd_bad":
        "pmd_sect(*pmd)" in phys_from_virt and
        "pmd_page_paddr(*pmd) & PMD_MASK" in phys_from_virt and
        phys_from_virt.index("pmd_sect(*pmd)") < phys_from_virt.index("pmd_bad(*pmd)"),
    "syscall-table install compare-exchanges the observed original handler":
        "kp_patch_cmpxchg64(" in function_body(read("lkm/infra/syscall_table.c"), "int kp_syscall_hook(") and
        "old == fn" in function_body(read("lkm/infra/syscall_table.c"), "int kp_syscall_hook(") and
        "*orig = old;" in function_body(read("lkm/infra/syscall_table.c"), "int kp_syscall_hook("),
    "syscall-table teardown compare-restores only the owned handler":
        "kp_patch_cmpxchg64(" in syscall_unhook and
        "current == orig" in syscall_unhook and
        "current != expected" in syscall_unhook,
    "supercall teardown propagates restore failures and preserves callback state":
        "kp_syscall_unhook(KP_SUPERCALL_NR, kp_supercall_handler" in supercall_uninstall and
        "if (rc)" in supercall_uninstall and
        "retaining callback state" in supercall_uninstall and
        supercall_uninstall.index("if (rc)") < supercall_uninstall.index("kp_supercall_backend = KP_SUPERCALL_BACKEND_NONE"),
    "module exit checks supercall restore before other callback teardown":
        "BUG_ON(kp_supercall_uninstall());" in init and
        init.index("BUG_ON(kp_supercall_uninstall());") < init.index("BUG_ON(kp_sucompat_hook_exit());"),
    "manager rename hook teardown retires callback and waits for active readers":
        "hook_unwrap_remove(" in manager_exit and
        "kp_rename_hook_cb, 1" in manager_exit and
        "rc == -EBUSY" in manager_exit and
        "cond_resched();" in manager_exit and
        manager_exit.index("kp_rename_hook_addr = 0;") >
            manager_exit.index("if (rc && rc != -ENOENT)"),
    "manager teardown failure prevents module image release":
        "int hook_rename_lsm_exit(void);" in manager_h and
        "BUG_ON(hook_rename_lsm_exit());" in init and
        "hook_unwrap(" not in manager_exit,
    "inline and LKM chain preparation record the normalized argno ABI class":
        "chain->argno_abi_class = abi_class;" in hook and
        "chain->argno_abi_class = abi_class;" in hook_engine and
        "hook_argno_abi_class(argno)" in hook_engine,
    "inline wrap rejects invalid or mismatched transit ABI classes":
        "abi_class < 0" in function_body(hook, "hook_err_t hook_wrap(") and
        "chain->argno_abi_class != abi_class" in function_body(hook, "hook_err_t hook_wrap(") and
        function_body(hook, "hook_err_t hook_wrap(").index("chain->argno_abi_class != abi_class") <
            function_body(hook, "hook_err_t hook_wrap(").index("hook_chain_add_locked(chain"),
    "LKM chain prepare records ABI class before publishing transit":
        "chain->argno_abi_class = abi_class;" in function_body(hook_engine, "static hook_err_t hook_chain_prepare("),

}

for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
