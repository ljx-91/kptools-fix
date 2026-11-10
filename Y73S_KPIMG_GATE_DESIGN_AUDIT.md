# Y73S KPIMG-resident Gate design audit

Date: 2026-11-10

Branch: `y73s-cred-layout-guards-20261108`

Scope: design and source audit only. This document does not claim a production Gate implementation, a Y73S KDIR build, or device validation.

## Decision

Continue with the KPIMG-resident Gate architecture. Do not add a permanent `try_module_get(THIS_MODULE)` self-reference to the LKM. The intended behavior is to retain ordinary module unload, provided the full entry-lifetime barrier can be implemented and validated.

## Source facts confirmed on the selected branch

### 1. The current inline chain enters LKM text

- `lkm/hook/hook_engine.c` defines `KP_HOOK_EXTERNAL_CHAIN_PREPARE` and supplies its own `hook_chain_prepare()`.
- That function selects `_transit0`, `_transit4`, `_transit8`, or `_transit12` from the LKM object and writes an absolute branch to that address into the chain stub.
- `lkm/hook/hook_engine.c` includes `kernel/base/hook.c`, so these transit functions are compiled into the LKM image in this build.
- `kernel/kpimg.lds` also places the corresponding `.transitN.text` sections from the KPIMG build of `kernel/base/hook.c` in the resident `.kp.text` section. Their presence in KPIMG does not change the target selected by the LKM-specific `hook_chain_prepare()`.

### 2. Chain payload and relocated original are separately allocated

- `lkm/hook/hook_runtime.c` allocates each hook payload with `kp_hook_exec_alloc()`, using a matched executable-memory backend such as `module_alloc()`, `execmem_alloc()`, or `vmalloc()`.
- The chain stub and the `hook_chain_t` payload are in that separately allocated region; the chain's first member is `hook_t`, which contains `relo_addr`.
- On successful `hook_unwrap_remove()`, `hook_mem_retire()` removes and frees only the small registry metadata object. It intentionally does not call `kp_hook_exec_free()` on the executable payload region.
- Therefore a retired chain payload, its branch stub, and its relocated-original trampoline remain allocated after the LKM registry entry is removed. This is currently a deliberate retention/leak policy that can support a late Gate fallback. It must not be silently changed to free or recycle those regions.

### 3. Existing transit code is not dependency-closed inside KPIMG

The transit functions in `kernel/base/hook.c` call:
- `hook_engine_lock()` / `hook_engine_unlock()`;
- `kp_hook_owner_call_get()` / `kp_hook_owner_call_put()`;
- callback pointers and callback owner metadata stored in the chain payload.

In the LKM build, the lock and owner-call backends are LKM functions. Merely changing the chain stub to branch to the KPIMG copy of `_transitN` would still allow resident code to call into an unloading LKM. The complete call dependency closure must either remain resident or be protected by a module reference acquired before entering it.

### 4. Existing KPIMG symbol export is not yet an LKM handoff API

- KPIMG's `KP_EXPORT_SYMBOL()` records symbols in its private `.kp.symbol` table; `symbol_lookup_name()` searches that table.
- The LKM's `kp_resolve_symbol()` in `lkm/infra/symbol_resolver.c` uses Linux `kallsyms_lookup_name()`.
- The reviewed LKM startup path does not currently establish a direct, versioned registration/handoff for a KPIMG Gate API.
- A Gate implementation therefore needs an explicit and validated KPIMG-to-LKM handoff. It must not assume that KPIMG-exported symbols automatically appear in Linux kallsyms or are directly linkable from the LKM.

## Required Gate contract

The Gate and its state must reside in memory that outlives the LKM image. The chain payload used by the late fallback must also remain retained.

### Entry path

1. The existing chain stub continues to load its chain pointer into `x16`.
2. The stub branches to a KPIMG-resident, arity-specific Gate entry. No instruction before the first Gate operation may dereference an LKM pointer or call LKM text.
3. The Gate atomically acquires a token from a resident combined closed-bit/active-count state. The state transition must reject new tokens once closed and must detect count overflow.
4. If the Gate is closed, it reads only the stable chain header field containing `hook.relo_addr`, releases no LKM-owned resource, and tail-branches to that relocated-original trampoline. It must not inspect callback arrays, owner pointers, LKM function pointers, or LKM data.
5. If the Gate is open, it obtains a Linux module reference using a safely handed-off `struct module *` and a correctly resolved `try_module_get()` entry. Only after that succeeds may it enter LKM transit. If module acquisition fails because the module is already going away, it takes the same relocated-original fallback.
6. On the LKM path, preserve the original return value across `module_put()` and Gate-token release, then return to the original caller.

### Teardown path

1. Close the resident Gate atomically. The close operation and token acquisition must use one coherent atomic state machine so there is no "saw open but not counted" window.
2. Restore/remove every hook while the retained chain payloads remain valid.
3. Wait until all accepted Gate tokens have drained. A token acquired before module reference acquisition must also be counted: module teardown can begin while that entrant is still deciding whether `try_module_get()` succeeds.
4. Clear the handed-off module pointer and LKM entry pointers only after the Gate is closed and the active count is zero.
5. Never free/recycle retired chain executable regions merely because the Gate count reached zero. A CPU may already have branched to a chain stub but be delayed before executing the Gate's first instruction; such a CPU is intentionally outside the Gate count. Retaining the stub and payload makes that late arrival safe: it observes the permanently resident closed Gate and branches to the retained original trampoline.

The same close/drain protocol must be used on init-error unwind if any hook could have been published.

## AArch64 ABI obligations

The Gate is entered by a branch stub, not a normal C call. Before implementation, define and test an assembly ABI for each supported arity (0, 4, 8, and 12):

- Preserve `x16` as the chain pointer until it has been safely saved.
- Preserve incoming integer argument registers `x0-x7`, indirect-result register `x8`, and `x30` while calling Gate helpers.
- Keep `sp` 16-byte aligned and leave stack-passed arguments (arguments 9-12) at the exact offsets expected by the downstream transit function.
- Do not corrupt the platform-reserved `x18` register.
- Preserve the original caller's return address and PAC/SCS assumptions; add the correct BTI landing instruction when required by the target.
- Preserve the original function's return value across the module-put and token-release helpers.
- Do not assume the current LKM synthetic Clang probe proves the Y73S vendor compiler's generated frame or CFI/SCS behavior.

A direct closed-path tail branch to `chain->hook.relo_addr` is preferable to calling a C fallback helper: it preserves the caller's argument/stack ABI and avoids touching LKM code. The chain layout offset must be expressed with shared compile-time layout assertions, not an unexplained numeric constant.

## Atomic and module-lifetime proof obligations

- Specify the resident Gate state encoding, CAS/LL-SC loop, memory orders, overflow behavior, and close/drain wait condition.
- Prove that a Gate token is acquired before reading the module pointer.
- Prove that teardown cannot clear the module pointer or free any LKM dependency while a token is held.
- Prove the module-get race in both orders: Gate entrant wins before module state becomes GOING; or module enters GOING first and module-get fails while the token keeps teardown from freeing Gate-visible state.
- Resolve the exact target-kernel `try_module_get()` and `module_put()` symbols and their vendor ABI/CFI entrypoints. The current absence of the Y73S vendor KDIR and Module.symvers prevents a symbol-CRC/build claim.
- Gate registration must publish all pointers before setting OPEN with release semantics; entry must acquire the state before reading those pointers.
- Gate close must prevent new accepted tokens before the teardown wait begins.

## Current blockers / status

| Item | Status |
|---|---|
| Independent chain payload and retained trampoline | Confirmed by source |
| Current LKM chain stub targets LKM transit | Confirmed by source |
| KPIMG resident transit sections exist | Confirmed by linker script |
| KPIMG transit dependency closure | Not satisfied by current code |
| KPIMG-to-LKM Gate registration ABI | Not implemented / not found in reviewed startup path |
| Arity-specific assembly Gate preserving AArch64 ABI | Not implemented |
| Atomic close/token proof | Design requirement only |
| Target `try_module_get` / `module_put` symbol and CFI validation | Blocked on vendor KDIR / runtime symbol evidence |
| Deterministic delayed-entry concurrency test | Not implemented |
| Y73S LKM build and device test | Not performed |

## Implementation order

1. Define a KPIMG-owned Gate state and an explicit registration API; prove the registration API is reachable from LKM without relying on Linux kallsyms to expose KPIMG-private symbols.
2. Add shared layout assertions for `hook_chain_t` and `hook_t`; define the only chain fields the closed path may read.
3. Implement and disassemble arity-specific resident entry stubs, initially with the Gate permanently closed and direct relocated-original fallback only.
4. Add host-side instruction/layout checks and a deterministic model test for delayed entry, close-vs-enter races, module-get failure, and token drain.
5. Only then add the open path and module-reference handoff; keep all callback dispatch behind successful module acquisition.
6. Integrate close/remove/drain into both normal exit and init-error unwind.
7. Run KPIMG CI, LKM source contracts, and—when available—vendor-KDIR build and device stress tests.

## Safety status

**The KPIMG-resident Gate is the selected architecture, but it is not implemented and unload safety is not yet established.** Until the complete Gate contract is implemented and validated, the LKM must still be treated as unsafe for ordinary unload while hooks are active. No self-pin or production behavior change is made by this audit document.


## Follow-up audit: KPIMG-to-LKM discovery path (2026-11-11)

### Confirmed negative result

A second pass checked the actual LKM symbol resolution and KPM loader, not only `kernel/base/symbol.c`:

- `kernel/base/symbol.c` exports `symbol_lookup_name`, `kp_symbol_count`, and `kp_symbol_list` through KPIMG's private `.kp.symbol` table. These are not Linux kallsyms exports.
- `lkm/infra/symbol_resolver.c` resolves names only with Linux `kallsyms_lookup_name()` and optional Linux `kallsyms_on_each_symbol()` variants.
- `lkm/kpm/symbols.c`'s compatibility table does not contain `symbol_lookup_name`, `kp_symbol_count`, or `kp_symbol_list`.
- `lkm/kpm/module.c:simplify_symbols()` resolves undefined KPM symbols first from that LKM compatibility table and then from Linux `kallsyms_lookup_name()`. It does not consult KPIMG's private symbol table.
- The reviewed `kernel/base/start.c` exports the KPIMG symbol resolver for KPIMG/KPM consumers, but no LKM-visible global handoff or registration callback is established by the current LKM startup path.

Therefore the previously noted handoff issue is now a confirmed architectural blocker: **adding `KP_EXPORT_SYMBOL(kp_hook_gate_register)` to KPIMG alone will not make it callable from this LKM.** Likewise, adding the symbol name to the LKM's KPM compatibility table would only publish an LKM-side address; it would not reveal the KPIMG resolver.

### Implications for candidate bridges

Do not implement any of these unproven shortcuts:

- Calling `symbol_lookup_name` through `kallsyms_lookup_name` (wrong symbol namespace).
- Guessing/scanning the KPIMG base or its private `.kp.symbol` bounds from a kernel address.
- Assuming the LKM KPM loader is the KPIMG's original KPM loader; the reviewed code is an LKM-side loader with a different undefined-symbol resolution path.
- Passing a KPIMG function pointer through an arbitrary kernel global or a guessed spare field.

A valid bridge must be explicitly created on both sides and have a stable lifetime. Candidate designs to evaluate separately are:

1. A KPIMG-owned registration endpoint reachable through an already-established, documented kernel-visible ABI. First prove such an endpoint exists on this exact KPIMG build; current source review has not found one.
2. A deliberately registered resident KPM shim whose relocation path is explicitly extended to resolve KPIMG-private exports, then uses a bounded callback ABI to register/unregister the LKM. This needs a separate lifecycle proof for the shim and must not be assumed to work with the current LKM KPM resolver.
3. Reconsider a non-KPIMG resident trampoline allocation only if the user explicitly changes the architectural requirement. It could be independent of LKM text, but it is not the selected KPIMG-resident design.

### Next safe action

Before writing Gate assembly, map every KPIMG entry/registration interface that is already reachable from the LKM on Y73S and identify a real, stable handoff. If none exists, stop and report that the selected architecture needs a deliberate cross-component ABI change. No production code should call an unresolved KPIMG address.

### Additional check: KPIMG's own KPM loader is not an LKM bridge

The repository also contains `kernel/patch/module/module.c`, the KPIMG-side KPM loader. Its `simplify_symbols()` resolves undefined symbols with KPIMG's private `symbol_lookup_name()`, which is the correct namespace for KPIMG-exported symbols. However:

- This loader is distinct from `lkm/kpm/module.c`, which is the loader used by the LKM supercall path reviewed here.
- The KPIMG loader's `load_module_ex()`, `load_module()`, and `unload_module()` entrypoints are not marked with `KP_EXPORT_SYMBOL` in the reviewed file; they are not established as callable public registration APIs for the LKM.
- The LKM loader's `simplify_symbols()` does not call the KPIMG-side loader or KPIMG `symbol_lookup_name()`.

Thus, the presence of a working KPIMG-side KPM resolver does not by itself solve the LKM handoff. Any bridge based on a resident KPM must explicitly route its load/registration through a proven KPIMG entrypoint, and its KPM image must remain resident until the LKM Gate has been closed and drained. The current source does not establish that route.

### Additional check: both KPIMG and LKM own syscall-45 supercall handlers

A further call-graph audit found an important control-plane path that was not covered by the earlier namespace-only review:

- KPIMG kernel/patch/common/supercall.c implements its own SUPERCALL_KPM_LOAD/UNLOAD/CONTROL/NUMS/LIST/INFO commands. Its KPM load path calls KPIMG load_module_path()/load_module() from kernel/patch/module/module.c.
- KPIMG installs that handler with hook_syscalln_override(__NR_supercall, 6, before, 0, 0), where __NR_supercall is syscall 45. Its before() callback sets skip_origin and returns the command result when the caller is trusted.
- KPIMG kernel/patch/common/syscall.c uses a global dispatcher only when syscall-wrapper support and a suitable handler-granularity target are available. Otherwise hook_syscalln_override() falls back to the syscall-table or inline per-syscall hook path.
- The LKM independently implements syscall 45 in lkm/supercall/supercall.c. Its SUPERCALL_KPM_* cases dispatch to kp_kpm_*_sc() and therefore to the LKM-side loader in lkm/kpm/module.c, not the KPIMG-side loader.
- On the Y73S target, the LKM init comments explicitly record that syscall-table data symbols are absent with KALLSYMS_ALL=n; the LKM then resolves and inline-hooks SyS_truncate.cfi. The target is Linux 4.14.141, so the modern syscall-wrapper/global-dispatch path must not be assumed.

This establishes that KPIMG has a userspace control plane for its own KPM loader. It does not establish a kernel-callable LKM-to-KPIMG registration API. The two implementations also use separate Hook Engine copies and separate KPM registries. Their use of the same syscall number creates a potential hook-order/dispatch collision: depending on the exact Y73S syscall-name resolution and patch composition, one handler may short-circuit syscall 45 before the other handler can run, or the second inline patch may fail/compose unsafely. The reviewed source alone does not prove which outcome occurs on the device.

The shared syscall-45 interface therefore cannot be treated as an implicit Gate bridge. Issuing or forwarding a KPM supercall from LKM code is not equivalent to directly calling KPIMG's private load_module() or symbol_lookup_name() functions. The KPIMG loader entrypoints are still not exported through Linux kallsyms or an established LKM-visible ABI.

### Required next checks

1. Resolve the exact syscall-45 name-table entry used by this KPIMG build and compare its final resolved address with the LKM's SyS_truncate.cfi target on the Y73S Boot symbol set.
2. Trace both Hook Engine install paths against the same target, including whether the second patch is rejected, chains through the first trampoline, or can leave stale/overwritten hook state.
3. Establish which supercall handler actually receives trusted-manager SUPERCALL_KPM_LOAD requests when both KPIMG and LKM are present. Do not infer this from command IDs alone.
4. Only after the collision is resolved, design an explicit registration ABI. A userspace KPM command path is a control plane, not by itself a safe in-kernel Gate handoff.

No Gate assembly or production Hook changes are justified by this finding. The KPIMG-resident Gate remains unimplemented; ordinary LKM unload safety remains unproven.

### Follow-up: the two syscall hooks do not share a Hook Engine registry

The two paths were compared down to their patch backends:

- KPIMG calls hook_syscalln_override() → inline_wrap_syscalln() → hook_wrap(). Its chain registry and payload allocation are owned by the KPIMG image; text writes go through kernel/base/hotpatch.c.
- LKM calls kp_install_inline_supercall() → hook() directly on SyS_truncate.cfi. Its hook registry is the LKM-local kp_hook_mems list in lkm/hook/hook_runtime.c; its text writes go through kp_patch_text_batch() in lkm/infra/patch_memory.c.
- Both compile a copy of kernel/base/hook.c, but they do not share a registry, chain object, or serialization lock. The LKM's local duplicate-origin check cannot see a KPIMG hook, and the KPIMG registry cannot see the LKM hook.
- The LKM hook_prepare() snapshots the instructions present at its target at install time. If those instructions already contain a KPIMG branch, relocation may preserve a branch into the KPIMG trampoline; this is not a shared-chain registration and does not by itself prove correct callback order or safe teardown.
- Conversely, the two patch backends do not coordinate their expected instruction snapshots. A later install/uninstall can overwrite a branch installed by the other side if the resolved patch ranges overlap.

Therefore the syscall-45 collision is a concrete architectural hazard, but the exact Y73S outcome still depends on whether KPIMG's syscall-name-table resolution and LKM's SyS_truncate.cfi resolution overlap or are branch aliases. The repository source reviewed here does not include a runtime trace proving the installed address/instruction sequence on the device.

### Gate implication

Do not build a Gate bridge on top of either current syscall-45 handler until a single owner/dispatch contract is established. The robust direction is to define one resident owner for syscall-45 dispatch and an explicit, versioned registration ABI for the other component, or to remove one of the competing handlers. Merely adding another hook callback in one image cannot register it with the other image's chain.


### Y73S Boot symbol cross-check: syscall 45 alias versus CFI body

The previously uploaded `vivo-y73s-kallsym-test.log` was searched directly for the exact truncate symbols. It contains two distinct symbol regions:

- `SyS_truncate.cfi` at Image offset `0x003cd6b8` (the implementation body selected by the LKM).
- `SyS_truncate` and `sys_truncate` aliases at Image offset `0x019305cc`.
- The following aliases are densely adjacent at four-byte intervals: `compat_SyS_truncate` at `0x019305d0`, `SyS_ftruncate` at `0x019305d4`, and `compat_SyS_ftruncate` at `0x019305d8`.

The LKM source explicitly documents that Linux 4.14 ARM64's public `sys_truncate` alias is a four-byte CFI jump-table stub and intentionally resolves `SyS_truncate.cfi` instead. Its resolver uses `kallsyms_lookup_name("SyS_truncate.cfi")`, which matches the Y73S symbol log at `0x003cd6b8`.

KPIMG `syscalln_name_addr()` uses a different name-resolution policy: for a table name it tries prefixes `__arm64_` then empty, and suffixes `.cfi_jt`, `.cfi`, then empty. If (as expected for native syscall number 45) the KPIMG table entry name is `sys_truncate`, the Y73S KALLSYMS contains no `__arm64_sys_truncate`, no `sys_truncate.cfi_jt`, and no `sys_truncate.cfi`; the final fallback is the plain `sys_truncate` alias at `0x019305cc`. The actual table initializer for entry 45 was not located in the reviewed file set, so this last mapping remains a high-confidence conditional rather than a fully closed proof.

The consequence if that mapping is confirmed is severe and concrete: KPIMG's `hook_prepare()` emits a 4-instruction absolute branch (`branch_absolute()`), and `hook_install()` patches `tramp_insts_num` words. At a four-byte CFI stub this writes 16 bytes beginning at `0x019305cc`, spanning the four adjacent entries at `0x019305cc`, `0x019305d0`, `0x019305d4`, and `0x019305d8`. `hook_prepare()` also snapshots six words from that address. This is exactly the adjacent-CFI-entry corruption the LKM's explicit target-selection comment is designed to avoid.

Therefore do not assume KPIMG and LKM simply hook the same function body. The likely current arrangement is KPIMG hooking the CFI jump-table stub while LKM hooks the implementation body; these hooks could execute in series for truncate, but KPIMG's 16-byte overwrite can also damage neighboring CFI entries and its trampoline may relocate adjacent branch stubs. The exact runtime branch chain is not established from KALLSYMS alone.

### Required closure before Gate work

1. Locate the exact KPIMG native syscall-name table initializer and prove `syscall_name_table[45].name` (or `.addr`) for this build.
2. Disassemble the original Y73S Image bytes at offsets `0x019305cc..0x019305e0` and `0x003cd6b8`, recording all four jump-table instructions and the implementation entry.
3. If KPIMG resolves the plain alias, treat its current syscall-45 inline hook as unsafe on this target; fix the resolver/table to select the canonical implementation body or remove the competing KPIMG handler, then add a regression test that rejects a 4-byte CFI-jump-table target.
4. Re-audit install/uninstall order and trampoline composition after the target is corrected. Do not infer safety merely because the two entry addresses differ.

This is still a source/symbol audit; no Y73S runtime trace, vendor-KDIR build, or device test has been performed. No production hook code was changed in this pass.
