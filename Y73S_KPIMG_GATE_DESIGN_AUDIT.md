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
