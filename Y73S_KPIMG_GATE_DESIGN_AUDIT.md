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


### Definitive closure: syscall-45 is the custom supercall and resolves to a 4-byte CFI stub (2026-11-11)

The previously conditional mapping is now proven from the selected branch and the original Y73S boot:

1. `kernel/patch/include/uapi/scdefs.h` defines `__NR_supercall 45`.
2. `kernel/patch/common/supercall.c` installs the KPIMG handler with `hook_syscalln_override(__NR_supercall, 6, before, 0, 0)`.
3. `kernel/patch/common/sysname.c` initializes `syscall_name_table[45]` as `"sys_truncate"`.
4. `kernel/patch/common/syscall.c:syscalln_name_addr()` tries, in order, `__arm64_sys_truncate.cfi_jt`, `__arm64_sys_truncate.cfi`, `__arm64_sys_truncate`, `sys_truncate.cfi_jt`, `sys_truncate.cfi`, and finally `sys_truncate`. The Y73S KALLSYMS dump has none of the first five names and has the plain `sys_truncate` alias at Image offset `0x019305cc`.
5. The Y73S KALLSYMS dump has no `sys_call_table` data symbol (the target config has `CONFIG_KALLSYMS_ALL=n`). The reviewed `hook_syscalln_override()` path therefore falls back to `inline_wrap_syscalln()`, which uses the name resolver above rather than a syscall-table slot.
6. The LKM's own supercall hook deliberately resolves `SyS_truncate.cfi` at Image offset `0x003cd6b8`; it does not target the public alias.

The original `boot.img` was materialized from the user's Library and its Android boot header parsed. The gzip kernel payload contains a valid AArch64 Image of 47,517,708 bytes. The original Image bytes were disassembled at both symbol locations:

| Image offset | Word | AArch64 instruction | Destination |
|---|---:|---|---:|
| `0x019305cc` | `0x17aa743b` | `B` | `0x003cd6b8` |
| `0x019305d0` | `0x17aa7474` | `B` | `0x003cd7a0` |
| `0x019305d4` | `0x17aa74ad` | `B` | `0x003cd888` |
| `0x019305d8` | `0x17aa753d` | `B` | `0x003cdacc` |
| `0x019305dc` | `0x17aa7657` | `B` | `0x003cdf38` |
| `0x019305e0` | `0x17aa7740` | `B` | `0x003ce2e0` |

The first four entries are the four adjacent aliases already identified in the symbol dump. KPIMG `branch_absolute()` emits four AArch64 instructions (16 bytes), and `hook_install()` writes those four words at the resolved target. Consequently the current KPIMG syscall-45 inline path overwrites all four adjacent CFI jump-table entries beginning at `0x019305cc`. This is no longer a conditional risk: it is a statically proven out-of-bounds patch relative to the intended single 4-byte syscall entry on this Y73S boot.

### Why a one-line symbol-name correction is not a safe complete fix

Changing `syscall_name_table[45]` from `"sys_truncate"` to `"SyS_truncate"` would make KPIMG resolve the canonical `SyS_truncate.cfi` implementation body. However, the LKM already installs its own independent inline hook at that same body address. KPIMG and LKM use separate Hook Engine registries, locks, trampoline allocations, and patch backends. Making the addresses equal without first consolidating ownership would convert the current adjacent-entry overwrite into an uncoordinated same-entry double-hook problem; it is not an acceptable stand-alone patch.

The safe architectural choices are therefore:

- Establish one owner for syscall 45 and a shared, explicitly versioned callback/dispatch ABI so the other component registers with that owner; or
- Remove one of the two syscall-45 handlers and deliberately route all required commands through the remaining handler, after proving that the removed side's KPM and SU operations remain available.

Do not simply rename the table entry, increase trampoline size, or patch only the first instruction without a proven branch-island/relocation design. Do not write Gate assembly on top of the current dual-owner arrangement.

### Updated status

- KPIMG syscall-45 target resolution to `0x019305cc`: **confirmed from source + Y73S KALLSYMS**.
- Original bytes at `0x019305cc..0x019305e0`: **disassembled and confirmed**.
- Four-entry overwrite from the 16-byte absolute branch: **confirmed from source + target bytes**.
- LKM target `SyS_truncate.cfi` at `0x003cd6b8`: **confirmed**.
- Safe single-owner syscall-45 design: **not yet selected/implemented**.
- No production hook code was changed. No vendor-KDIR build, runtime trace, or device test was performed.


### Same-target double-hook composition check

The same-target fallback option was checked against the actual relocation implementation rather than assumed to chain:

- `branch_absolute()` emits `LDR X17, #8; BR X17; .quad target`. Thus the first instruction's literal address is inside the four-word prologue range that `hook_install()` replaces.
- `hook_prepare()` computes `tramp_insts_num = 4` for this branch form, then relocates each of the four original words.
- `relo_ldr()` explicitly returns `-HOOK_BAD_RELO` when an LDR-literal target falls inside the range `[origin_addr, origin_addr + tramp_insts_num * 4)`; `is_in_tramp()` implements that exact range check.
- Therefore, if KPIMG is changed to target `SyS_truncate.cfi`, the other independent Hook Engine cannot simply install a second absolute-branch hook over the already-patched entry and expect the first branch literal to be relocated. The second `hook_prepare()` should reject that prologue as `HOOK_BAD_RELO` (subject to confirming each caller propagates the error without unsafe fallback).
- The same reasoning applies in reverse order: the first absolute branch installed by either engine places its literal inside the overwritten four-word range, so the second engine's relocation check rejects it.

This is a useful fail-closed property for a same-target double hook, but it does not repair the current distinct-target problem: KPIMG still writes 16 bytes over four neighboring CFI stubs at `0x019305cc`. It also means simply renaming KPIMG's syscall table entry is likely to make one supercall handler fail to install, not create a shared chain.

The next implementation decision must therefore be an explicit single-owner dispatch design with a proven bridge for the other component, or a deliberate removal/rerouting of one handler. Do not rely on independent Hook Engine copies to compose.


### Single-owner feasibility: command-surface and authentication comparison (2026-11-11)

The two syscall-45 handlers are not interchangeable drop-in implementations. Their command surfaces and authorization rules were compared:

| Capability | KPIMG `kernel/patch/common/supercall.c` | LKM `lkm/supercall/dispatch.c` |
|---|---|---|
| HELLO / version / kernel version | Yes | Yes |
| Build time | Yes | Explicit unsupported stub |
| SU query / task / allowlist / profile | Yes | Yes, through LKM SU state |
| SU get/reset path | Yes | Yes |
| SU allow SELinux context get/set | Yes | Not present in LKM dispatch switch |
| SU safe mode | Android-only | Not present |
| KStorage read/write/list/remove | Yes | Not present |
| Superkey get/set/root enable | Yes | Not present |
| AP package config | Android-only | Not present |
| KPM load/unload/control/list/info | Yes, KPIMG's own KPM loader | Yes, LKM's separate KPM loader |
| Control feature | Yes | Stub returns `-ENOENT` |
| KLOG / bootlog / panic / test | Yes | Not present |

Authentication also differs:
- KPIMG accepts a preset superkey (read from syscall argument 0), a trusted manager UID, or an SU-allowlisted UID. It sets `is_authed` only for the superkey or trusted manager; KPM and superkey-management commands are behind that stronger authenticated flag.
- LKM accepts manager UID or SU-allowlisted UID and dispatches its command set without the KPIMG superkey authentication path.
- Both handlers use the same command-number range and the same syscall number 45, but their implementations are not semantically equivalent.

KPM is especially important: the KPIMG command calls KPIMG's own `kernel/patch/module/module.c` loader and its private symbol resolver. The LKM command calls `lkm/kpm/module.c` and its Linux-kallsyms/LKM compatibility resolver. They are separate module registries and symbol namespaces. Replacing one handler with the other changes which KPM loader owns user-requested modules; it is not just changing the syscall hook owner.

### Consequence for single-owner design

Neither naive removal is currently safe to recommend:

- **Remove KPIMG handler, keep LKM:** LKM can serve its own SU and KPM subset, but KPIMG-only commands and KPIMG's private-symbol KPM loading path become unreachable through the existing syscall ABI. The LKM's current KPM resolver does not automatically gain access to KPIMG private exports.
- **Remove LKM handler, keep KPIMG:** KPIMG's own SU/KPM interfaces remain, but LKM-specific SU state/commands and its LKM KPM loader are no longer reachable through the manager's current syscall path. The LKM's exec compatibility hook and its SU credential path cannot be assumed to share KPIMG's allowlist/profile state.

A correct consolidation needs an explicit command ownership map and a versioned cross-component dispatch ABI. That ABI must define:
- which component owns authentication and how the authenticated identity/privilege level is conveyed;
- which component owns SU policy/profile state and how the LKM exec hook observes the same policy;
- which KPM loader owns modules, symbol namespaces, module lifetime, and unload;
- how KPIMG-only commands are preserved or intentionally deprecated;
- how registration, callback invocation, teardown, and Gate closure are ordered.

Do not implement a handler removal or command forwarding yet. The existing sources do not provide a proven LKM-visible KPIMG registration endpoint, and no shared policy-state ABI was found in this pass. The immediate blocker is now more specific: the Gate needs a real cross-component control/dispatch contract, not merely an exported function name.


### Existing KPIMG syscall-dispatch API: useful internally, not an LKM bridge (2026-11-11)

A further pass found that KPIMG does have a callback registry for syscall hooks, separate from its per-function inline Hook Engine:

- `kernel/patch/common/syscall.c` exports `hook_syscalln()`, `hook_syscalln_override()`, `unhook_syscalln()`, `syscall_hook_global_enabled()`, and `syscall_hook_set_gate()` with `KP_EXPORT_SYMBOL`.
- When the global dispatcher is active and handler-granular, `hook_syscalln_override(45, ...)` registers a callback in KPIMG's 64-slot syscall registry instead of installing a second per-syscall inline hook.
- This could be the right *internal KPIMG dispatch point* for a unified syscall-45 owner, but it is not currently callable by the LKM through its normal resolver.

Why it is not yet a bridge:
1. `KP_EXPORT_SYMBOL` in `kernel/include/symbol.h` emits a private record into section `.kp.symbol`; it is not Linux `EXPORT_SYMBOL` and does not add the function to Linux kallsyms/module exports.
2. KPIMG's own KPM loader resolves undefined symbols through its private `symbol_lookup_name()` first, then Linux kallsyms.
3. The LKM's `kp_resolve_symbol()` calls only Linux `kallsyms_lookup_name()`; its own KPM loader similarly checks its own compatibility resolver and Linux kallsyms. Neither path invokes KPIMG's private `symbol_lookup_name()`.
4. The KPIMG syscall registry snapshots raw callback and `udata` pointers under its private spinlock, then invokes them after releasing the lock. The inspected registry has no Linux-module owner token or `try_module_get()` around callbacks. Therefore merely making the registration function reachable would still not make an LKM callback safe to unload.
5. KPIMG KPM owner pin APIs (`kp_kpm_owner_pin/unpin/call_get/call_put`) protect KPIMG-managed KPM images, not an ordinary Linux LKM image. They cannot be treated as an LKM module reference protocol.

This narrows the implementation requirement. A real bridge needs both:
- a KPIMG-resident registration/dispatch endpoint reachable through an explicitly established ABI from the LKM (not a guessed private symbol address); and
- an owner-lifetime protocol that pins the Linux LKM before entering its text and drains in-flight calls before its image can be freed.

The existing KPIMG syscall callback table is a promising internal owner for syscall 45, but it cannot safely host an LKM callback without those two additions. The existing KPIMG private symbol namespace and callback table do not, by themselves, satisfy the selected resident-Gate design.


### Y73s / Linux 4.14.141: per-call Linux module symbol pin is a viable LKM callback-lifetime primitive (2026-11-11)

This pass found a better bridge-lifetime mechanism than storing `struct module *` in KPIMG and calling `try_module_get()` directly.

#### Exact 4.14.141 kernel behavior

Against `gregkh/linux:v4.14.141`:

- `kernel/module.c::__symbol_get()` is exported with `EXPORT_SYMBOL_GPL`.
- It disables preemption, calls `find_symbol(symbol, &owner, NULL, true, true)`, then calls `strong_try_module_get(owner)` before returning `sym->value`. If the symbol is not exported or its owner cannot be pinned, it returns NULL.
- `strong_try_module_get()` rejects `MODULE_STATE_COMING`, then delegates to `try_module_get()`; `try_module_get()` checks that the module is not `MODULE_STATE_GOING` and atomically increments a nonzero reference count.
- `__symbol_put()` resolves the same exported symbol name and calls `module_put(owner)`. It must only be called after a successful `__symbol_get()` for the exact same still-exported symbol.
- `try_stop_module()` first drops the loader's base reference. If any extra reference remains, it returns `-EWOULDBLOCK` without setting `MODULE_STATE_GOING`. The Y73s config evidence already recorded for this branch has `CONFIG_MODULE_UNLOAD=y` and `CONFIG_MODULE_FORCE_UNLOAD` disabled, so ordinary unload cannot force past this reference.

This gives the resident caller an atomic lookup-plus-owner-pin operation. It avoids the unsafe sequence “load a saved module pointer, then try_module_get()” and avoids retaining a permanent reference that would prevent ordinary unload.

#### Direct evidence in the original Y73s boot KALLSYMS

The original boot's extracted KALLSYMS log contains both canonical plain-name entries and CFI implementation entries:

| Symbol | CFI body Image offset | Plain-name entry Image offset |
|---|---:|---:|
| `__symbol_get` | `0x00235140` | `0x01913380` |
| `__symbol_put` | `0x00235034` | `0x01942dd8` |
| `try_module_get` | `0x002342bc` | `0x01913714` |
| `module_put` | `0x00234708` | `0x0193e844` |
| `kallsyms_lookup_name` | `0x0023dfa0` | `0x01922680` |

The plain-name entries are present despite the previously established `CONFIG_KALLSYMS_ALL=n`; these are exported kernel interfaces, not evidence that arbitrary non-exported symbols are visible. KPIMG's `kernel/base/start.c` already resolves and stores the kernel `kallsyms_lookup_name` pointer. The Y73s boot therefore has the ingredients for KPIMG to resolve `__symbol_get` and `__symbol_put` by name. The actual vendor ABI and indirect-call CFI type still need compile-time and runtime verification.

#### Candidate bridge shape

- Keep syscall 45 owned by the resident KPIMG dispatcher. Do not install a second LKM syscall-45 hook.
- Add one narrowly scoped LKM bridge function with a fixed, versioned request structure and export it through Linux `EXPORT_SYMBOL_GPL` (not KPIMG's private `KP_EXPORT_SYMBOL`).
- KPIMG resolves `__symbol_get` and `__symbol_put` through its already-initialized kernel kallsyms resolver.
- For each routed request, KPIMG calls `__symbol_get("kp_lkm_supercall_dispatch")`. If it returns NULL, the LKM backend is unavailable and KPIMG must follow an explicit command-ownership fallback policy.
- If it returns a function pointer, KPIMG calls it using one shared, exact prototype/header, then calls `__symbol_put("kp_lkm_supercall_dispatch")` on every return path.
- Do not cache the returned LKM function pointer beyond the pinned call. Do not cache an LKM module pointer. Do not call `__symbol_put` after a failed `__symbol_get`.

This makes the Linux module loader's own exported-symbol lifetime protocol the Gate: the module reference is acquired before control enters LKM text, and ordinary unload is blocked until the callback releases it. The resident KPIMG dispatcher itself remains resident, so a CPU delayed before entering it does not depend on LKM text or data.

#### Still-open requirements — not yet a production fix

1. Verify that the vendor Clang/CFI toolchain emits the exported bridge symbol as the callable canonical CFI entry and that KPIMG's indirect function-pointer call uses an identical prototype/type hash. The plain-name kernel symbols in the boot support this approach but do not prove the LKM export's generated address.
2. Check the exact vendor `Module.symvers`, `CONFIG_MODVERSIONS`, export policy, and Kbuild/modpost behavior when a Y73s KDIR becomes available. The runtime name lookup avoids a direct link-time import, but the LKM still must successfully publish its export.
3. Define a versioned request/reply ABI with explicit `handled` versus command-result status. A plain `-ENOSYS` cannot safely distinguish “LKM does not own this command” from “LKM owns it but the operation failed.”
4. Resolve the existing overlapping command IDs and auth/policy ownership. KPIMG and LKM currently maintain distinct SU authorization/policy paths and distinct KPM loaders; a safe symbol bridge does not make those semantics equivalent.
5. Only after the command ownership table, authentication contract, CFI prototype, and per-call pin/unpin error paths are specified should production code change.

Status: a target-kernel-native callback lifetime primitive is identified and backed by exact 4.14.141 source plus original Y73s boot KALLSYMS. The cross-component dispatch contract and production implementation remain open. No vendor-KDIR build, runtime race test, or device test is claimed.


#### KPIMG boot ordering and the syscall-45 single-owner route

The current boot sequence supports resolving the module-symbol helpers before syscall interception is installed:

- `kernel/base/start.c` resolves and stores the kernel `kallsyms_lookup_name` pointer during KPIMG startup.
- `kernel/patch/patch.c::before_rest_init()` calls `syscall_dispatch_init()` before `supercall_install()`.
- On this Y73s 4.14.141 target, the already-audited absence of `CONFIG_ARCH_HAS_SYSCALL_WRAPPER` means the global wrapper dispatcher is not installed by `syscall_dispatch_init()`; the per-syscall override path falls back to KPIMG's inline syscall hook.
- The current KPIMG syscall-name table maps syscall 45 to `sys_truncate`, which the original Y73s boot proves is a four-byte CFI jump-table alias at `0x019305cc`. That remains unsafe because the KPIMG absolute branch overwrites four adjacent alias entries.
- A single-owner KPIMG route should resolve the actual `SyS_truncate.cfi` implementation body (present in the original Y73s KALLSYMS) rather than the `sys_truncate` alias, and the LKM must stop installing its own syscall-45 hook. The LKM then exposes only the versioned command backend export, acquired per call with `__symbol_get()`.

This is a candidate migration sequence, not an implemented change. Before modifying the name table, the resolver must be tested against the exact Y73s symbol spellings and its generated target address must be asserted as `0x003cd6b8` (the `SyS_truncate.cfi` body), never `0x019305cc` (the unsafe alias). The LKM hook removal and KPIMG backend forwarding must land atomically or in an order that never leaves syscall 45 unhandled or double-hooked.


### SU authorization and policy-state ownership audit (Y73s / Linux 4.14.141, 2026-11-11)

This pass compared the actual KPIMG and LKM entry checks, dispatch switches, SU allowlist storage, profile handling, and KPM command handlers.

#### 1. Authentication levels are not equivalent

KPIMG `kernel/patch/common/supercall.c::before()` computes two separate facts:

- `is_trusted_caller`: preset superkey accepted, trusted manager UID, or SU-allowlisted UID.
- `is_authed`: preset superkey accepted or trusted manager UID. An ordinary SU-allowlisted UID does not set this bit.

The KPIMG `supercall()` dispatcher applies `if (!is_authed) return -EPERM;` before the Superkey management and KPM command groups. Therefore KPIMG distinguishes SU access from management-level KPM/Superkey access.

The LKM `lkm/supercall/supercall.c::kp_supercall_handler()` accepts manager UID or `kp_is_su_allow_uid(uid)`, then calls `kp_handle_supercall()` without passing a stronger-authentication bit. `lkm/supercall/dispatch.c` routes KPM load, unload, control, list, count, and info directly to the KPM handlers; `lkm/kpm/kpm.c` has no second manager/superkey authorization check in those handlers.

Both implementations initialize UID 2000 (Android shell) and UID 0 in their allowlists. Consequently, the LKM path permits an ordinary allowlisted UID, including the default shell entry, to reach LKM KPM management commands. The KPIMG path denies those commands to an allowlisted-only caller unless it also satisfies the stronger authentication rule.

**Severity: high.** Forwarding LKM KPM commands through a bridge that merely carries “caller is allowed” would preserve the weaker LKM policy and widen KPM-management access. The bridge ABI must carry a KPIMG-derived privilege class (at minimum `SU_ALLOWED` versus `MANAGER_AUTHENTICATED`) and LKM KPM handlers must reject requests below the required class. The backend must not independently re-infer privilege from a caller-supplied UID or a boolean supplied by userspace.

#### 2. The two SU allowlists are independent state stores

- KPIMG `kernel/patch/common/sucompat.c` owns a private `su_kstorage_gid` allocated from KPIMG's own KStorage implementation.
- LKM `lkm/supercall/sucompat.c` owns a separate `su_group` allocated from the LKM's own KStorage implementation.
- Both seed UID 2000 and UID 0 with the Magisk SELinux context, but subsequent grant/revoke operations update only the backend that receives the command.
- No shared backing store, synchronization, generation counter, or cross-backend invalidation mechanism was found.

Therefore a manager granting an app through one dispatcher does not establish that the other backend's SU exec hooks will recognize that UID. A split-owner transition can create contradictory authorization state. The unified design must nominate exactly one canonical allowlist owner and make every SU execution path query that owner through a stable interface, or deliberately disable the duplicate path. Mirroring writes asynchronously is not sufficient for security decisions.

#### 3. SU command semantics differ

| Command | KPIMG | LKM | Finding |
|---|---|---|---|
| `SU` | `commit_su()` | `kp_commit_su()` | Separate credential implementations; both must retain fail-closed SELinux behavior |
| `SU_TASK` | `task_su()` | `-EOPNOTSUPP` | Not equivalent; LKM intentionally refuses cross-task cred replacement |
| `SU_GRANT_UID/REVOKE_UID` | KPIMG KStorage | LKM KStorage | Independent allowlists; LKM validates NUL in profile context, KPIMG forces final byte to NUL |
| `SU_NUMS/LIST/PROFILE` | KPIMG allowlist | LKM allowlist | Reads can disagree because stores are independent |
| `SU_GET_PATH/RESET_PATH` | KPIMG pointer-backed path | LKM fixed 128-byte buffer | Different lifetime and validation semantics |
| `SU_GET/SET_ALLOW_SCTX` | Implemented in KPIMG | Not exposed in LKM dispatcher | KPIMG-only global context controls |
| `SU_GET_SAFEMODE` | Android-only KPIMG | Absent | KPIMG-only |
| SU exec interception | KPIMG `sucompat.c` hooks | LKM port explicitly allowlist-only; exec hooks out of scope | LKM cannot replace KPIMG exec compatibility path as-is |

The KPIMG `su_reset_path()` stores the passed pointer directly and has no allocation/free or lifetime management in the setter; the caller path uses `strndup_user()`. The LKM copies the path into a fixed static buffer and rejects overlong paths. These are not interchangeable contracts. The unified ABI should copy and validate the path into backend-owned storage, and should not forward a transient userspace-derived pointer into a persistent KPIMG field.

#### 4. Privilege boundaries for non-KPM commands also need an explicit policy

KPIMG currently places SU grant/revoke, path reset, global SELinux context set, control-feature, and generic KStorage read/write/list/remove before its `is_authed` gate. Thus these operations are available to any caller that passed the outer trusted-caller check, including an ordinary SU-allowlisted UID. The generic KStorage commands accept a caller-selected group and data ID, so their effective authority is broader than a narrowly scoped SU allowlist API.

LKM has no generic KStorage supercall surface and does not expose KPIMG's global SELinux context commands. It does expose SU grant/revoke/path commands to the outer manager-or-allowlisted caller. This is a policy design question, not merely a dispatch mismatch: the bridge must explicitly state which commands require SU privilege, manager privilege, or superkey authentication. It must not accidentally make KPIMG's broad legacy pre-auth command surface the permanent new policy.

#### 5. Safe ABI contract derived from this audit

The versioned request must include:
- ABI version and structure size;
- command ID and fixed-width arguments;
- a kernel-derived privilege enum, not a userspace-supplied UID/authorization boolean;
- a separate `handled` result from the operation's errno/result, so “backend does not own this command” cannot be confused with “owned operation failed”;
- explicit pointer direction/length rules for every user buffer;
- one canonical owner for SU allowlist, profile, default SELinux context, and SU path state.

Minimum privilege levels:
- `PUBLIC_QUERY`: only explicitly safe version/hello queries;
- `SU_ALLOWED`: SU self-operation and narrowly scoped SU status;
- `MANAGER_AUTHENTICATED`: grant/revoke/configuration and KPM management;
- `SUPERKEY_AUTHENTICATED`: only commands whose existing contract specifically requires preset superkey authentication.

The exact mapping of legacy commands to these levels must be reviewed against the manager application before changing behavior. Do not silently upgrade or downgrade existing callers.

Status: the SU auth mismatch, duplicated allowlist state, command behavior differences, and persistent path pointer contract are source-confirmed. No production changes were made. The proposed ABI is a design constraint, not yet an implementation. No vendor-KDIR build or device test is claimed.


### Dual KPM loader audit: independent registries, symbol universes, and executable-memory policy (Y73s / Linux 4.14.141, 2026-11-11)

This pass compared the KPIMG loader (`kernel/patch/module/module.c`) and LKM loader (`lkm/kpm/module.c`) rather than assuming their similarly named APIs form one subsystem.

#### 1. They are two independent module registries

KPIMG owns `struct module`, `modules.list`, and its own `module_lock`. LKM owns `struct kp_module`, a separate `modules.list`, and a different `module_lock`. Each registry independently tracks `LOADING/LIVE/UNLOADING/EXITING/DEAD`, `active_calls`, and `hook_refs`.

Consequences:
- Both loaders can accept the same KPM `.kpm.info` name because duplicate-name checks are local to each registry. No cross-registry uniqueness check exists.
- KPIMG list/count/info/control/unload operate only on KPIMG's registry; LKM equivalents operate only on LKM's registry. The same visible name can therefore identify two different images depending on which supercall dispatcher receives the command.
- Each loader owns its own callback owner tokens. KPIMG `kp_kpm_owner_pin/unpin/call_get/call_put` are KPIMG-private exports; LKM's identically named functions are local to the LKM KPM implementation and are used by the LKM Hook Engine. A token from one registry is not valid in the other.
- Their unload state machines are similar in broad outline, but the registry locks, module objects, executable allocations, and in-flight reference counts are not shared.

This is a real namespace split, not just duplicate front-end wrappers.

#### 2. The symbol universes are deliberately different

KPIMG's `simplify_symbols()` resolves undefined KPM symbols using KPIMG's private `symbol_lookup_name()`. The source explicitly leaves Linux `kallsyms_lookup_name()` fallback disabled in that path.

LKM's `simplify_symbols()` resolves in this order:
1. LKM's own `kp_kpm_symbol_lookup()` compatibility table;
2. Linux `kallsyms_lookup_name()`.

Neither loader calls the other loader's private resolver or shares an export table. `KP_EXPORT_SYMBOL` records are KPIMG-private `.kp.symbol` entries, not Linux module exports. Consequently, moving a KPM binary from one loader to the other is not a transparent operation: an undefined symbol may resolve in one namespace and fail in the other, or resolve to a different provider. A unified loader would need a versioned, collision-checked symbol ABI and a compatibility audit of every KPM import; adding guessed aliases is not safe.

#### 3. Executable-memory and CFI/BTI handling are not equivalent

The LKM loader:
- resolves matched allocator/free pairs (`module_alloc/module_memfree`, `execmem_alloc/execmem_free`, or a guarded vmalloc backend);
- verifies executable page permissions and BTI/GP state before entering KPM init;
- flushes the KPM instruction cache;
- restores NX/GP before freeing, and deliberately leaks the region if permission restoration cannot be verified;
- installs a KPM CFI-range bypass before exposing KPM commands when `CONFIG_CFI_CLANG` is enabled, and refuses to initialize the KPM loader if that bypass is unavailable.

The inspected KPIMG loader's `move_module()` allocates with KPIMG `kp_malloc_exec()`, copies sections, and later calls `flush_icache_all()`; that path does not contain the LKM loader's per-image executable-PTE/BTI verification and NX/GP restoration protocol. KPIMG uses its own earlier `bypass_kcfi()` startup path. These are distinct mitigation and memory-lifecycle implementations; one cannot be assumed to validate or protect the other's KPM images.

For Y73s 4.14.141 specifically, the LKM runtime probes `module_alloc` and `module_memfree` by symbol name and chooses that pair when both exist. This is a runtime selection, not proof that the vendor allocator's exact PTE/BTI properties have been validated. The original Y73s boot evidence and vendor KDIR are still required to close that target-specific property.

#### 4. The current syscall command IDs cannot identify which KPM registry is intended

Both dispatchers expose the same KPM command IDs from the shared supercall UAPI:
- `SUPERCALL_KPM_LOAD`
- `SUPERCALL_KPM_UNLOAD`
- `SUPERCALL_KPM_CONTROL`
- `SUPERCALL_KPM_LIST`
- `SUPERCALL_KPM_INFO`
- module count query.

The command payload does not include a loader namespace/version selector. Today the receiving dispatcher implicitly selects the registry. If syscall 45 becomes KPIMG-owned and blindly forwards all these commands to the LKM backend, existing KPIMG-loaded KPMs become invisible/unmanageable through those commands; if it keeps all commands in KPIMG, existing LKM KPMs become invisible/unmanageable. Forwarding by module name is ambiguous when both registries contain the same name.

#### 5. Safe consolidation options

No safe one-line choice exists. The viable choices require an explicit compatibility migration:

A. **KPIMG owns the syscall and keeps the KPIMG KPM registry.** LKM-only KPM features and existing LKM KPM images need a migration/import/export plan. The KPIMG resolver must not be extended with arbitrary Linux symbols without a reviewed export manifest.

B. **KPIMG owns the syscall and routes a separately versioned LKM-KPM namespace through the per-call `__symbol_get()` bridge.** This preserves both registries temporarily, but it is not one KPM loader: the UAPI must expose the namespace explicitly, list/info/control/unload must be namespace-qualified, duplicate names must be unambiguous, and each loader's own CFI/BTI and owner-lifetime policy remains separate. This is a compatibility bridge, not final consolidation.

C. **One loader becomes canonical and the other is retired.** Before retirement, inventory deployed KPM binaries and all imports, test relocation compatibility, define migration of module state and hooks, and prove that the canonical loader can safely load every supported image on Y73s 4.14.141. No such inventory or compatibility proof currently exists.

The safest immediate design is option B as a transitional ABI only if backward compatibility requires both existing KPM populations to remain manageable. It must be treated as two explicit namespaces, not as one merged name space. Final consolidation should wait until a KPM compatibility inventory exists.

#### 6. No production changes in this pass

The dual-registry behavior, duplicate-name ambiguity, separate owner tokens, private-vs-Linux symbol lookup, common command IDs, and differing executable-memory mitigation paths are source-confirmed. No production code was changed. No KPM migration was attempted, no vendor-KDIR build was run, and no device test is claimed.


### Y73s CFI slowpath: KPIMG and LKM attempt to own the same patched entry (2026-11-11)

This pass closes the target-specific CFI double-hook question using the extracted Y73s config, the original boot's recovered KALLSYMS, the original kernel bytes, and both implementations.

#### 1. Y73s configuration and symbol evidence

The extracted Y73s 4.14.141 config explicitly has:
- `CONFIG_CFI=y`
- `CONFIG_CFI_CLANG=y`
- `CONFIG_CFI_CLANG_SHADOW=y`
- `CONFIG_LTO=y` and `CONFIG_LTO_CLANG=y`

The validated original-boot KALLSYMS audit reports:
- `__cfi_slowpath` present at Image offset `0x002ddc00`
- `__cfi_slowpath_diag` absent
- `report_cfi_failure` absent
- `find_check_fn` is not established as a Y73s symbol by the current evidence; do not assume it exists.

The KPIMG `kernel/patch/common/secpass.c::bypass_kcfi()` falls back from missing `__cfi_slowpath_diag` to `__cfi_slowpath`, then calls `hook()` on that address during the early `before_rest_init` path. Thus KPIMG's CFI hook target on this Y73s image is the same `__cfi_slowpath` entry.

The LKM `lkm/infra/secpass.c::kp_bypass_kcfi()` independently performs the same fallback and calls its own `hook()` on the result. The LKM build includes `infra/secpass.o` in `lkm/Kbuild`, and `kernelpatch_init()` invokes `kp_bypass_kcfi()` after Hook runtime initialization. Therefore this is not dead/unbuilt source: the LKM attempts to hook the exact same kernel CFI slowpath after KPIMG has already installed its hook.

#### 2. The second Hook Engine cannot chain onto KPIMG's absolute branch

KPIMG's `kernel/base/hook.c::branch_absolute()` emits four AArch64 words:
- `LDR X17, #8`
- `BR X17`
- 64-bit target literal in the next two words.

`hook_prepare()` therefore overwrites 16 bytes at the original function entry.

The original Y73s boot bytes at `0x002ddc00` before patching are:
- `0xd10103ff`
- `0xa90157f6`
- `0xa9024ff4`
- `0xa9037bfd`

After KPIMG installs its absolute branch, the LKM Hook Engine does not recognize the `LDR X17` absolute veneer in `branch_func_addr_once()` (it only follows direct `B` and BTI entry forms). It therefore treats the patched entry as the original origin. Its `hook_prepare()` then attempts to relocate the first `LDR X17, #8`. `relo_ldr()` detects that the literal target `origin + 8` lies inside the 16-byte overwrite range and returns `-HOOK_BAD_RELO`. This is an expected fail-closed rejection, not a supported hook chain.

The two engines have separate registries and do not share the original trampoline or chain. There is no automatic callback composition.

#### 3. Current runtime consequence is a degraded KPM mode, not a successful second hook

In `lkm/core/init.c`:
- `kp_bypass_kcfi()` failure is logged but does not abort LKM initialization.
- Under `CONFIG_CFI_CLANG`, a failed CFI bypass prevents `kp_kpm_init()` from running; KPM supercalls are expected to return `-ENOSYS`.
- The LKM then continues to install its SU compatibility hook and its own syscall-45 hook.

On rollback, `kp_bypass_kcfi_exit()` calls `unhook_checked()` for the attempted target. Since the LKM engine never published a hook record for the KPIMG-owned entry, it receives `-ENOENT`, which the cleanup currently treats as already absent. It does not restore or overwrite KPIMG's hook. This avoids a second unhook of the KPIMG-owned CFI entry.

Thus the current source is fail-closed for LKM KPM loading on the Y73s CFI target, but it still performs a redundant, guaranteed-to-fail hook attempt and emits a misleading generic “CFI bypass failed” log. It must not be described as two working CFI layers.

#### 4. Ownership conclusion and safe direction

For Y73s / Linux 4.14.141, the CFI slowpath must have one patch owner. The current evidence identifies KPIMG as the earlier owner of `__cfi_slowpath`; LKM must not independently patch it.

The safest immediate behavior is:
- make LKM detect/receive an explicit KPIMG CFI-owner capability through the future versioned bridge;
- do not infer ownership merely from the first instruction bytes or from a failed second hook;
- when KPIMG owns the slowpath, do not attempt the LKM hook;
- keep LKM KPM loading disabled until KPIMG's resident CFI policy can explicitly authorize the LKM KPM executable range, or until a single shared CFI owner provides that policy;
- never weaken the CFI check globally or turn all failed checks into unconditional pass.

A future bridge must define the address-range registration lifetime, KPM unload synchronization, CFI type/CFI-shadow semantics, and rollback order. Merely forwarding a boolean “CFI bypass ready” is insufficient because KPIMG's current `should_cfi_pass()` recognizes KPIMG text/hook/KPM regions, not the LKM KPM allocation range.

Status: target config, symbol selection, original prologue bytes, both Hook Engine implementations, LKM Kbuild inclusion, and LKM fail-closed behavior are source/artifact-confirmed. No production code changed. No Y73s KDIR build, runtime hook test, or device test is claimed.


#### 5. Vendor-specific `__cfi_slowpath` ABI verified from the original Y73s machine code

Generic Clang CFI documentation describes the conventional two-argument `__cfi_slowpath(uint64_t, void *)` and three-argument `__cfi_slowpath_diag(uint64_t, void *, void *)`. That generic signature must not be imposed on this vendor kernel without checking its binary.

The original Y73s Image at `0x002ddc00` disassembles as follows in the relevant argument-preservation sequence:

- `0x002ddc1c: mov x20, x2`
- `0x002ddc20: mov x19, x1`
- `0x002ddc24: mov x21, x0`
- On the successful CFI-check path, `0x002ddcf8: mov x1, x19`, `0x002ddcfc: mov x2, x20`, followed by `blr x8`.

Thus the Y73s vendor implementation consumes and forwards all three AArch64 argument registers x0, x1, and x2. The existing KPIMG and LKM replacement/backup typedefs with three arguments match the observed Y73s machine-level ABI. This is a vendor-specific implementation detail and must not be generalized to upstream Clang CFI runtimes or other kernels.

This check also rules out treating the third argument as harmless padding on this target: it is forwarded to the resolved `__cfi_check` callback. Any future shared CFI Gate must preserve x2 exactly.

The generic Clang documentation is useful background only; the original Y73s disassembly is the controlling ABI evidence for this device.


### CFI range registry and lifetime audit: what a future KPIMG/LKM bridge must guarantee (2026-11-11)

This pass traced the actual range predicates and LKM KPM registry locking, rather than treating a successful address predicate as a lifetime reference.

#### 1. KPIMG's CFI allowlist is three fixed linker ranges

`kernel/include/common.h` defines `should_cfi_pass()` inputs as:
- `[_kp_text_start, _kp_text_end)`: KPIMG resident text;
- `[_kp_hook_start, _kp_hook_end)`: KPIMG hook area;
- `[_kp_rox_start, _kp_rox_end)`: KPIMG KPM executable arena.

`kernel/kpimg.lds` places the transit sections and KPIMG `.text/.rodata` in `.kp.text`, then lays out KPIMG data separately. The CFI predicate has no dynamic range registry and does not include Linux LKM `THIS_MODULE->core_layout.text_size`, LKM callback trampoline pages, or LKM KPM allocations.

Therefore the existing KPIMG slowpath replacement cannot authorize LKM KPM code, regardless of what the LKM's own `kp_kpm_cfi_allowed_addr()` returns.

#### 2. LKM's KPM range predicate is lock-protected but is not a lifetime pin

`kp_kpm_cfi_allowed_addr()`:
- returns false unless `kp_kpm_ready` is set;
- acquires `module_lock` with `spin_lock_irqsave()`;
- checks each registered KPM's `[start, start + text_size)` interval;
- releases the lock before returning the boolean;
- separately checks the callback trampoline page.

No module pointer escapes the locked scan. This is a sound bounded range lookup in isolation, but it only answers “was this address registered during the lookup?” It does not increment `active_calls`, reserve the KPM image, or protect the later indirect branch. The CFI predicate must never be treated as a substitute for the KPM owner's call reference.

#### 3. Existing LKM call paths show the required lifetime pairing

The LKM KPM implementation already uses separate lifetime references:
- control operations call `kp_module_get()` before entering KPM control callbacks and `kp_module_put()` afterwards;
- callback owner registration increments persistent `hook_refs`;
- transit callback execution obtains `active_calls` with `kp_hook_owner_call_get()` and releases it after the callback;
- `kp_kpm_safe_kallsyms_on_each_symbol()` obtains an owner by callback address before range decisions, then releases it after the kernel iterator returns;
- unload marks the KPM `UNLOADING`, refuses to free while `active_calls` or `hook_refs` remain, and frees executable memory only after both drain.

The bridge must preserve these references across the complete CFI-checked indirect call. A CFI “allowed” answer without the caller's active owner reference leaves a check/use race.

#### 4. Proposed bridge semantics: immutable provider call + per-call module reference + owner pin

A safe future KPIMG CFI provider call needs all of these properties:

1. KPIMG's resident slowpath obtains the LKM provider through a Linux module symbol lookup that also acquires a reference (candidate: `__symbol_get` for a deliberately exported, versioned provider symbol). Do not cache an unpinned raw LKM function pointer.
2. The provider is called only while that module reference is held; it performs the LKM registry lookup under `module_lock` and returns only a boolean/range classification, never an internal `struct kp_module *`.
3. The provider's ABI is fixed-width/versioned, CFI-signature-compatible with the Y73s three-register slowpath environment, and compiled with the required no-sanitize boundary where recursion would otherwise occur.
4. A positive CFI range result is accepted only when the *calling KPM operation* already holds an `active_calls`/owner reference that pins that exact KPM image until after the indirect call returns. The provider must not pretend to acquire that reference on behalf of an arbitrary CFI check.
5. On provider lookup failure (LKM absent, GOING, or symbol unavailable), KPIMG must fail closed for LKM KPM ranges and continue normal CFI enforcement. It must not turn “provider absent” into unconditional pass.
6. LKM teardown must first stop publishing new KPM calls, drain active calls and hook owners, and ensure no KPM image still depends on LKM text or callbacks before its module code can disappear. Only then can provider lookup naturally fail for subsequent checks.

This is a design contract, not implemented code. In particular, `__symbol_get` per CFI check may be too expensive; a persistent provider registration with a resident gate could reduce overhead, but it must include a safe unregister/close/drain protocol that does not itself make ordinary `rmmod` impossible. Do not choose persistent self-pinning as a shortcut.

#### 5. Current fail-closed status and a separate teardown concern

On the Y73s image, LKM's own CFI hook attempt cannot chain over KPIMG's absolute branch. Under `CONFIG_CFI_CLANG`, the LKM init path therefore leaves its KPM loader disabled when the CFI enforcement hook was not installed. This is currently safer than exposing LKM KPM loading without an effective CFI path.

The current `kernelpatch_exit()` does not call `kp_kpm_exit()`; that function is explicitly documented as init-failure-only and assumes the supercall entry was never published. This means the runtime unload contract for a live LKM KPM registry is not yet established by this code path. Before enabling the bridge, audit whether LKM unload is forbidden while KPM images exist, whether all KPMs must be explicitly unloaded, or whether a full KPM shutdown/drain phase must be added. Do not assume the CFI range provider alone makes KPM images safe after LKM teardown.

Status: KPIMG linker ranges, LKM range predicate locking, active-call/owner reference pairing, and current LKM init gating are source-confirmed. The proposed provider contract is design-only. No production code changed; no target KDIR build or device test is claimed.
