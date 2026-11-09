# Y73S Hook Concurrency Audit (2026-11-08)

## Scope

Offline source audit of branch `y73s-cred-layout-guards-20261108`, HEAD
`d8c60856446bb488fe68aa305b1bbca1abd1f8ce`.

Reviewed:
- `kernel/base/hotpatch.c`
- `kernel/base/hmem.c`, `kernel/base/hmem.h`
- `kernel/base/hook.c`
- `kernel/base/fphook.c`
- `kernel/include/hook.h`
- `kernel/patch/include/kp_spinlock.h`
- `kernel/patch/common/kp_spinlock.c`
- `kernel/linux/include/linux/spinlock.h`
- `kernel/linux/include/linux/rcupdate.h`

No device access, flashing, partition writes, or runtime test was performed.

## Findings

### H1 — Hook-memory allocator and lookup are unsynchronized (Critical)

`hook_mem_zalloc()` scans `using`, then writes `using = 1`, origin and type,
and only afterwards clears the chain object. There is no atomic claim or lock.
Two CPUs can claim the same free slot. A concurrent
`hook_get_mem_from_origin()` can also observe `using == 1` and return the
chain while it is only partially initialized.

`hook_mem_free()`, `hook_mem_retire()`, and lookup also access `using` and
origin metadata without synchronization. The retired state prevents ordinary
reuse after a successful retirement, but does not close races around
publication, free, or lookup.

### H2 — Hook-chain callback dispatch races with add/remove (Critical)

The inline and function-pointer transit routines read `states[i]`, then
separately read `befores[i]`/`afters[i]` and `udata[i]`, and invoke the
callback. Removal changes READY to BUSY and clears those fields. A reader
that already observed READY can race with that clearing and observe a
partially changed tuple. The `dsb(ish)` operations do not provide a reader
lifetime guarantee and do not make the tuple update atomic.

`chain_items_max` is also concurrently written by add and read by transit
loops without a synchronization protocol. The duplicate-check and slot
allocation loops are not serialized, so concurrent add calls can both pass
the duplicate check or claim the same EMPTY slot.

### H3 — Concurrent first-time wrap can install multiple chains (Critical)

`hook_wrap()` and `fp_hook_wrap()` perform lookup followed by allocation
without serializing the compound operation. Two CPUs can both observe no
chain, allocate separate records, and attempt to patch the same origin
function/function pointer. `stop_machine()` serializes each patch operation,
but does not serialize the preceding lookup/snapshot/ownership transaction.

### H4 — Function-pointer snapshot occurs outside patch transaction (High)

`fp_hook()` reads the original 64-bit function pointer before calling
`hotpatch()`. The two 32-bit words are then patched under the stop-machine
callback on supported 4.6+ kernels. Stop-machine coordination protects
instruction patch execution, but does not make the earlier snapshot part of
the same ownership transaction. Concurrent writers can therefore preserve
the wrong predecessor and later restore a stale pointer.

### H5 — Callback code/data lifetime is not protected by chain memory retirement (Critical)

Retiring a chain record prevents its storage from being reused, but it does
not prevent a CPU that already loaded a callback pointer from executing it
after the callback's module/code/data has been unloaded. Nor does it wait
for in-flight transit invocations before a module unload proceeds. This is
separate from trampoline-storage lifetime.

### H6 — RCU helper needs correction/verification before use (High)

The local `kernel/linux/include/linux/rcupdate.h` declares
`synchronize_rcu()`, but its inline wrapper currently calls
`kfunc_call(rcu_barrier_tasks_rude)` rather than the declared
`synchronize_rcu` target. Do not rely on this wrapper as an RCU grace-period
wait until corrected and verified against the target kernel's symbol ABI.
Also verify that the target Y73S kernel resolves the required RCU read-side
and grace-period symbols before adopting RCU for callback lifetime.

## What is sound in the reviewed patch path

For Linux 4.6+ the current `hotpatch()` path checks the stop-machine symbol,
rejects unsafe interrupt-masked calls outside early boot, and calls
`stop_machine(hotpatch_cb, ..., NULL)`. The callback preflights all target
addresses, saves original instructions, applies the patch sequence, and
attempts reverse-order rollback. A rollback failure returns `-EUCLEAN`.
This is useful patch-transaction protection, but it is not a substitute for
serializing hook ownership and callback-chain lifetime.

## Remediation plan (not yet implemented)

1. Establish a KP-owned management lock with a documented lock order. Use it
   to serialize allocator claim/publication/free/retire and the complete
   lookup-or-create plus install/uninstall transaction. Do not call arbitrary
   callbacks while holding this lock.
2. Make chain publication explicit: initialize all metadata and transit
   storage first, then publish an ACTIVE state with release semantics. Lookup
   must acquire-load that state and reject INITIALIZING/RETIRING/RETIRED.
3. Replace in-place callback tuple mutation with a reader-safe design.
   Preferred direction is immutable callback snapshots plus a verified
   grace-period mechanism, or a per-chain active-reader protocol with a
   proven unload wait. A state flag and barriers alone are insufficient.
4. Correct and test the RCU wrapper/symbol mapping before using RCU. Confirm
   read-side semantics in the actual Linux 4.14.141 target and ensure module
   unload waits for callbacks to finish.
5. Put function-pointer read/replace/restore under the same serialized
   ownership protocol. Reject unexpected current pointer values rather than
   blindly restoring a stale snapshot.
6. Add deterministic host-side model tests for simultaneous first-wrap,
   duplicate adds, add/remove versus dispatch, unhook versus in-flight
   callback, failed patch rollback, and module unload. Add static checks for
   all public call sites and return-value handling.

## Release decision

**Not ready for device testing or a flashable image.** The existing GCC/CI
success only establishes compilation and the configured static checks. It
does not establish concurrent hook correctness, callback unload safety, or
device boot/runtime success. No code changes are made by this audit report.


## Follow-up: RCU wrapper correction and target symbol evidence (2026-11-08)

The wrapper defect identified in H6 has now been corrected in
`kernel/linux/include/linux/rcupdate.h`: `synchronize_rcu()` dispatches to
`kfunc_call(synchronize_rcu)`, not `rcu_barrier_tasks_rude`. Regression
assertions were added to `scripts/verify_y73s_fphook_contract.py`.

The updated GCC 14.2 workflow passed on commit
`cf69972748c8b0ce7395c769d6f54c55b90a45e4` (run
`42494604969`). This confirms compilation and the source regression checks
only.

A previously recovered Y73S Linux 4.14.141 kallsyms listing contains
`synchronize_rcu.cfi` at image offset `0x001dc35c` and
`__rcu_read_unlock` at `0x01940484`. Exact-name searches in that listing did
not find `__rcu_read_lock` or `rcu_barrier_tasks_rude`. The listing is a
static extraction, not a live runtime symbol-resolution trace. The KP shim
uses suffix-based kallsyms lookup, so the exact alias resolution behavior
must be verified before relying on these symbols. In particular, do not
assume the RCU read-side wrapper is operational merely because the header
compiles.

**Updated RCU decision:** the wrong synchronize wrapper is fixed, but RCU
is still not approved as the hook callback lifetime mechanism. Verify actual
lookup results and read-side semantics against the target kernel first; if
any required function is absent or ambiguously resolved, fail closed and use
another proven lifetime protocol.


## Follow-up: CFI suffix resolver audit (2026-11-08)

The Y73S kallsyms evidence includes `synchronize_rcu.cfi`, but not an
unsuffixed `synchronize_rcu` name in the recovered listing. The suffix
resolver previously rejected every suffix token named `cfi`, despite its
comment claiming to reject only `.cfi_jt` jump-table stubs. Consequently,
the corrected `synchronize_rcu()` wrapper could still fail to resolve the
available instrumented implementation. The resolver now accepts the real
`.cfi` implementation and rejects only the `.cfi_jt` jump-table stub.
Source regression assertions cover both rules.

GCC 14.2 build and all configured static audits passed on commit
`531640d14248a6412edaff8afd7deb53ab3a9a94`, workflow run
`42495162302`. This remains a build/static result, not runtime symbol
resolution evidence.

### Final RCU assessment for this target

The recovered Y73S symbol listing contains `__rcu_read_unlock` but does not
show `__rcu_read_lock`. The KP `kfunc_call_void` family silently does
nothing when a function pointer is unresolved. Therefore the presence of a
corrected `synchronize_rcu()` wrapper does not establish a working RCU
read-side critical section. RCU is **not approved** as the callback lifetime
solution for this target. Do not use it to justify callback/module unload.

### Release gate

The source and build audit is complete for this pass. The Hook allocator,
chain publication, callback add/remove/dispatch, concurrent first-wrap, and
callback code/data lifetime races remain unresolved. The existing private
spinlock helper is not by itself a lifetime protocol; holding a spinlock
across arbitrary callbacks is unsafe, and waiting synchronously for readers
can deadlock if a callback removes itself. A safe implementation needs an
explicit callback owner/unload contract plus a proven reader-quiescence
mechanism, or must permanently pin callback code/data and reject unsafe
removal. Until that design is implemented and tested, the branch is **not
release-ready and not suitable for device boot testing**.

No device write, Fastboot operation, partition modification, or runtime test
was performed.


## Follow-up: KPM callback ownership and unload ordering (2026-11-08)

A further lifecycle audit of `kernel/patch/module/module.c`,
`kernel/linux/include/linux/rcupdate.h`, `kernel/base/hook.c`, and
`kernel/base/fphook.c` found an additional release blocker.

### 1. KPM exit runs inside an RCU read-side section

Current `unload_module()` performs the following sequence:

1. `rcu_read_lock()`;
2. find the module and unlink it with `list_del()`;
3. invoke `mod->exit()` while still inside that read-side section;
4. free module text with `kp_free_exec()` and free the module object;
5. only then call `rcu_read_unlock()`.

This ordering is incompatible with an exit callback that waits for an RCU grace
period: `synchronize_rcu()` called from `mod->exit()` can wait for the very
read-side section that cannot finish until `mod->exit()` returns. It also frees
module text before leaving the section that is intended to protect readers.
The unload path has a `// todo: lock` marker and does not provide a complete
module lifetime protocol.

### 2. Y73S RCU read-side symbol mapping is not proven

The current compatibility header implements `__rcu_read_lock()` by
`kfunc_call(__rcu_read_lock)` and `__rcu_read_unlock()` by
`kfunc_call(__rcu_read_unlock)`. The recovered Y73S kallsyms listing contains
`__rcu_read_unlock` but has no exact `__rcu_read_lock` entry. The kfunc call
helper silently skips unresolved functions. Therefore the shim may not execute
the read-side lock operation while still resolving the unlock operation. This
must be treated as an invalid/unbalanced RCU mapping until the actual target
implementation and resolver behavior are proven. Do not use the module
loader's RCU sections as evidence that KPM text is pinned on this target.

### 3. Hook callback owner is not tracked

The inline and function-pointer chain entries contain callback pointers and
`udata`, but no KPM owner/module reference. `hook_wrap()` and
`fp_hook_wrap()` cannot currently pin the module containing the callback.
KPM documentation tells modules to unregister hooks from `.kpm.exit`, but
unregistering currently only clears a READY slot; it does not wait for a CPU
that already loaded the callback pointer or is between before/origin/after
phases. Since `unload_module()` frees module executable memory immediately
after the exit callback, an in-flight callback can execute freed text or
access freed module data.

### 4. Required architectural correction (not applied in this pass)

Do not add a call to `synchronize_rcu()` inside a KPM exit callback as a
workaround. The safe correction requires coordinated changes:

- replace the current module-list/unload lifetime scheme with a serialized
  module state machine (LIVE -> UNLOADING -> QUIESCED -> FREED), and ensure
  module callbacks cannot start after UNLOADING;
- do not invoke a module exit callback while holding an RCU read-side lock;
- provide a proven target-specific reader mechanism, or an explicit KP-owned
  active-call/reference protocol that does not depend on the unresolved
  `__rcu_read_lock` symbol;
- associate hook chain entries with their owning KPM (explicit owner token or
  a validated callback-address-to-module mapping);
- acquire a callback reference before reading/invoking its pointer, retain it
  across both before and after phases, and prevent slot reuse until all refs
  drain;
- make removal report a pending/busy state and provide an unload path that
  waits only from a sleepable, non-self-callback context; reject or defer
  self-unload rather than waiting on the caller's own reference;
- only free module text/data after both ordinary KPM entry points and Hook
  callback references have reached zero.

A spinlock around list mutation alone is insufficient. Holding a spinlock
across arbitrary callbacks is unsafe, and a global wait from within the same
callback can deadlock. Existing void unregister APIs also cannot communicate
that a callback is still executing, so an unload-safe API/contract change is
required.

### Release status

The CFI suffix resolver and KPIMG build checks passed on commit
`531640d14248a6412edaff8afd7deb53ab3a9a94`. This follow-up is a static
source audit only. The KPM unload ordering, RCU mapping, Hook callback owner
tracking, and in-flight callback quiescence remain unresolved. The branch is
still **not release-ready and not suitable for device boot testing**.


### 5. Additional module-manager defects in the same lifecycle path

The module-manager scan also confirmed:

- `module_lock` is initialized in `module_init()`, but the only two
  occurrences in `kernel/patch/module/module.c` are its declaration and
  initialization. It does not serialize module-list insertion, removal,
  lookup, or unload. `load_module_ex()` appends to the list without taking
  it, while `unload_module()` removes from the list without taking it.
- `notify_modules_event()`, `module_control0()`, and `module_control1()`
  invoke arbitrary KPM code while inside `rcu_read_lock()`. A callback that
  tries to wait for an RCU grace period can self-deadlock if the read-side
  operation is effective. If the Y73S `__rcu_read_lock` mapping is ineffective,
  those callbacks instead run without the intended lifetime protection.
- `get_module_info()` enters `rcu_read_lock()` and returns `-ENOENT`
  immediately when `find_module()` fails, without the matching
  `rcu_read_unlock()`.
- `find_module()` itself performs an ordinary list traversal and relies on
  callers to establish protection; it does not acquire the module lock.

These findings make the existing module manager an unsafe foundation for
Hook-owner reference tracking until its list serialization, callback-entry
references, and teardown sequencing are redesigned together. They are not
fixed by changing only the Hook chain spinlock.


### 6. Follow-up: control-buffer and list-reader races (2026-11-08)

The full module-manager path and structure were inspected, including
`kernel/patch/include/module.h`, `kernel/include/kpmodule.h`,
`kernel/patch/common/kp_spinlock.c`, and the complete exported manager
functions.

#### M1 — `module_control0()` shares a mutable argument buffer (Critical)

`struct module` stores one `char *ctl_args`. Each `module_control0()`
call frees the previous buffer, allocates a replacement, and invokes
`mod->ctl0(mod->ctl_args, ...)`. There is no per-module serialization.
Two concurrent control calls can therefore free/replace the buffer while
another callback is still using it. The callback receives a dangling pointer
and can read freed memory. Unload also frees `ctl_args`, compounding the
lifetime race.

Preferred correction: make the control argument copy call-local, pass that
local immutable buffer to ctl0, and free it only after ctl0 returns. Do not
store transient call arguments in `struct module`. This assumes the documented
callback contract does not retain the argument pointer after return; that
contract must be explicit. A module active-call reference must still pin the
module text/data for the entire callback.

#### M2 — list operations are not a valid RCU list protocol (Critical)

The list is traversed by ordinary `list_for_each_entry()` in
`find_module()`, `notify_modules_event()`, and query functions, while
insertion uses `list_add_tail()` and removal uses `list_del()`. These are
not the RCU list primitives and no writer lock is taken. Merely surrounding
ordinary traversal with `rcu_read_lock()` does not make concurrent ordinary
list mutation safe. In particular, `list_del()` may poison links that a
concurrent reader is following. The missing target `__rcu_read_lock`
mapping is an additional independent reason not to rely on these sections.

A correct redesign must choose one coherent scheme: a KP-owned lock held for
short list traversal/mutation with references acquired before dropping it, or
a fully implemented RCU list protocol with RCU add/delete primitives and a
verified target grace-period implementation. Do not mix ordinary list
operations with nominal RCU read sections.

#### M3 — load publication and duplicate-name check are not atomic (High)

`load_module_ex()` checks `find_module(name)` before allocating, relocating,
and running `mod->init()`; it later appends the initialized object using
`list_add_tail()` without a lock. Two concurrent loads of the same name can
both pass the duplicate check, both run init, and both publish duplicate
entries. A concurrent unload or query can also overlap publication.

Serialize name reservation/publication with an explicit LOADING reservation
or manager lock. Do not hold a spinlock across relocation, init, or arbitrary
module callbacks. Roll back the reservation on every failure path.

#### M4 — event iteration calls arbitrary callbacks while walking mutable list (Critical)

`notify_modules_event()` iterates the live global list and calls each
module's event callback inline. Concurrent unload can unlink/free the current
or next module; concurrent load can mutate the traversal links. The RCU
annotations do not protect this because the list primitives are not RCU-safe
and the read-side lock mapping is unproven.

Take a stable snapshot of module references under the manager lock, release
the lock, invoke callbacks while holding each reference, then drop references.
If snapshot allocation is unavailable in the calling context, use a bounded
preallocated snapshot or a documented serialization mechanism; never call
arbitrary callbacks while holding the list spinlock.

#### M5 — query helper has an unmatched read unlock (High)

`get_module_info()` returns `-ENOENT` after acquiring `rcu_read_lock()`
without calling `rcu_read_unlock()`. This is a direct lock-balance defect.
It should use a single cleanup exit or, preferably, the redesigned module
reference API rather than RCU annotations around an ordinary list traversal.

#### Structure and lock observations

`struct module` currently contains only metadata, args/ctl_args pointers,
callback pointers, allocation sizes, executable start, and list node. It has
no state, active-call counter, wait primitive, owner identity, or per-module
lock. `module_lock` is initialized but not used by the manager operations.
The KP private spinlock helper can protect short KP-owned critical sections;
its fallback masks local IRQs and uses a local atomic lock. It does not
provide a sleepable wait, callback lifetime, or safe module unload by itself.

#### Consolidated design contract (design only; no production patch applied)

1. Add explicit module states: `LOADING -> LIVE -> UNLOADING -> QUIESCED -> FREED`.
   Publish LIVE only after init succeeds and duplicate-name reservation is
   committed. Reject new ordinary entries and hook registrations after
   UNLOADING begins.
2. Under a short manager lock, find a LIVE module and increment its active
   entry reference before returning the pointer. Drop the lock before any
   module callback. Every success/error path must release the reference.
3. For event fan-out, snapshot referenced modules under the lock, then invoke
   callbacks outside it. If a snapshot cannot be safely allocated, fail or
   serialize explicitly rather than traversing a concurrently mutable list.
4. Replace shared `ctl_args` with a call-local immutable buffer. Keep the
   module entry reference until ctl0 returns.
5. Hook registration must carry an explicit owner token tied to a LIVE module.
   Do not infer ownership from arbitrary callback addresses unless executable
   range validation is complete and handles every callback/data lifetime.
6. Hook transit must acquire a callback-entry reference before loading the
   callback tuple and hold it through the entire before/origin/after sequence.
   Unregister first prevents new acquisitions, then waits/defer-reports until
   in-flight references drain. Self-unregister/self-unload must return pending
   or busy; it must not synchronously wait for its own reference.
7. Unload changes LIVE to UNLOADING under the manager lock, removes visibility
   and rejects new refs, invokes exit outside the lock, unregisters owned hooks,
   waits only from a sleepable non-callback context for ordinary and hook refs
   to reach zero, then frees args/text/object. Define whether exit runs before
   or after hook quiescence and ensure no new callback can enter either phase.
8. All APIs must document context constraints (sleepable vs atomic), recursion,
   callback retention rules, and exact error/pending semantics.

#### Verification gates

Add deterministic model tests for simultaneous duplicate loads, concurrent
ctl0 calls, event iteration versus unload, lookup versus unlink, failed init
rollback, missing-module info lookup, hook callback versus unregister, and
self-unload. Static audit must fail or explicitly mark BLOCKED while the old
patterns remain. No production change is justified until the target-specific
atomic/refcount/wait primitives and callback contexts are proven.

This section is a static audit/design addition only. No production source
code, device partition, or runtime state was modified.


## Follow-up: KPM ELF parser and AArch64 relocation bounds audit (2026-11-08)

The loader and relocation implementation in
`kernel/patch/module/module.c` and `kernel/patch/module/relo.c` were
reviewed as a separate input-validation boundary. This is a source audit;
no malformed module was executed.

### E1 — ELF section-string table index is dereferenced before validation (Critical)

`setup_load_info()` uses `e_shstrndx` to index `sechdrs[]` before checking
that the index is below `e_shnum`, is not a reserved index, and refers to a
valid string-table section. `find_sec()` then uses each `sh_name` as an
unbounded offset into that table and passes the result to `strcmp()`.
A malformed relocatable object can therefore make the parser read outside
the section-header array or string-table bounds.

Required validation: validate ELF extended/reserved index rules supported by
this loader, validate the selected section type and file range, require every
`sh_name` to be within `shstrtab.sh_size`, and require a NUL terminator
within the remaining string-table bytes before comparing names.

### E2 — Symbol-table link and symbol names are not bounds-checked (Critical)

The SHT_SYMTAB scan trusts `sh_link` when indexing `sechdrs[]` and trusts
the linked string table's offset/size. `simplify_symbols()` and
`layout_symtab()` use `st_name` with `strlen()` without proving it lies
inside the linked string table or reaches a NUL before its end. The relocation
path also indexes the symbol table using `ELF64_R_SYM(r_info)` without
checking the symbol index against the actual symbol count.

Required validation: verify `sh_link < e_shnum`, the linked section is the
expected string-table type, symbol-table size is an exact multiple of
`sizeof(Elf_Sym)`, every `st_name < strtab.sh_size`, every symbol name is
NUL-terminated within that bound, and every relocation symbol index is below
the symbol count.

### E3 — RELA writes are formed from untrusted offsets without target bounds (Critical)

`apply_relocate_add()` computes
`loc = target_section.sh_addr + r_offset` and writes 2/4/8 bytes or an
instruction there, but does not check that the target section index is valid,
that the target section is allocatable and has the expected type/permissions,
or that the relocation write width fits within
`target_section.sh_size - r_offset`. The relocation section's entry size and
exact divisibility are also not validated before iteration.

A malformed KPM can therefore direct relocation writes outside the intended
target section, potentially corrupting another module section or unrelated
memory adjacent to the allocation.

Required validation: validate REL/RELA section header links and entry sizes,
validate `sh_info` and `sh_link`, reject unsupported target sections, and
check each relocation's type-specific write width using overflow-safe
subtraction checks before forming `loc`. Validate instruction alignment for
instruction relocations.

### E4 — REL relocation sections are silently accepted but not applied (High)

`apply_relocations()` dispatches SHT_REL sections to `apply_relocate()`,
but the current AArch64 implementation in `relo.c` returns zero without
applying any entries. The loader consequently treats a REL section as
successfully processed even though its relocations remain unresolved. The
loader must either implement and validate the supported REL form or reject
SHT_REL with `-ENOEXEC`; returning success for a no-op is unsafe.

### E5 — Section file-range and layout arithmetic need overflow-safe checks (High)

`rewrite_section_headers()` checks
`sh_offset + sh_size` against input length using addition, which should be
rewritten as subtraction-based bounds checking after first validating
`sh_offset <= len`. The section layout path accumulates sizes into
`unsigned int` through `get_offset()` and `layout_sections()` without
checking alignment/addition overflow or enforcing a documented maximum
module allocation. Alignment values also need validation (power-of-two and
bounded) before use in `ALIGN`.

Required validation: use checked-add/checked-align helpers, reject overflow,
and impose a hard module image size cap before allocation.

### E6 — ELF header validation is incomplete for the fields subsequently used (High)

The current header check validates magic, ET_REL, AArch64 machine, section
header entry size, and a basic section-header range. It does not fully validate
`e_ehsize`, `e_shstrndx`, section-table alignment, section-name table,
symbol/string table relationships, or all section data ranges before later
dereferences. `e_shnum`/section-header range arithmetic should be kept in a
single overflow-safe validation routine.

### Required remediation order

1. Add a pure, allocation-free ELF preflight validator that checks all header,
   section, string-table, symbol-table, and relocation metadata before any
   pointer arithmetic or executable allocation.
2. Validate each relocation record completely before writing anything.
   Prefer a two-pass process: validate all records first, then apply them, so
   a late malformed record cannot leave a partially relocated image.
3. Reject SHT_REL until a real AArch64 REL implementation exists.
4. Add malformed-object fixtures for out-of-range `e_shstrndx`, `sh_name`,
   `sh_link`, `st_name`, relocation symbol index, `sh_info`,
   `r_offset`, mis-sized relocation sections, overflowed section ranges,
   oversized alignment, and oversized total allocation.
5. Run the parser/relocator harness under ASan/UBSan on a host build where
   feasible, then run the normal cross-build and static checks.

### Release decision

These parser/relocation findings are additional blockers. Do not load
third-party or malformed KPMs on the Y73S until preflight validation and
relocation bounds checks are implemented and tested. This pass changes only
this audit document; it does not modify production loader code, boot images,
or device state.


### E7 — 64-bit relocation mask uses an invalid shift expression (Critical)

In `relo.c:reloc_data()`, the mask is formed as
`u64 imm_mask = (1 << len) - 1;`. The literal `1` has type `int`, so
`len == 64` invokes undefined behavior (and the shift is invalid even before
the result is widened to `u64`). This path is reached by R_AARCH64_ABS64 and
R_AARCH64_PREL64. Use width-safe construction, with a dedicated 64-bit case
that does not shift by the type width, and add UBSan coverage for all supported
relocation widths.

### E8 — Invalid relocation section metadata is silently skipped (High)

`apply_relocations()` currently continues when `sh_info >= e_shnum`, and
also silently ignores relocation sections whose target section is not marked
SHF_ALLOC. A malformed relocation section should not be treated as if it did
not exist. First identify every SHT_REL/SHT_RELA section, validate its
`sh_info`, `sh_link`, target section, symbol table, entry size and size
divisibility, and reject malformed or unsupported records explicitly.

### E9 — Section size helper returns sh_entsize instead of sh_size (Medium)

`get_sh_size()` returns `infosec->sh_entsize`, while its name and caller
(`info->info.size = get_sh_size(info, ".kpm.info")`) indicate that the
section byte size is intended. The section's `sh_entsize` is an entry-size
field and is commonly zero for this metadata section. Return the validated
`sh_size` instead, or remove the unused field if no caller needs it. Add a
test that checks the reported .kpm.info byte length against the ELF section
header.

### E10 — Relocation helpers mutate instructions/data before overflow is reported (Medium)

The relocation helpers write the calculated value into the target before
performing their overflow check. The current module load path normally frees
the not-yet-published module after a relocation error, which limits exposure,
but this ordering makes the helpers non-transactional and fragile if reused.
Prefer calculate/validate first, then commit the write; ensure the caller never
publishes a partially relocated image.

These findings supplement E1-E6. They are source-level findings only; no
production loader or relocation code was changed in this audit pass.


## 7. Whole-branch high-risk implementation pass (2026-11-08)

The branch tree was re-inventoried after the original report. It now contains
379 tracked files, including first-party KPIMG/KPM code, host tools, CI and
scripts, plus a separate LKM/BTI subtree and vendored libraries. The pass
prioritized executable first-party code and input/lifetime boundaries; it is
not represented as a line-by-line security certification of every vendored
third-party file.

### Implemented source changes

- Device KPM loader (`kernel/patch/module/module.c`): ELF64/little-endian
  header validation, bounded section-name and symbol-name strings, section
  and symbol-table link checks, safe section layout arithmetic, NOBITS
  handling without file-pointer arithmetic, checked section copy extents,
  fail-closed REL handling, relocation section metadata checks, and fixes to
  module-list output bounds, module-info error unlock, and module file-size
  validation.
- AArch64 relocation (`kernel/patch/module/relo.c`): width-safe 64-bit mask
  construction, relocation symbol and target-section write bounds, alignment
  checks, REL rejection, and delayed instruction/data writes until overflow
  validation succeeds.
- Host KPM inspection (`tools/kpm.c`): ELF header/section/string range
  validation, bounded metadata string iteration, NOBITS handling, required
  metadata checks, and correct `.kpm.info` `sh_size` reporting.
- KStorage/SU paths (`kernel/patch/common/kstorage.c`,
  `kernel/patch/common/sucompat.c`): negative range rejection, serialized
  writer lookup/replacement, RCU-safe snapshots for user copies, stored
  profile-size validation, and bounded SELinux-context copying.
- Android userd (`kernel/patch/android/userd.c`): bounded exact file reads,
  trusted-manager index checks, directory-entry name bounds, and
  subtraction-based ZIP central-directory extent validation.
- Host image tools (`tools/bootimg.c`, `tools/patch.c`,
  `tools/common.c`, `tools/image.c`): input/read/allocation checks,
  decompression caps, checked repack extents and AVB offset movement,
  tail checksum bounds, checked output writes, no uninitialized AVB footer
  writes, bounded embedded preset/extra parsing, checked extra serialization,
  safe hex patch sizes/digits, and ARM64 branch range/alignment validation.
- Added fail-closed source contract checks and connected them to the GCC 14.2
  KPIMG and host-tools workflows:
  `verify_kpm_loader_contract.py`,
  `verify_bootimg_io_contract.py`,
  `verify_kptools_patch_bounds.py`, and
  `verify_userd_file_contract.py`; the runtime contract test now also covers
  KStorage and SU callback ordering.

### Current validation evidence

- GCC 14.2 KPIMG build plus stack-frame, memblock, runtime, relocation,
  fphook, KPM-loader, and userd source checks passed on commit
  `07750d150e3523082f47cdd0613d4ae0d6419a2f`.
- Host kptools build plus KPM, boot-image I/O, and embedded-preset checks
  passed on commit `8c95481cef97e290d7a40216c5a915cc10db82aa`.
- The latest audit-script-only commit is
  `a5866dc1e78fb599cfaeb2cd8dfd1942a6a1779c`; its two workflows were
  still running when this report was written. Earlier failed runs were
  inspected and the corresponding verifier/implementation issues were
  corrected; cancelled runs are not counted as passes.

### Remaining release blockers — explicitly not marked fixed

1. **KPM manager lifetime/concurrency remains critical.** The manager still
   lacks a proven per-module active-call reference protocol. The global
   `module_lock` is not consistently used for list publication/removal;
   plain list mutation mixed with RCU readers is not a valid RCU list
   protocol. `unload_module()` can still free module text while a callback
   already holds a function pointer. `module_control0()` still has the
   shared mutable `ctl_args` lifetime race. The current audit fixes do not
   make KPM load/unload safe under concurrency.
2. **Hook registration and callback lifetime remains critical.** Hook slot
   claim/lookup/retire and first-wrap ownership are not yet serialized, and
   callback code/data lifetime is not tied to module unload. The RCU wrapper
   symbol mapping alone is not a quiescence proof.
3. **Separate LKM subtree remains outside this Y73S KPIMG validation.**
   `lkm/kpm/module.c` and `lkm/kpm/relo.c` contain a second, older KPM
   loader implementation with the same classes of weak ELF/relocation
   validation, including a no-op REL path and unsafe 64-bit mask expression.
   The LKM subtree has not been brought to parity or validated by the Y73S
   workflows; do not treat it as production-ready.
4. **No malformed-input fuzz/ASan/UBSan campaign has run yet.** The new
   regression checks are source-contract checks, not dynamic proof that all
   malformed ELF, ZIP/APK, or boot-image inputs are rejected safely.
5. **AVB signing and actual device behavior remain unverified.** The host
   repacker preserves/checks footer metadata where possible; it cannot
   recreate vivo signing descriptors without the signing material. No image
   from this branch has been flashed or boot-tested.

### Release decision

The parser and host-tool hardening is materially improved and the recorded
builds above passed, but the branch is **not fully resolved or release-ready**
until the KPM manager and hook callback lifetime protocols are redesigned,
the separate LKM loader is either hardened or explicitly excluded from the
deliverable, and malformed-input dynamic tests are run. All work in this
pass was repository/CI work only; no Fastboot, 9008, partition write, or
device-side modification was performed.


## 8. Re-audit of the independent LKM KPM loader (2026-11-09)

The current branch HEAD was re-fetched from GitHub as
`f75a404e87ace1c6ddad71c666ac27fff609a88b`. The recursive Git tree
contains 448 entries (the previous 379-file inventory is stale). The LKM
loader is not covered by the Y73S KPIMG loader contract checks, and direct
inspection of `lkm/kpm/module.c`, `lkm/kpm/relo.c`, and
`lkm/kpm/module.h` confirms that it is materially behind the hardened
KPIMG implementation.

### L1 — LKM ELF header and section metadata are insufficiently validated (Critical)

`lkm/kpm/module.c:elf_header_check()` checks only a subset of ELF identity
fields and section-header bounds. It does not validate ELF class, data
encoding, ELF version, `e_ehsize`, `e_shstrndx` against `e_shnum`, or the
section-name string table type/range before `setup_load_info()` dereferences
the section headers and string table. `setup_load_info()` then trusts
`sh_name`, `sh_link`, symbol entry size, and symbol-name offsets. A malformed
KPM can therefore cause out-of-bounds reads before allocation.

### L2 — LKM section layout and copy lack overflow/range checks (Critical)

The LKM `get_offset()` uses `ALIGN(*size, sh_addralign)` and adds
`sh_size` without validating power-of-two alignment or overflow.
`layout_sections()` and `layout_symtab()` do not propagate checked errors.
`move_module()` copies each allocatable section to
`mod->start + sh_entsize` without verifying the destination extent. The
KPIMG-side checked layout must not be assumed to protect this independent
implementation.

### L3 — LKM symbol simplification trusts symbol indices and names (Critical)

`simplify_symbols()` forms `info->strtab + st_name` and indexes
`sechdrs[st_shndx]` without validating the symbol name offset/termination or
the section index. The LKM setup path also accepts a symbol table without
checking its `sh_link` target type, `sh_entsize`, or size divisibility.

### L4 — LKM relocation dispatch and RELA application are not bounded (Critical)

`apply_relocations()` silently skips a relocation section with an invalid
`sh_info`, does not validate `sh_link`, and dispatches SHT_REL to
`kp_apply_relocate()`, which currently returns success without applying
anything. `kp_apply_relocate_add()` directly indexes the target section and
symbol table, uses `r_offset` to form a write pointer without checking the
target extent, and does not validate relocation entry size/divisibility,
symbol index, or write width.

### L5 — LKM relocation mask still has undefined behavior (Critical)

`lkm/kpm/relo.c:reloc_data()` uses `(1 << len) - 1`; 64-bit ABS/PREL
relocations can shift a 32-bit signed integer by 64. This is undefined
behavior and was fixed only in the KPIMG-side relocation implementation.

### L6 — LKM module registry and unload lifetime remain unsafe (Critical)

The LKM path also uses ordinary `list_add_tail`/`list_del` while readers
such as `kp_kpm_cfi_allowed_addr()` traverse under RCU. The writer operations
are not an RCU list protocol. `kp_load_module()` performs duplicate lookup
before initialization and publishes later without a lock, allowing concurrent
duplicate loads. `kp_unload_module()` removes the module and invokes its exit
callback while inside an RCU read-side critical section, then frees executable
text before leaving that section. This does not protect callbacks already
holding function pointers and can deadlock if an exit callback waits for an
RCU grace period.

### L7 — LKM lifecycle implementation is duplicated, not shared (High)

The LKM loader has its own `kp_module` structure, relocation helpers,
registry, and callback dispatch. Fixes in `kernel/patch/module/module.c` or
`kernel/patch/module/relo.c` do not automatically apply to
`lkm/kpm/module.c` or `lkm/kpm/relo.c`. The two implementations need
either a shared validated parser/relocator abstraction or independent,
equivalent test coverage before both can be considered supported.

### Verification and release status

This section records source-confirmed blockers only. No LKM production source
was modified in this pass. The existing
`scripts/verify_kpm_loader_contract.py` reads the KPIMG-side files and
`tools/kpm.c`; it does not inspect `lkm/kpm/module.c` or
`lkm/kpm/relo.c`. Therefore its PASS output cannot be interpreted as an LKM
loader pass. The current LKM loader must remain explicitly unsupported for
untrusted KPM input until L1-L7 are fixed and independently tested.

The previous inventory count and older commit/run references in this report
are historical snapshots, not claims about the current HEAD. The current
branch ref and file-tree count above were re-fetched on 2026-11-09.


## 9. LKM AArch64 relocation hardening — partial implementation (2026-11-09)

Production source changes were made in `lkm/kpm/relo.c`:

- The 64-bit data-relocation mask now uses an explicit all-ones case and
  16/32-bit masks use `1ULL`, avoiding the prior 32-bit `1 << 64` UB.
- Invalid relocation widths now return `-EINVAL`.
- `kp_apply_relocate()` now returns `-EOPNOTSUPP` rather than falsely
  reporting success for unapplied AArch64 REL records.
- RELA handling validates section type, entry size/divisibility, target
  section index/link, allocatable target, symbol table shape, symbol index,
  relocation write width, target-section extent, and alignment before writes.
- The RELA path performs a first pass over records before applying them, so
  malformed bounds/symbol references are rejected before relocation writes.

Commits:
- `bac74da768c8728927d2de3685b254b93421eecc` — initial LKM RELA bounds work.
- `b628ab44415d16c2c654dbb0d45a60bbcac85f22` — invalid width handling correction.
- `293ecaecf8b28eb68911ef0e2503dbb4256a82c7` — explicit REL rejection.

### Important limitations

This is a partial fix, not a completed LKM loader hardening. The current
RELA validation still relies on the caller having validated the relocation
section's own in-memory address and the section-header array. The module
loader still has the ELF/header/string-table, section-layout, symbol
simplification, module-list concurrency, and unload lifetime defects L1-L3
and L6 described above. Relocation helper writes are not fully transactional
for arithmetic-overflow failures (the helper encodes before returning an
overflow error). The relocation source has not yet been compiled by an LKM
kernel-header build or exercised with ASan/UBSan/fuzz fixtures.

The Y73S KPIMG workflow path filter currently watches `kernel/**` and
`scripts/**`, not `lkm/**`; therefore a green KPIMG workflow would not
validate this LKM change. Do not count existing KPIMG/host-tools runs as
validation for these LKM edits. Keep the LKM loader unsupported for
untrusted KPM input until the remaining loader and lifecycle issues are
fixed and a dedicated LKM build/test job passes.


## 10. LKM loader hardening follow-up (2026-11-09)

Additional production changes in `lkm/kpm/module.c`:

- Reject null/empty in-memory images and invalid/oversized path-loaded files
  before converting lengths or allocating buffers.
- Require `.kpm.init` and `.kpm.exit` to be non-empty executable sections.
- Require `.kpm.info` to be a non-empty `SHT_PROGBITS` section with a
  terminating NUL; bound metadata tag matching.
- Avoid constructing file-backed pointers for `SHT_NOBITS` sections.
- Remove redundant unchecked section-header/string-table pointer setup;
  use the section table range-checked by `elf_header_check()`.
- Replace the single shared kallsyms callback trampoline with per-call
  16-byte slots allocated under the short manager spinlock. Concurrent
  iterators no longer overwrite the same trampoline slot.
- Check AArch64 `B imm26` alignment and signed +/-128 MiB reach before
  encoding the direct branch; out-of-range callbacks fail with `-ERANGE`
  instead of receiving a truncated branch.

A dedicated source contract verifier now also checks image-length validation,
per-call trampoline slot acquisition/release, and branch reach. The verifier
is wired into `.github/workflows/build-y73s-kptools-host.yml` and that
workflow now watches `lkm/**`.

Latest verified workflow:
- Run `42503399769`, head `00104bf1f00fff39a09b8deac1bafd88b2db7c40`,
  conclusion `success`.
- The `Audit LKM KPM ELF loader source` job passed with the image-size and
  per-call trampoline regression checks.
- The Linux host kptools build/package job passed.

This is source-level regression coverage only; no LKM kernel module build
against a real target KDIR has been run.

### Remaining high-severity blockers

- Module registry writers/readers still use ordinary list operations with
  RCU read-side sections but no RCU-safe writer protocol or consistent lock.
- Concurrent duplicate loads and module unload versus control/event callbacks
  still lack active references and a quiescence protocol.
- `kp_loading_mod` publication and CFI-range inspection still have a
  lifetime race if a load fails/frees while another CPU inspects it.
- The per-call trampoline slots fix slot overwrite, but do not fix the
  module-registry lifetime issues above.
- RELA arithmetic-overflow helpers still need a complete no-partial-write
  guarantee, and no target KDIR compile/fuzz/UBSan validation has been done.

Do not treat this branch as safe for arbitrary or untrusted KPMs yet.

## 11. LKM KPM registry lifecycle and callback-reference hardening (2026-11-09)

The independent LKM KPM manager was updated after re-reading the current
lkm/kpm/module.c and lkm/kpm/module.h. The changes replace the previous
mixed ordinary-list/RCU-reader approach with one registry-lock protocol and
explicit module states.

### Implemented changes

- Added LOADING, LIVE, UNLOADING, EXITING, and DEAD states plus an
  active_calls counter protected by module_lock.
- Added locked name lookup and kp_module_get() / kp_module_put() helpers.
  Only LIVE modules can be acquired for normal control callbacks.
- A load reserves its module name in the registry as LOADING before calling
  init. A concurrent load of the same name now fails under the same lock.
  The entry becomes LIVE only after init succeeds.
- A failed-init exit callback runs while the image remains registered as
  EXITING; the entry is removed only after that callback returns.
- Unload atomically changes LIVE to UNLOADING, preventing new normal
  callback references. If active calls remain, it returns -EBUSY without
  waiting or freeing the image. The caller must retry after active calls drain.
  Once quiescent, it changes to EXITING, runs exit outside the spinlock while
  retaining the CFI-visible image range, then unlinks and frees the module.
- ctl0 now uses a call-local immutable argument copy; the old shared
  mod->ctl_args buffer was removed.
- ctl0 and ctl1 callbacks acquire/release module references.
- Event fanout takes a dynamically allocated snapshot and increments each
  target's active reference under the registry lock; callbacks run outside the
  lock and release their references afterward.
- Module count/list/info readers now use the registry lock or a module
  reference. The missing not-found unlock path in module-info lookup is gone.
- The kallsyms callback wrapper pins the callback's owning KPM for the complete
  iteration. The CFI address predicate now traverses the registry under the
  same lock; ordinary list writers are no longer paired with RCU read-side
  traversal in this LKM manager.
- The callback owner lookup permits nested kallsyms calls from a module already
  in UNLOADING only while that module remains registered due to active calls.
  EXITING remains visible to the CFI range predicate for the synchronous exit
  path, but the safe kallsyms wrapper refuses to acquire a new callback
  reference in EXITING and fails closed with -EBUSY.

### Source/CI evidence

Lifecycle contracts were added to
scripts/verify_lkm_kpm_loader_contract.py, including checks for state
definitions, name reservation, active reference acquisition/release,
retryable unload, event snapshots, call-local control arguments, CFI callback
owner pinning, and removal of the old RCU registry reader pattern.

Latest verified LKM/host workflow:
- Run 42504673787
- Head 33b432d34841fd7c282375292f8c9e1946e46ee5
- Conclusion: success
- Audit LKM KPM ELF loader source: success
- build-kptools host build/package: success

The separate Y73S KPIMG GCC workflow also completed successfully on the
same source-contract commit (run 42504673911, same head SHA). This validates
the KPIMG build/audit path, not compilation of the independent LKM module.

This workflow validates the source-contract script and host kptools build.
It does not compile lkm/kpm/module.c against the target kernel headers.

### Remaining lifecycle and release limitations

1. Unload is deliberately retry-based rather than waitqueue-based: a call
   returning -EBUSY leaves the module UNLOADING; the caller must retry.
   No automatic completion notification is provided.
2. The active-reference protocol covers the LKM manager's control callbacks,
   event fanout, and safe kallsyms iteration. It does not yet prove ownership
   for every Hook callback, arbitrary KPM-created worker/thread, timer,
   deferred work item, or function pointer retained by an external subsystem.
   Those paths must be tied to module references or explicitly unregistered
   and quiesced before unload.
3. kp_kpm_cfi_allowed_addr() is a range predicate, not a general-purpose
   reference acquisition API. The safe kallsyms wrapper separately pins its
   owner, but unrelated consumers that only call the predicate still need
   their own lifetime guarantee.
4. The separate LKM ELF/RELA loader still needs a target-KDIR compile,
   malformed-object fixtures, ASan/UBSan or equivalent dynamic validation,
   and a complete no-partial-write relocation guarantee.
5. No device boot, APatch initialization, root, Fastboot, 9008, or partition
   write test was performed. The branch is not certified for loading arbitrary
   or untrusted KPMs.

This pass is a meaningful registry/callback-lifetime improvement, not a
release sign-off.

## 12. LKM hook-runtime registry and retirement follow-up (2026-11-09)

A further audit of the shared hook engine and its LKM backend found that
kernel/base/hook.c calls hook_mem_retire(), but lkm/hook/hook_runtime.c did
not define that backend symbol. The LKM Kbuild includes hook_runtime.o and
hook_engine.o, but does not include kernel/base/hmem.c; the KPIMG-side
implementation therefore could not satisfy the LKM link. The LKM backend now
defines hook_mem_retire().

### Implemented changes

- LKM hook_mem_retire() removes the lookup metadata but deliberately retains
  the executable trampoline/chain region. This matches the existing KPIMG
  retirement policy: successful text restoration does not prove that every
  CPU which entered the old trampoline has returned, so retired code storage
  is not immediately recycled.
- Added hook_mem_publish() to both the LKM runtime and KPIMG hmem backend.
  New allocations remain unpublished until the patch is installed and the
  first callback slot is ready. Typed lookup ignores unpublished entries.
- The KPIMG allocator uses a distinct constructing state (using=3), publishes
  as live (using=1), and continues to reserve retired entries (using=2).
- The LKM allocator rechecks origin uniqueness under its registry mutex before
  inserting a new record. This closes the duplicate first-allocation race
  where two callers both miss an earlier lookup.
- Added hook_get_mem_from_origin_type() to both backends and changed inline,
  inline-chain, and function-pointer-chain call sites to request the expected
  allocation type. This prevents a same-origin lookup from returning a
  different chain layout and being cast to the wrong structure.
- Direct inline hooks and both chain variants publish only after successful
  patch setup. The generic origin lookup remains available for the branch
  resolver's trampoline detection.

### Validation evidence

The new scripts/verify_lkm_hook_runtime_contract.py checks the LKM retirement
backend, duplicate-origin serialization, type-safe lookup, publication order,
and matching KPIMG allocator semantics. It is included in both the LKM source
audit workflow and the KPIMG build workflow.

Latest source commit tested:
- Head 2b68fa80863d0b2900690f2f72c37d093e2a504c
- LKM/host workflow run 42505764381: success
  - LKM loader and hook-runtime source contracts: success
  - host kptools build/package: success
- KPIMG GCC workflow run 42505764343: success
  - Arm GNU GCC 14.2 KPIMG build and audit: success

The KPIMG build validates the shared kernel/base hook and hmem changes. It
does not compile the independent LKM runtime objects against a target KDIR.

### Updated hook-lifetime status

The later hardening recorded in section 13 resolves the chain-slot races listed
above for the shared KPIMG/LKM hook engine: transit readers are counted before
callback tuples are consumed; removal marks slots RETIRED under the engine
lock; slot metadata and persistent owner references are reaped only after
active readers drain; and each KPM callback receives a transient active-call
reference for its invocation. Direct hook APIs reject callbacks that belong to
a KPM image rather than silently registering an unpinned callback.

The following limitations remain:
1. LKM retired executable trampoline/chain regions are intentionally leaked.
   This avoids premature reuse but needs a proven cross-CPU quiescence scheme
   before memory can be reclaimed.
2. KPM-created workers, timers, delayed work, and external callback registries
   must explicitly use the public kp_kpm_owner_pin/unpin and call_get/call_put
   API or otherwise unregister and quiesce before unload. The manager cannot
   automatically discover arbitrary external function pointers.
3. kp_kpm_cfi_allowed_addr() remains a range predicate, not a reference API.
   Consumers that use it to authorize an indirect call must separately hold
   an owner reference across that call.
4. Target-KDIR compilation of the LKM objects and runtime concurrency stress
   testing are still required.

This is a substantial callback-lifetime improvement, but not a complete
release sign-off.

## 13. Full follow-up audit: ELF symbol policy, branch arithmetic, and CI repair (2026-11-09)

A follow-up pass after the earlier CI failures found and fixed several
independent issues rather than merely adjusting the failing checks.

### Production fixes

- Both KPM loaders now reject every SHN_COMMON symbol. Neither loader has a
  common-symbol allocator, so retaining SHN_COMMON and treating st_value as a
  runtime address could turn its alignment value into an invalid relocation
  target. KPMs must be built with -fno-common.
- The LKM loader now rejects any SHF_ALLOC section that did not receive a
  checked image offset during layout, before allocating/copying the image.
  Previously move_module() would reject the sentinel offset later; this moves
  the failure earlier and makes the layout invariant explicit.
- The shared AArch64 B-range predicate now compares unsigned forward/backward
  distances directly. This removes a uint64_t-to-int64_t conversion followed
  by negation, which could overflow for large address differences. The
  accepted range remains [-128 MiB, +128 MiB-4], with 4-byte alignment.
- KPIMG hook-arena initialization now uses subtraction-safe loop bounds rather
  than testing i + sizeof(u64) <= end, avoiding unsigned wraparound near the
  top of the address space.
- The freestanding KPIMG build lacked UINT_MAX in its minimal headers. Added
  a local UINT_MAX fallback in both KPIMG and LKM module managers, fixed
  owner-reference null-guard formatting, and removed an unused relocation
  type variable by switching on the already-decoded type.

### CI and verifier repairs

- Updated the LKM hook permission contract to inspect the shared PTE updater
  (kp_hook_update_exec), not the thin kp_hook_make_exec wrapper.
- Updated the KPIMG retired-slot contract to match the explicit claimed-retire
  state (using=4) and permanent retired state (using=2).
- Updated the runtime branch-range contract for the new unsigned comparisons.
- Added regression checks for SHN_COMMON rejection, unplaced alloc sections,
  unsigned A64 branch bounds, and hook-arena initialization bounds.

### Latest verified evidence

Both workflows below ran against the same source-code HEAD:
- Source HEAD: 81831f30c9e274e5362cd37c5a9efbffc036b2e0
- The audit document was updated after these successful source-code runs;
  that documentation-only update did not change production source, verifier,
  or workflow files.
- LKM source audit + host kptools build: run 42622781803, success
- Arm GNU GCC 14.2 Y73S KPIMG build + full audit suite: run 42622781699, success

The KPIMG workflow compiles the KPIMG image and runs its ELF, map/relocation,
memblock, runtime, function-pointer hook, hook-runtime, KPM loader/lifecycle,
and userd contracts. The host workflow compiles/packages host kptools and runs
the LKM source contracts plus host KPM/bootimg/patch-bound checks.

Neither workflow compiles lkm/kpm/*.c or lkm/hook/*.c against the exact target
Android kernel KDIR. Static source contracts do not substitute for that build
or runtime testing.

### Remaining release blockers

1. The independent LKM module and hook backend still need a build against the
   exact target kernel headers/configuration. No matching target KDIR is
   currently configured in this repository workflow.
2. No malformed-ELF corpus, fuzzing, KASAN/UBSAN, lockdep, or concurrency stress
   tests have been run against a live kernel.
3. LKM retired trampoline/chain executable pages are intentionally retained
   after unhook. They are not recycled, so this is a bounded-by-hook-history
   memory leak until a rigorously proven quiescence/reclamation mechanism is
   implemented.
4. Arbitrary KPM worker threads, timers, delayed work, and third-party callback
   registries must opt into the exported owner pin/call reference API. The
   loader cannot guarantee lifetime for pointers that external code retains
   without registration.
5. No device boot, APatch initialization, root validation, Fastboot, 9008, or
   partition-write test has been performed. No device-side operation was run.

The current source and KPIMG CI state is green, but the repository is not yet
certified for device use or for loading untrusted KPMs.

## 14. LKM user-string and execve redirection hardening (2026-11-09)

A further review of the LKM supercall boundary found that several
strncpy_from_user() callers treated a full-size return as a valid C string.
When the user buffer had no NUL within the destination size, subsequent
strcmp(), logging, or path handling could read beyond the local buffer.

### Production changes

- Added a shared bounded-copy helper in lkm/kpm/kpm.c. It rejects null
  pointers, propagates copy faults, rejects strings without an in-range NUL
  with -ENAMETOOLONG, and explicitly terminates accepted strings.
- KPM load path, optional load arguments, control module name/arguments,
  unload name, and info name now use that helper. Invalid optional argument
  pointers no longer silently become absent arguments.
- The KPM list/info output handlers now reject null output pointers and
  invalid lengths before copying to userspace.
- Both the LKM and KPIMG KPM control handlers reject negative output lengths
  and nonzero output lengths paired with a null output pointer.
- The feature-control name parser now rejects overlong names and explicitly
  terminates accepted names.
- lkm/supercall/sucompat_hook.c now applies the same bounded-copy rule to
  execve filenames and SUPERCMD argv/-Z context strings. An overlong execve
  filename is passed through to the original syscall rather than compared as
  an unterminated stack buffer.
- Removed shared static scratch buffers for per-exec SELinux contexts; the
  context is now stored in the current execve handler's stack frame.
- execve redirection no longer overwrites the caller's original filename
  buffer. It stages the replacement path in fresh user stack space and
  updates pt_regs->regs[0]. APD argv[0] staging is kept separate, and stack
  pointer subtraction is checked before each allocation.

### Regression coverage and CI

scripts/verify_lkm_supercall_input_contract.py checks bounded copies, all KPM
string entry points, execve and SUPERCMD input handling, local context buffers,
and stack-based filename redirection. It runs in the LKM source-audit job.

Validated source HEAD:
- 3cffd04f2e7c899e6d811b8af0a6db17ec4e42f2
- Host/LKM source-audit workflow run 42625593449: success
  - LKM KPM ELF/relocation contracts: success
  - LKM Hook runtime contracts: success
  - KPM lifecycle contracts: success
  - LKM supercall input contracts: success
  - host kptools build/package: success

The matching KPIMG workflow run 42625593407 also completed successfully:
Arm GNU GCC 14.2 KPIMG build and audit suite: success. This is a separate
KPIMG build and does not compile the LKM objects against the Y73s target KDIR.

### Remaining limitations

- These are source-contract and host-tool checks; they do not compile the LKM
  against the target Android 10 / Linux 4.14.141 KDIR.
- The execve stack-staging change still needs a target-kernel compile and
  runtime validation of syscall ABI, user stack behavior, APD argument
  preservation, and failure paths.
- No device-side test or write was performed.


## 9. LKM relocation metadata follow-up (2026-11-09)

A fresh source review of the selected branch found a concrete interaction
between the LKM layout and relocation phases:

- `layout_symtab()` intentionally repurposes the symbol section's
  `sh_entsize` field to store its in-image destination offset.
- `kp_apply_relocate_add()` then incorrectly re-validated that rewritten
  field as though it were still the original ELF symbol entry size.
- This rejects otherwise valid KPM relocation tables after the symbol table
  has been moved into the allocated image.

The original ELF `sh_entsize` remains validated in `setup_load_info()`
before layout. The relocation helper now relies on that earlier validation
and continues to check the symbol table type, size divisibility, and address.
This preserves the loader's private offset convention without confusing it
with ELF metadata.

Changes committed on `y73s-cred-layout-guards-20261108`:

- `d0da55a`: add independent LKM KPM loader source-contract verifier.
- `7f265c3`: run the verifier in CI and include the selected branch in
  push triggers.
- `4bd615b`: fix the post-layout symbol-table `sh_entsize` conflict.
- `0bd24a3`: add a regression assertion for the metadata contract.
- `198e52f`: correct verifier regex escaping.

Verification status: the source changes and workflow configuration were
re-fetched from the branch after commits. The branch files were re-fetched after the changes and the ten source-contract
assertion groups were independently evaluated against the current LKM source;
all 10/10 passed. This reproduces the verifier's source assertions but is not
a Python process execution or a compiler/runtime test. The GitHub combined-status
endpoint returned no status checks for the latest commit at review time, and the
workflow-run query returned no PR-triggered runs. Therefore the new verifier
has not yet been reported as executed by CI; no compile or device test is
claimed. The branch remains unsuitable for untrusted KPM/device validation
until CI and runtime tests pass.
