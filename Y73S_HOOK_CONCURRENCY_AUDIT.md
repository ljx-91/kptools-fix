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
