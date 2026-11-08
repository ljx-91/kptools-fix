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
