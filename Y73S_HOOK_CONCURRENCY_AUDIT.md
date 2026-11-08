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
