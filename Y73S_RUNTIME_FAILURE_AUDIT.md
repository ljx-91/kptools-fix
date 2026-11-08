# Y73S runtime-failure path audit (read-only)

Branch: `y73s-gcc-audit-20261108`

This note records source-level risks found while reviewing the branch. It does **not** claim a confirmed bootloop root cause and does not change runtime code.

## Confirmed source-level gaps

### 1. Allocation result is used without validation

In `kernel/base/map.c`, `_paging_init()` obtains:

```c
uint64_t start_pa = map_phys_alloc(data, all_size, page_size);
```

The return value is then passed to `memblock_mark_nomap` (when present), used to construct `start_va`, and used for page mapping/copying. There is no immediate check that `start_pa` is nonzero or page-aligned, nor that the requested range is valid and does not overflow.

`map_phys_alloc()` itself returns 0 when the detected allocator type is not one of its supported cases. That makes the unchecked use particularly important.

### 2. Intermediate page-table allocation is unchecked

In `get_or_create_pte()`, an invalid non-leaf entry triggers `map_phys_alloc(data, page_size, page_size)`. The code immediately builds a table descriptor and clears the returned address. A zero result is not propagated as an error. The function also returns an entry pointer without a failure status, and its callers dereference that pointer.

This is a separate failure path from the main `start_pa` allocation.

### 3. The memory-probe path has a hard trap

In `mem_proc()`, absence of `memblock_virt_alloc_relo` reaches `__builtin_trap()`. This is fail-stop behavior, not a recoverable fallback. Before relying on this path, the Y73S report must establish that the symbol is found and that the function-pointer ABI and returned physical/virtual pair are valid on this exact kernel.

## Stack-frame verifier scope

`scripts/verify_kpimg_stack_frame.py` checks a hard-coded `_paging_init` prologue pattern, a hard-coded restore sequence, and the immediate used by `add sp, x10, #imm`. It fails closed when the patterns are absent or ambiguous, which is good.

However, the verifier does not identify the restore sequence by ELF symbol/range and does not independently validate the compiler-generated prologue of `start()` (which is relied on by the inline assembly using `x29`). The next audit should use the ELF symbol table and disassembly to verify both function boundaries and the relevant frame-chain assumptions.

## Target-specific relevance

For the reported Y73S Linux 4.14.141 kernel, `new_era = kmajor > 5` is false, so the newer-kernel scratch mapping branch is not selected. That does not eliminate the allocation and page-table failure paths above.

## Required evidence before any runtime change

1. Obtain the exact Y73S preset/log showing which allocator symbols and types were selected.
2. Disassemble the exact GCC-built `kpimg.elf`; verify `_paging_init` and `start` by symbol boundaries, not byte-pattern search alone.
3. Trace the 4.14.141 `memblock_alloc_try_nid`, `memblock_virt_alloc_try_nid`, `memblock_mark_nomap`, and `memblock_free` implementations and call conventions from the original kernel.
4. Define a safe abort/rollback path before adding null checks. Returning from the hook after partially reserving or changing page tables is not automatically safe.
5. Keep generated images out of flashing until a complete static audit and a recoverable test plan are in place.

## Status

- Source audit: findings recorded.
- Runtime source changes: none in this audit note.
- GCC CI execution: not verified from this review.
- Device boot: not verified.

A passing build or byte-pattern check is not proof that the Y73S device will boot.


## Follow-up on hardening branch (2026-11-08)

The isolated branch `y73s-runtime-contract-hardening-20261108` adds source regression gates and updates the current status. The following previously recorded source gaps are guarded in the current branch source:

- `_paging_init()` rejects a zero, unaligned, or overflowing main destination PA before `memblock_mark_nomap()`.
- `get_or_create_pte()` traps when an intermediate page-table allocation returns zero before writing a table descriptor.
- The Y73S linear-map probe is checked to run only after the original `paging_init()` returns, and checks the exact-page probe and release result.
- The known-bad `memblock_alloc_try_nid` virtual-return fallback is rejected by the resolver and by the new source regression verifier.

The new CI verifier is `scripts/verify_y73s_runtime_contract.py`. It is a source-level regression check, not a replacement for disassembling the target kernel and validating the ABI independently.

### Verified CI result

- Workflow run: https://github.com/ljx-91/kptools-fix/actions/runs/42474139101
- Commit: `01b8b028d3eb258bfc340a75868945220a01e1ed`
- Arm GNU Toolchain 14.2.rel1 build: passed
- ELF stack-frame verifier: passed
- Existing memblock source contract verifier: passed
- New runtime contract verifier: passed
- KPIMG map-relocation verifier: passed
- Artifact: `y73s-kpimg-arm-gnu-gcc14-audit`
- Artifact SHA-256: `8a9a18167fce3b7bb40d76eeaeb11dacbf86e71a2dd4bd626c6ceb0732ad8742`

This validates the CI build and the listed static checks only. It does not establish device boot, APatch initialization, AVB validity, or root availability. No device-side test or partition write was performed.


## Hotpatch / hook lifecycle audit (2026-11-08)

### Confirmed defect in the previous implementation

The previous `hotpatch_cb()` used `num_online_cpus()` both to elect the patching CPU and to make the other CPUs wait. The Y73S KALLSYMS audit found no `cpu_online_mask`, `__cpu_online_mask`, or `nr_cpu_ids`. In this repository's `cpumask.h`, `cpu_online_mask` resolves to one of those optional symbols and `num_online_cpus()` immediately passes that pointer to `cpumask_weight()`. The fallback in `hotpatch()` was entered precisely when those symbols were unavailable, but it still called this callback. This was a real source-level inconsistency and a potential null-mask dereference, not merely a style issue.

The prior GCC ELF disassembly also showed the callback calling `__bitmap_weight` and loading the online-mask state. That confirms the problematic dependency survived compilation.

### Changes in the hardening branch

- Removed the per-CPU counter / `num_online_cpus()` callback protocol.
- The callback now preflights every target address and snapshots original instructions before changing any text.
- It applies the patch on the single callback execution coordinated by `stop_machine(hotpatch_cb, &patch, NULL)`; the callback does not need KP-resolved CPU-mask symbols.
- If a later write fails, the callback attempts reverse-order rollback. A rollback failure returns `-EUCLEAN`.
- Missing `stop_machine` or an unsafe interrupt context returns `-EOPNOTSUPP`; the old uncoordinated direct callback fallback is removed.
- `hook_install()` and `hook_uninstall()` now return patch status. `hook()` checks installation failure, clears the backup pointer on ordinary failure, and retains trampoline storage if rollback is uncertain. `unhook()` likewise retains storage if restoring the original text fails.
- The source verifier now rejects reintroduction of the CPU-mask dependency and checks error propagation.

### Early-boot stop_machine consideration

Linux v4.14 has an explicit pre-initialization path in `stop_machine_cpuslocked()`: before the stopper threads are initialized, it warns if the online CPU count is not one, disables local interrupts, and executes the callback directly. This is important because the initial `rest_init` hook is installed before normal initcalls. The kernel's own `stop_machine` implementation handles that early state; KP no longer needs to resolve the missing CPU-mask globals itself. The target kernel's exact implementation and runtime state still need confirmation against the supplied vendor image.

### CI and binary evidence

- Workflow: https://github.com/ljx-91/kptools-fix/actions/runs/42474757991
- Commit: `55bbd5fbe02ea41276746a06295e51ae9f0cfc47`
- GCC 14.2 build: passed
- ELF stack-frame, memblock, runtime-contract, and map-relocation checks: passed
- New hotpatch and hook lifecycle checks: passed
- KPIMG binary SHA-256: `f70d78c22f04d7a8e6c26ace7bab53f2e6466a1603eadfa1bb0a10856182b61a`
- KPIMG ELF SHA-256: `7b373a9901b3f62dfbcb576b226ed4f11b124df07e8938063af422313d3bd3cf`
- Artifact ZIP SHA-256: `418d0a163440e2e0393e9eeb23ef1d615c8c8cd4f5215dccbaa68a4ce6debae1`

These checks establish that the changed source compiles and the listed static checks pass. They do not establish that the vendor kernel's `stop_machine` implementation, early-boot CPU state, CFI behavior, AVB chain, or actual device boot is correct. No device-side test or partition write was performed.


### Follow-up: explicit early-boot IRQ window

The first fail-closed implementation still rejected the initial hook if DAIF showed IRQ/FIQ masked. That is incompatible with the initial KP entry point, which runs during early `setup_arch()/paging_init()`, before `start_kernel()` reaches its later `local_irq_enable()`.

The branch now exposes `hotpatch_set_early_boot()`. `patch()` enables this narrowly scoped mode before installing the first boot hooks; `before_rest_init()` clears it on every exit, and error/no-hook paths clear it in `patch()`. While this flag is set, `hotpatch()` may call the kernel's own `stop_machine()` despite masked IRQ/FIQ. Linux v4.14's `stop_machine_cpuslocked()` has a pre-initialization path that checks the single-online-CPU condition and runs the callback locally with IRQs saved/disabled; once initialized, normal stop-machine coordination is used. The KP callback itself still never dereferences unresolved CPU-mask symbols.

This early-mode lifecycle is now part of `verify_y73s_runtime_contract.py`. The exact vendor v4.14.141 implementation and the device's actual call context must still be checked against the original Y73S kernel image; the upstream v4.14 reference is not a substitute for that binary evidence.
