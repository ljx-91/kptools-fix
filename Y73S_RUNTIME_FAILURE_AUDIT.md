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


### Final early-boot build verification

After adding the missing public declarations for `hotpatch()` and `hotpatch_set_early_boot()`, the source commit `6cbb6b7f0b122056deedb1d3bbef49e3ce62fb31` passed the full GCC 14.2 workflow:

- Workflow: https://github.com/ljx-91/kptools-fix/actions/runs/42475073570
- All six static checks passed, including the new early-boot window check.
- KPIMG SHA-256: `d1ea5a0c7b13df2d30369d4111bd62515c44e3a0ca3f134d11665887285dcaed`
- ELF SHA-256: `90fd5357adee35d53e35fe77f49a819edc652005f75c036851bc9b648db3ade5`
- Artifact ZIP SHA-256: `dee21b99c536d0244a97993d6fac4396542fd909f6f190d8abd76094555b26c4`
- Artifact ID: `13615117233`

The generated ELF disassembly confirms that `hotpatch_cb` calls the page-table preflight and `hotpatch_nosync`, and contains no call to `num_online_cpus()` / `__bitmap_weight()`. The `hotpatch()` disassembly passes a NULL third argument to the resolved `stop_machine` function and gates IRQ-masked execution on the explicit early-boot flag.

Reference source for the upstream early-stop path: https://github.com/torvalds/linux/blob/v4.14/kernel/stop_machine.c. Vendor-kernel equivalence is not yet proven.


## ARM64 inline-hook relocation audit (2026-11-08)

### Confirmed source-level buffer bound defect

`hook_t.relo_insts` was sized to 36 32-bit words, while the relocation handlers can emit up to 8 words for one overwritten instruction (`relo_b` for conditional branches / `relo_ldr` for SIMD literal loads). The trampoline can overwrite 4 instructions normally or 5 when a PACIASP/PACIBSP prologue is preserved with a BTI landing instruction. The conservative upper bound for the declared six-instruction limit is therefore `TRAMPOLINE_MAX_NUM * 8 + 4` words (six slots plus the maximum absolute jump-back). The old 36-word array did not establish that bound and could be overrun by a valid instruction mix. The header now uses the conservative 52-word bound.

### Confirmed A64 B-range boundary defect

The old `can_b_rel()` used a symmetric absolute-distance check of `<= 0x08000000`. AArch64 `B` has a signed imm26 scaled by four, so the actual byte range is [-0x08000000, +0x07fffffc]. The previous test could accept the positive +128 MiB endpoint, which is not representable, and did not explicitly reject unaligned addresses. The new implementation checks four-byte alignment and the asymmetric signed range before encoding.

### Regression checks and validation status

The source verifier now checks the relocation buffer expression, both alignment guards, and the exact positive/negative range endpoints. Workflow for the new source commit: https://github.com/ljx-91/kptools-fix/actions/runs/42475461806

The prior compiled artifact's disassembly was inspected with LLVM objdump; it predates these latest two source changes and therefore is not evidence for the newly corrected code. Wait for the current workflow to complete before treating the new KPIMG as a verified build. No target device execution has been performed.


### Hook relocation hardening build result

The updated source commit `45138be7b961cc15fadc2f7172b9a7a1b3f278bf` passed GCC 14.2 CI:

- Workflow: https://github.com/ljx-91/kptools-fix/actions/runs/42475461806
- New relocation-buffer and A64 branch-boundary regression check: passed.
- KPIMG SHA-256: `50054d4ee21bacc0313ff5e586a44ae1627e59a235e17bd994064179636b6eba`
- ELF SHA-256: `369c0cf4229b0200bcfe251d5ab43e867679aaf4c1643761e11e396bfa966509`
- Artifact ZIP SHA-256: `4a97729c666d5bc80f0fffa5fe6f5add8711e703c6a42cb840f1a5e6d785b2a3`
- Artifact ID: `13615750289`

The downloaded ELF was disassembled locally with LLVM objdump. `hook_prepare` initializes the relocation buffer through offset `0x128` from offset `0x58`, which is 52 32-bit words, matching the new array size. The emitted `branch_relative` checks alignment and uses the distinct positive limit `0x07fffffc` and negative limit `0x08000000`. This is binary confirmation of the two source changes.

The ZIP still stores files at its root while `SHA256SUMS.txt` names them with a `dist-y73s/` prefix; therefore `sha256sum -c SHA256SUMS.txt` fails if run from the extracted root. Each file's SHA-256 was independently calculated and matches the manifest. Fix the artifact directory layout in a separate workflow cleanup.


## ARM64 entry-thunk resolver hardening (2026-11-08)

The prior `branch_func_addr()` followed unconditional A64 `B` entry branches in an unbounded loop. A self-branch or cyclic thunk chain could therefore hang the KP hook setup path indefinitely. It also did not validate each resolved target before the next instruction fetch.

The resolver now:
- rejects invalid or non-4-byte-aligned starting addresses;
- records up to eight visited entry addresses and rejects cycles;
- validates every next target before dereferencing it;
- rejects chains longer than eight hops with a zero result;
- makes `hook()`, `hook_wrap()`, and `hook_unwrap_remove()` reject an invalid resolved origin rather than proceeding with origin zero.

The first CI attempt caught that the `hook_wrap()` / `hook_unwrap_remove()` callers still checked the original function pointer after resolution. That check was corrected to validate `origin`; the subsequent run passed.

### Build and ELF confirmation

- CI: https://github.com/ljx-91/kptools-fix/actions/runs/42475912679
- Source commit: `29841d24c65d4126a5fa956a624a1e687aa01343`
- GCC 14.2 build and all source/static checks: passed
- KPIMG SHA-256: `b7ceed6f78ff6f44a7326618cdf87affabce6dc5c1b5a561cce4d330b36d7252`
- Artifact ZIP SHA-256: `3e2cb32bc532ab21a553db6667c6920ac2159f7c48fe4fcd4f500d103bcd9fef`
- Artifact ID: `13615726175`

The downloaded ELF disassembly of `branch_func_addr` shows the eight-entry stack tracking array, the hop-count comparison against eight, the alignment check, and the zero-return failure path. This verifies code generation for the resolver change, not the vendor kernel's memory validity rules or runtime behavior.

### CFI scope clarification

The built KPIMG ELF contains symbols named `bypass_kcfi`, `replace_report_cfi_failure`, and `replace__cfi_slowpath`, but the current repository source tree does not expose their matching implementation as a CFI source file. Their ELF disassembly shows address-range filtering and tail-branching to saved original callbacks for addresses outside KP-owned ranges. The exact callback prototypes, vendor CFI implementation, and call-site ABI cannot be proven from these KP symbols alone. Treat CFI bypass as **unverified**, not as a completed compatibility result. The original Y73S vendor kernel image and its matching symbol/prototype context are required for a sound ABI audit.


**Checksum label correction:** the workflow's `SHA256:` line is the ELF hash, not the raw KPIMG hash. For artifact `13615726175`, the raw `kpimg-android` SHA-256 is `28ed397a9e9bdb4489bbfbdd50333097baf68f6a2ce4517608c80a4f288d2863`; the ELF SHA-256 is `b7ceed6f78ff6f44a7326618cdf87affabce6dc5c1b5a561cce4d330b36d7252`. Both match the artifact's `SHA256SUMS.txt` entries when compared by filename.


## Hook-chain failure propagation and ADR relocation guard (2026-11-08)

A follow-up call-chain review found that the inline helpers `hook_chain_install()` and `hook_chain_uninstall()` discarded the return value from `hook_install()` / `hook_uninstall()`. Consequently, `hook_wrap()` could report success even when text patching failed, and `hook_unwrap_remove()` could free the chain/trampoline allocation even when restoring the original prologue failed.

The active call sites now call the checked primitives directly:
- `hook_wrap()` returns `-HOOK_PATCH_FAILED` for a normal patch failure;
- on `-EUCLEAN`, it returns `-HOOK_PATCH_UNCERTAIN` and deliberately retains chain storage because the patched text may still reference it;
- `hook_unwrap_remove()` retains chain/trampoline memory and returns if restoration fails; it frees only after a successful restore;
- `unhook()` now rejects null/invalid function pointers and invalid resolved origins before looking up hook memory.

The relocation audit also found that `relo_adr()` left an ADR target unchanged when it pointed into the prologue bytes that the hook would overwrite. The target could then refer to the newly installed branch sequence rather than the original bytes. The implementation now rejects such ADR relocations with `-HOOK_BAD_RELO` (fail-closed), matching the existing ADRP policy. It does not attempt to remap an arbitrary address into transformed trampoline instructions.

### CI and artifact

- CI: https://github.com/ljx-91/kptools-fix/actions/runs/42476609978
- Source commit: `1f9699397d87163aa16fcb54f991487e525c8568`
- GCC 14.2 build and all source/static checks: passed
- Artifact ID: `13615676648`
- Artifact ZIP SHA-256: `986a8a36db4bcae41d6440aa49bb6aaa2316fe3d697b5c49da0393262ad99252`
- KPIMG SHA-256: `daa4efed10a9a0fb9354f4fa7daf0beb527c9f2cbda0dd67e458a465eeca137d`
- ELF SHA-256: `a6757e80cf1c192d154edba87081eb3780ce68f49e3d4b1516ae16a5aa133701`

The archive checksum and all four manifest payload checksums were independently matched. As in earlier builds, `SHA256SUMS.txt` contains `dist-y73s/...` paths while the artifact ZIP stores the files at its root; therefore running `sha256sum -c SHA256SUMS.txt` from the extracted root fails on path lookup. The file contents' hashes themselves match the manifest values exactly. This packaging-path mismatch remains a known CI artifact issue.

### PAC/BTI scope

The prologue path preserves PACIASP/PACIBSP in the relocated original instructions and prefixes the replacement trampoline with BTI_JC in that special case. This is not sufficient to claim general BTI compatibility: `branch_absolute()` uses `BR X17`, so the replacement target's landing-pad type and the target page's BTI enforcement must also be compatible. The Y73S Android 10 / Linux 4.14 target's actual BTI enablement and replacement entry encodings have not been established from the original vendor kernel. Leave PAC/BTI compatibility **unverified** until those facts are checked against the exact device image and CPU feature state.
