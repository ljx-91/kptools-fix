# KernelPatch LKM (DDK-built .ko)

KernelPatch as an out-of-tree Linux loadable module. This is an alternative
delivery path to the image-patched KPIMG; it does not modify or repack
`boot.img`.

Current branch-wide status and exact CI evidence: [Y73s status overview](../Y73S_STATUS_CN.md).

## Implementation status

The repository contains an LKM framework with the following implemented
components:

- module entry, runtime symbol resolution, syscall-table discovery and
  syscall patching;
- trusted APatch manager APK verification and manager UID discovery;
- supercall dispatch for version, SU profile/UID operations, KStorage and KPM
  management;
- KPM ELF loading, symbol resolution, relocation processing, executable-page
  permission checks, module listing/info/control and unload handling;
- ARM64 inline and function-pointer Hook chains, text-patch rollback checks,
  callback owner references and KPM unload guards;
- manager sucompat interception and SELinux context selection.

This is not a release certification. In particular, the LKM objects have not
yet been compiled in this branch against the exact vivo Y73s Android 10 /
Linux 4.14.141 kernel build tree and configuration. The source-level CI
contracts do not replace a target-KDIR build, lockdep/KASAN testing, or runtime
stress testing. The LKM Hook backend also intentionally retains retired
executable trampoline regions because a safe cross-CPU reclamation protocol
has not yet been established.

The LKM feature-control supercall remains a stub, and x86_64 is not supported
by this ARM64 implementation.

### Y73S deployment modes are mutually exclusive

On vivo Y73s / Linux 4.14.141, use either the KPIMG-patched boot path or the
standalone LKM path; do not load this LKM on top of a boot image where KPIMG
already installed its syscall-45 hook.

Both paths target the real SyS_truncate.cfi implementation. KPIMG's inline
patch is a four-word literal-backed branch. If the LKM is loaded afterward,
its relocation validator detects that the branch's literal points into the
prologue being overwritten and rejects the second inline hook. LKM init then
unwinds instead of stacking two independent patch registries on the same
entry. This is intentional fail-closed behavior, not a supported coexistence
mechanism. Do not weaken the relocation rejection to force both paths to load.

## Build

### What repository CI currently validates

- `.github/workflows/build-y73s-kptools-host.yml`: host kptools build/package
  and LKM/KPM source-contract checks. It does **not** compile
  `kernelpatch.ko`.
- `.github/workflows/build-y73s-kpimg-gcc.yml`: Arm GNU GCC KPIMG build and
  KPIMG-side audit suite. It does **not** compile the LKM objects.

There is currently no `build-lkm.yml` workflow in this repository. Do not
interpret a green host/KPIMG workflow as proof that the LKM module builds for
the target kernel.

### Locally with a configured DDK/KDIR

With the DDK toolchain and a compatible configured kernel tree:

```sh
cd lkm
CONFIG_KP_LKM=m CC=clang make
```

Or use the DDK CLI with a supported kernel target, for example:

```sh
ddk build android12-5.10 ODIR="$(pwd)/out" -e CONFIG_KP_LKM=m
```

The android12-5.10 example is a generic DDK build target, not the vivo Y73s
Linux 4.14 target. A successful build against it would not establish Y73s
compatibility.

## Target validation requirements

Before considering the LKM usable on a device:

1. Build against the exact target kernel source, generated headers, config,
   toolchain and ABI.
2. Resolve all compile/link errors and verify the resulting module metadata.
3. Run malformed-KPM input tests and concurrency/lifecycle stress tests in a
   disposable kernel test environment.
4. Verify Hook install/uninstall, permission transitions, KPM load/unload and
   callback teardown under lockdep and memory-safety instrumentation where
   available.

No device-side test, Fastboot operation, 9008 operation, or partition write is
performed by the repository CI described above.

## Layout

```
lkm/
  Kbuild / Makefile / Kconfig
  core/       module entry and subsystem initialization
  infra/      symbol resolver, text patching, syscall table, hashing
  manager/    trusted APatch manager APK verification and discovery
  hook/       shared Hook engine and LKM executable-memory backend
  kpm/        KPM ELF loader, relocations, symbol table and supercalls
  supercall/  SU, KStorage, dispatch and sucompat handling
```
