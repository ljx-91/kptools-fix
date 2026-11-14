# Y73s Stock Boot kptools Round-trip Audit — 2026-11-14

## Scope

This is an offline format and payload-preservation test using the user's original vivo Y73s stock `boot.img`. No image was flashed to the device.

The Windows x86-64 `kptools.exe` passed a Windows CI synthetic Android Boot v2 round-trip test. The exact stock-image round-trip below was run with the Linux host kptools binary from commit `6a8846afa608a1bf8c8b63e4e0ed1ec6d560c9dc`, because this execution environment does not provide Windows or Wine.

GitHub compare `5471191...6a8846a` reports changes only in workflow files and the audit/test documentation and script; no source files under `tools/` changed. The stock-image round-trip was repeated with the Linux kptools artifact built from `6a8846a` itself. This still is not a direct execution of the Windows PE against the stock image.

The Windows x86-64 executable passed a Windows CI Android Boot v2 fixture test at commit `6fa43cb0fa05de26c4b4b42b637292193ed8c97d`, including both an appended kernel DTB and a v2 tail DTB table. The reusable test script also accepts `--boot-image` to test a supplied real image on a Windows PC.

## Inputs and outputs

- Stock image: 100,663,296 bytes (96 MiB)
- Stock SHA-256: `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`
- Repacked image: 100,663,296 bytes (96 MiB)
- Repacked SHA-256: `0c076c7e2ca83e2dec208c500c504f96ad424a07d6235058ba37726825e6f363`
- Host kptools version: `d0a`

## Results

1. `unpack stock boot.img` succeeded.
2. Android Boot Header v2 and 2048-byte page size were recognized.
3. GZIP kernel was decompressed to 47,517,708 bytes.
4. `repack stock boot.img` succeeded and generated a 96 MiB image.
5. Re-unpacking the generated image succeeded.
6. Decompressed kernel payload was byte-identical:
   - SHA-256: `345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e`
7. Appended DTB payload was byte-identical:
   - Size: 158,312 bytes
   - SHA-256: `d9f9e01f2763d76bc842c91c06e76dbb1f0baa0f91a27cc10ecd1fee4a9a0bdc`
8. Ramdisk payload was byte-identical:
   - Size: 777,508 bytes
   - SHA-256: `f14df852dfc9d2dc7fe17edfbceedb564d616b19e2ace7ef0f633d94798065dc`
9. Second-stage payload size remained zero.

## Repeating the test on Windows

From the repository root on a Windows PC, run:

`py scripts\\test_kptools_bootimg_roundtrip.py .\\kptools-windows-x86_64.exe --boot-image .\\boot.img`

This checks the supplied image's decompressed kernel, appended kernel DTB, Boot v2 tail DTB table, ramdisk, and second-stage size after unpack/repack/unpack. It does not validate or regenerate AVB metadata.

## AVB warning — do not flash

kptools explicitly warned:

> AVB metadata bytes are preserved, but partition digest and signature are not recomputed; do not treat the repacked image as AVB-verified

The repacked image is strictly an offline round-trip test artifact. It is not a flash candidate. No AVB/vbmeta changes were attempted.

## Conclusion

The host kptools implementation correctly unpacked and repacked the actual Y73s stock Boot image while preserving the decompressed kernel, appended DTB, and ramdisk byte-for-byte. This validates the tested host tool's basic Android Boot v2 I/O path for this image.

It does **not** prove that the Windows executable itself has processed this exact stock image, does not validate AVB, does not prove KPIMG runtime compatibility, and does not establish that a patched image will boot on the device.


## Matched Windows + KPIMG artifacts

A matched package was assembled from the same source commit `939ddd03cb6d2290ff78176e473a8b6cddb1df30`.

- Windows kptools x86-64 SHA-256: `0e51e9e23ad5846ffc49e5e4b0ee5ecf5526a5f3aacab6985ffc9c748980dbb8`
- KPIMG payload SHA-256: `4ab1f2e9235cc404a9785842f29af29266aee3456aa29ceab37cb4b750f1a9ea`
- KPIMG ELF SHA-256: `cf2c596ccc24f74a3da3ba963f69d42e8ffc5e324a762e7bdba1110e68a71cb0`

Windows build run: https://github.com/ljx-91/kptools-fix/actions/runs/43557013491

KPIMG build/audit run: https://github.com/ljx-91/kptools-fix/actions/runs/43557013440

The Windows CI test uses a synthetic fixture, not the user's 96 MiB stock image. The actual stock-image round-trip was verified with the Linux host build. The test runner in `scripts/test_kptools_bootimg_roundtrip.py` now accepts `--boot-image` so the same Windows executable can be exercised locally against the supplied stock image.
