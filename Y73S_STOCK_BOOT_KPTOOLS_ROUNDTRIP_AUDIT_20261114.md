# Y73s Stock Boot kptools Round-trip Audit — 2026-11-14

## Scope

This is an offline format and payload-preservation test using the user's original vivo Y73s stock `boot.img`. No image was flashed to the device.

The Windows x86-64 `kptools.exe` passed a Windows CI synthetic Android Boot v2 round-trip test. The exact stock-image round-trip below was run with the Linux host kptools binary from commit `5471191b9026ab77213e06f6a31026e38cbf8ba5`, because this execution environment does not provide Windows or Wine.

GitHub compare `5471191...aaf9c397` reports only two changed workflow files:
- `.github/workflows/build-y73s-kpimg-gcc.yml`
- `.github/workflows/build-y73s-kptools-windows.yml`

No source files under `tools/` changed between those revisions. This supports source-level equivalence of the host kptools implementation, but is not a direct execution of the Windows PE against the stock image.

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

## AVB warning — do not flash

kptools explicitly warned:

> AVB metadata bytes are preserved, but partition digest and signature are not recomputed; do not treat the repacked image as AVB-verified

The repacked image is strictly an offline round-trip test artifact. It is not a flash candidate. No AVB/vbmeta changes were attempted.

## Conclusion

The host kptools implementation correctly unpacked and repacked the actual Y73s stock Boot image while preserving the decompressed kernel, appended DTB, and ramdisk byte-for-byte. This validates the tested host tool's basic Android Boot v2 I/O path for this image.

It does **not** prove that the Windows executable itself has processed this exact stock image, does not validate AVB, does not prove KPIMG runtime compatibility, and does not establish that a patched image will boot on the device.
