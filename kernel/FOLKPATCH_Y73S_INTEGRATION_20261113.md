# FolkPatch Y73S 0.13.10 integration record

Target: vivo Y73s V2031A / PD2031, MT6853, ARM64, Android 10, Linux 4.14.141+.

## Integrated APK payload (offline artifact; not built by this repository workflow)

- APK SHA-256: `e2eb9548998d4c6b926fb4a56fb9122aa794af4390903cc7ff8bffdc2f16cde4`
- Android ARM64 kptools SHA-256: `bcd18722cbfbd72cb02280ce8b7cecb1fbbd17a7810fd59016b0b5ea73b4bb8a`
- Y73S KPIMG 0.13.10 SHA-256: `0eee6c55ef62b86d7b611f17594f8fa6ad6f5c002f493e723a373b73fc9fc0c4`
- libapjni.so SHA-256: `475f8b53da27a94ed956d5f65ce51e46326cce1064c08ae441373d486896fdb6`
- boot_patch.sh SHA-256: `e6f1b61346c12452cfabc51c3030cc50c0a0a1bf419e1f7132fe03802f89a28a`

The four APK payload components were extracted and compared byte-for-byte with their corresponding integration bundle files. The shell script passes `sh -n`. The APK JAR signature verifies; the signing certificate is self-signed and the native signer pin matches its SHA-256 certificate fingerprint.

## Original boot image and offline evidence

- Original Library boot.img SHA-256: `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`
- Existing offline validation reports a successful host-simulated unpack/patch/repack flow with kptools 0xd0a / KPIMG 0.13.10.
- The report explicitly states that CONFIG_KALLSYMS_ALL is not set.
- The modified kernel payload does not match the original AVB Boot Hash Descriptor. No AVB re-signing or real-device boot test has been performed.

## Release and safety notes

- The custom APK uses a local self-signed certificate and cannot be installed as an in-place update over the official-key FolkPatch APK.
- Never commit or publish the private JKS signing key.
- This record is an integration/audit record, not a flash approval. Keep the original boot image and recovery route.

## Follow-up CI artifact comparison (2026-11-13)

The newly enabled GCC 14.2 KPIMG workflow completed successfully on this branch:
- Run: https://github.com/ljx-91/kptools-fix/actions/runs/43271136525
- Artifact SHA-256: `059e2a3a687622c6b8a2526851a488ddec8b6972a5bf569b2582524be9d8d094`
- CI `kpimg-android` SHA-256: `a5d38bd78d3b7e8fdec7e6ba3e65e51d5ef4e4e68b943b5c202764bf1599ac94`
- CI source version: 0.13.10.

Important integration discrepancy: the existing offline APK contains KPIMG SHA-256 `0eee6c55ef62b86d7b611f17594f8fa6ad6f5c002f493e723a373b73fc9fc0c4`, which is **not byte-identical** to the latest CI artifact. Both report version 0.13.10, but the binaries differ substantially, not merely in their embedded build-time string. A repeat CI run also produced a different KPIMG hash (the raw image embeds its build time), so archive the exact CI artifact used for any future APK packaging and do not assume bit-for-bit reproducibility. The existing APK must therefore be treated as a previously integrated candidate, not as a package containing the latest branch CI KPIMG. Replacing this asset requires rebuilding/re-signing the APK and keeping its native signer pin consistent; do not silently substitute the binary.



## Local APK re-integration script

- Added `scripts/rebuild-folkpatch-apk-with-ci-kpimg.sh`.
- It refuses a base APK whose signing certificate does not match the native `libapjni.so` pin (`dd7fa45abc401b4ec89124538fcb55db593928e82bdb36496beb84318e7ef0be)).
- It verifies the original ARM64 `libkptools.so` and `libapjni.so` hashes, replaces only `assets/kpimg`, re-signs with the user-provided local JKS, then reopens the APK and verifies the KPIMG, native libraries, alignment and signer pin.
- JKS private key and passwords are intentionally not stored in Git. The JKS file is present in the user's Library bundle; the keystore/key passwords are not available to this build session. The script must be run locally with those credentials supplied through environment variables.
- The new CI KPIMG has not yet been injected into the APK, and no APK signed with that new payload is being claimed as built.


## kptools zero-padding parser fix and fresh offline validation

A real host-side patch/repack/reparse test against the Library original boot.img found a parser defect:
- The patcher reserves `extra_size=0x80` even when there are no embedded extra records; this area is all zero.
- `parse_image_patch_info()` previously treated the zero-filled empty slot as a malformed `kpe` record and returned `-ENOEXEC` from `kptools -l`, despite the kernel patch and boot repack having succeeded.
- Fixed in `tools/patch.c` by accepting an all-zero remaining extra area as padding before attempting to parse an extra record.
- Source fix commit: `9557f9e99120f2ec8cc5afe5cca9056336e4cdf7`.
- Host build with the fix passed: https://github.com/ljx-91/kptools-fix/actions/runs/43273501646
- Android AArch64 build with the fix passed: https://github.com/ljx-91/kptools-fix/actions/runs/43273501436

Fresh host-side validation using the fixed host kptools, the latest CI KPIMG, and the exact Library original boot.img:
- Original boot SHA-256: `c47e94f64696fe70de11ea26cda4a3e0e6e025e581e7a96b95f1d975c9fe7cd5`.
- KPIMG SHA-256: `a5d38bd78d3b7e8fdec7e6ba3e65e51d5ef4e4e68b943b5c202764bf1599ac94`.
- Patched/repacked candidate SHA-256: `f8e2880e153040d9c7bf2e8c251f8c169963a84a27000dd4215f53e0f76aa7ae`.
- Patch exit code 0; repack exit code 0; fresh extraction succeeded.
- `kptools -l` now returns 0 and reports `patched=true`, KPIMG version `0xd0a` (0.13.10), ARM64, android/release.
- KALLSYMS exact count `0x1a5b9`, Token Table `0x01e4bd00`, Token Index `0x01e4c100`, Addresses `0x01c1c700`, vectors index 18/offset `0x2800`, `pid_vnr` SP_EL0 instruction `0xd5384108`, kernel base `0xffffff8008080000`.
- The patched candidate hash matches the first run with the pre-fix host tool; the parser-only fix does not change patch output bytes.

Updated Android kptools SHA-256: `77bad7aae3c7ca9d51e4092ca6d68c977cfa37fcf9d78c17aa814e4c04789524` (AArch64 PIE, Android API 24, NDK r27c). The local APK re-integration script now replaces both `assets/kpimg` and `lib/arm64-v8a/libkptools.so`, verifies the unchanged `libapjni.so` pin, signs locally, and verifies all final component hashes.

The offline candidate is still **not flash-approved**: `CONFIG_KALLSYMS_ALL` is disabled and the original AVB Boot Hash Descriptor is stale after kernel modification. No device boot test has been done.
