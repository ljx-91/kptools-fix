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
