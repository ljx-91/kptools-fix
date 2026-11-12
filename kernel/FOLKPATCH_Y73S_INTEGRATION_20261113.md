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
