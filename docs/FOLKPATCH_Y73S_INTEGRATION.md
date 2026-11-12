# FolkPatch Y73s integration

This branch contains the Y73s-specific KernelPatch/kptools changes. FolkPatch 115404
(commit `0f3f42ba02d6441dbbeb247f34c0f5eabc14e393`) packages its Android ARM64
kptools executable as `app/libs/arm64-v8a/libkptools.so` and copies it to its
private `kptools` command path at runtime.

The FolkPatch 115404 Gradle build already supports local KernelPatch artifacts
through `-PkernelPatchArtifacts=/absolute/path/to/artifacts`. The directory must
contain these exact filenames:

- `kptools-android`: Android ARM64 PIE executable.
- `kpimg-android`: the matching Y73s KernelPatch payload.
Both are built from the same source commit by
`.github/workflows/build-folkpatch-y73s-artifacts.yml` and uploaded together
as the `folkpatch-y73s-kernelpatch-artifacts` Actions artifact. That workflow
also builds the side-by-side patcher APK as `folkpatch-y73s-patcher-apk`.

Do not substitute the Linux host binary for `kptools-android`. The Android file
is an executable ELF with `/system/bin/linker64` as its interpreter; FolkPatch
stores it under the historical filename `libkptools.so`, then executes it.

## Build the manager from source

Use the FolkPatch source revision matching the supplied 115404 APK, rather than
repacking or modifying the signed APK in place:

```sh
git clone --recurse-submodules https://github.com/LyraVoid/FolkPatch.git
cd FolkPatch
git checkout 0f3f42ba02d6441dbbeb247f34c0f5eabc14e393
# Match the custom KP 0.13.10 payload and keep the patcher alongside the official manager.
sed -i 's/project.ext.set("kernelPatchVersion", "0.13.9")/project.ext.set("kernelPatchVersion", "0.13.10")/' build.gradle.kts
sed -i 's/applicationId = "me.yuki.folk"/applicationId = "me.yuki.folk.y73s.patcher"/' app/build.gradle.kts
./gradlew assembleDebug -PkernelPatchArtifacts=/absolute/path/to/artifacts
```

The Gradle task copies the local `kpimg-android` into
`app/src/main/assets/kpimg` and `kptools-android` into
`app/libs/arm64-v8a/libkptools.so` before packaging.

## Safety gates

- The generated patcher APK is debug-signed and uses package
  `me.yuki.folk.y73s.patcher`; it is designed to coexist with the official
  `me.yuki.folk` manager. Keep the official manager installed.
- The KPIMG trusts only the official `me.yuki.folk` release signer. Its
  SHA-256(DER certificate) is pinned to
  `a9eba5b702eb55fb5f4b1a672a7133a16a7bcaea949cde43c812ef26c77de812`,
  independently extracted from the supplied APK. The patcher variant is for
  offline image patching only; use the official signed manager after boot.
- The Y73s test image currently preserves the original AVB metadata but does not
  recompute the partition digest/signature. A successful kptools patch is not an
  AVB-verified image and must not be flashed while AVB verification is enforced.
- Always keep the original `boot.img` and a known-good recovery path.
