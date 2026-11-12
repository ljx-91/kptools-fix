# FolkPatch Y73s integration

This branch contains the Y73s-specific KernelPatch/kptools changes. FolkPatch 115404
(commit `0f3f42ba02d6441dbbeb247f34c0f5eabc14e393`) packages its Android ARM64
kptools executable as `app/libs/arm64-v8a/libkptools.so` and copies it to its
private `kptools` command path at runtime.

The FolkPatch 115404 Gradle build already supports local KernelPatch artifacts
through `-PkernelPatchArtifacts=/absolute/path/to/artifacts`. The directory must
contain these exact filenames:

- `kptools-android`: Android ARM64 PIE executable produced by
  `.github/workflows/build-y73s-kptools-android.yml`.
- `kpimg-android`: the matching Y73s KernelPatch payload from this branch's
  `y73s-kpimg-arm-gnu-gcc14-audit` Actions artifact.

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
# The branch payload is KP 0.13.10 (0xd0a), not the APK's bundled 0.13.9.
sed -i 's/project.ext.set("kernelPatchVersion", "0.13.9")/project.ext.set("kernelPatchVersion", "0.13.10")/' build.gradle.kts
./gradlew assembleDebug -PkernelPatchArtifacts=/absolute/path/to/artifacts
```

The Gradle task copies the local `kpimg-android` into
`app/src/main/assets/kpimg` and `kptools-android` into
`app/libs/arm64-v8a/libkptools.so` before packaging.

## Safety gates

- A rebuilt APK is not signed by the original FolkPatch release key. It cannot
  update the official signed APK in place; do not uninstall the official manager
  or overwrite its data just to test the patcher.
- A changed APK signature/package identity can affect manager authorization.
  Validate the post-boot manager handshake separately before treating the image
  as install-ready.
- The Y73s test image currently preserves the original AVB metadata but does not
  recompute the partition digest/signature. A successful kptools patch is not an
  AVB-verified image and must not be flashed while AVB verification is enforced.
- Always keep the original `boot.img` and a known-good recovery path.
