#!/usr/bin/env bash
set -euo pipefail

# Repackage FolkPatch with the exact Y73S CI KPIMG and Android kptools binaries.
# CI note: host build validates patch/repack; APK signing remains a local operation.
# Usage:
#   KS_PASS='...' KEY_PASS='...' [KEY_ALIAS=folkpatch-y73s] \
#     scripts/rebuild-folkpatch-apk-with-ci-kpimg.sh base.apk kpimg-android kptools-android signing.jks output.apk

[[ $# -eq 5 ]] || { echo "Usage: $0 <base.apk> <kpimg-android> <kptools-android> <signing.jks> <output.apk>" >&2; exit 2; }
APK_IN=$(realpath "$1")
KPIMG=$(realpath "$2")
KPTOOLS=$(realpath "$3")
KEYSTORE=$(realpath "$4")
APK_OUT=$(realpath -m "$5")
ALIAS=${KEY_ALIAS:-folkpatch-y73s}
EXPECTED_CERT=dd7fa45abc401b4ec89124538fcb55db593928e82bdb36496beb84318e7ef0be
EXPECTED_KPTOOLS=77bad7aae3c7ca9d51e4092ca6d68c977cfa37fcf9d78c17aa814e4c04789524
EXPECTED_APJNI=475f8b53da27a94ed956d5f65ce51e46326cce1064c08ae441373d486896fdb6

for cmd in unzip zip zipalign apksigner sha256sum grep awk realpath readelf; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing tool: $cmd" >&2; exit 127; }
done
[[ -s "$APK_IN" && -s "$KPIMG" && -s "$KPTOOLS" && -s "$KEYSTORE" ]] || { echo "Input APK/KPIMG/kptools/keystore missing or empty" >&2; exit 1; }
[[ "$APK_OUT" != "$APK_IN" ]] || { echo "Output must not overwrite input APK" >&2; exit 1; }
: "${KS_PASS:?Set KS_PASS in environment}"
: "${KEY_PASS:?Set KEY_PASS in environment}"

[[ "$(sha256sum "$KPTOOLS" | awk '{print $1}')" == "$EXPECTED_KPTOOLS" ]] || { echo "Unexpected Android kptools artifact" >&2; exit 1; }
readelf -h "$KPTOOLS" | grep -q 'AArch64' || { echo "kptools is not AArch64" >&2; exit 1; }
readelf -h "$KPTOOLS" | grep -q 'DYN (Position-Independent Executable file)' || { echo "kptools is not PIE" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/base" "$WORK/new"
apksigner verify --verbose --print-certs "$APK_IN" > "$WORK/base-verify.txt"
grep -Eiq "Signer #1 certificate SHA-256 digest: *${EXPECTED_CERT}" "$WORK/base-verify.txt" || { echo "Base APK signer does not match libapjni.so pin" >&2; exit 1; }
unzip -q "$APK_IN" -d "$WORK/base"
[[ -f "$WORK/base/lib/arm64-v8a/libapjni.so" && -f "$WORK/base/assets/kpimg" ]] || { echo "Expected APK assets/native library missing" >&2; exit 1; }
[[ "$(sha256sum "$WORK/base/lib/arm64-v8a/libapjni.so" | awk '{print $1}')" == "$EXPECTED_APJNI" ]] || { echo "Unexpected libapjni.so in base APK" >&2; exit 1; }

cp -a "$WORK/base/." "$WORK/new/"
install -m 0644 "$KPIMG" "$WORK/new/assets/kpimg"
install -m 0644 "$KPTOOLS" "$WORK/new/lib/arm64-v8a/libkptools.so"
printf '0.13.10\n' > "$WORK/new/assets/kpimg.version"
if [[ -d "$WORK/new/META-INF" ]]; then
  find "$WORK/new/META-INF" -maxdepth 1 -type f \
    \( -iname '*.SF' -o -iname '*.RSA' -o -iname '*.DSA' -o -iname '*.EC' -o -iname 'MANIFEST.MF' \) -delete
fi
(cd "$WORK/new" && zip -X -qr "$WORK/unsigned.apk" .)
zipalign -f -p 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
apksigner sign --ks "$KEYSTORE" --ks-key-alias "$ALIAS" \
  --ks-pass env:KS_PASS --key-pass env:KEY_PASS \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --out "$APK_OUT" "$WORK/aligned.apk"

apksigner verify --verbose --print-certs "$APK_OUT" > "$WORK/final-verify.txt"
grep -Eiq "Signer #1 certificate SHA-256 digest: *${EXPECTED_CERT}" "$WORK/final-verify.txt" || { rm -f "$APK_OUT"; echo "Final signer does not match libapjni.so pin" >&2; exit 1; }
zipalign -c -v 4 "$APK_OUT" >/dev/null
unzip -p "$APK_OUT" assets/kpimg > "$WORK/final-kpimg"
unzip -p "$APK_OUT" lib/arm64-v8a/libkptools.so > "$WORK/final-kptools"
unzip -p "$APK_OUT" lib/arm64-v8a/libapjni.so > "$WORK/final-apjni"
[[ "$(sha256sum "$WORK/final-kpimg" | awk '{print $1}')" == "$(sha256sum "$KPIMG" | awk '{print $1}')" ]] || { rm -f "$APK_OUT"; echo "KPIMG hash mismatch after packaging" >&2; exit 1; }
[[ "$(sha256sum "$WORK/final-kptools" | awk '{print $1}')" == "$EXPECTED_KPTOOLS" ]] || { rm -f "$APK_OUT"; echo "kptools changed after packaging" >&2; exit 1; }
[[ "$(sha256sum "$WORK/final-apjni" | awk '{print $1}')" == "$EXPECTED_APJNI" ]] || { rm -f "$APK_OUT"; echo "libapjni.so changed after packaging" >&2; exit 1; }
cat "$WORK/final-verify.txt"
sha256sum "$APK_OUT"
