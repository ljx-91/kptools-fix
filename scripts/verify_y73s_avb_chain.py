#!/usr/bin/env python3
"""Offline AVB/LK policy audit for the vivo Y73s MT6853 boot image set.

Checks vbmeta authentication-block hashes and RSA-2048 signatures, the root
vbmeta -> boot child-key link, the root key's presence in the supplied LK,
boot HashDescriptor salted digests, and the static unlocked policy row.
It cannot prove the handset runs this LK build or currently reports LKS_UNLOCK.

MTK reference sources used to interpret policy:
- platform/common/boot/avb20/load_vfy_boot.c
- platform/mt6853/sec_policy.c
- platform/mt6853/include/platform/sec_policy.h
- platform/mt6853/include/platform/sec_policy_config{1..4}.h
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

EXPECTED_LK_SHA256 = "e44dc34afa12235011331309c3cac1f995cbca65c5e61c9e598984a5539000d4"
POLICY_ROW_OFFSET = 0xB0C18
POLICY_BYTES_OFFSET = POLICY_ROW_OFFSET + 20
EXPECTED_POLICY = bytes.fromhex("01 00 03 00")
SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class AuditError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


def verify_rsa_sha256(signature, data, avb_key):
    if len(avb_key) != 520 or struct.unpack_from(">I", avb_key)[0] != 2048 or len(signature) != 256:
        raise AuditError("unsupported AVB RSA public-key/signature size")
    modulus = int.from_bytes(avb_key[8:264], "big")
    sig = int.from_bytes(signature, "big")
    if sig >= modulus:
        return False
    decoded = pow(sig, 65537, modulus).to_bytes(256, "big")
    digest_info = SHA256_DER_PREFIX + sha256(data)
    pad_len = 256 - len(digest_info) - 3
    return decoded == b"\x00\x01" + b"\xff" * pad_len + b"\x00" + digest_info


def parse_vbmeta(blob, label):
    if len(blob) < 256 or blob[:4] != b"AVB0":
        raise AuditError(f"{label}: missing AVB0 header")
    u32 = lambda o: struct.unpack_from(">I", blob, o)[0]
    u64 = lambda o: struct.unpack_from(">Q", blob, o)[0]
    auth_sz, aux_sz, alg = u64(12), u64(20), u32(28)
    hash_off, hash_sz = u64(32), u64(40)
    sig_off, sig_sz = u64(48), u64(56)
    pub_off, pub_sz = u64(64), u64(72)
    desc_off, desc_sz = u64(96), u64(104)
    end = 256 + auth_sz + aux_sz
    if alg != 1 or end > len(blob):
        raise AuditError(f"{label}: unsupported algorithm or truncated vbmeta")
    auth = blob[256:256 + auth_sz]
    aux = blob[256 + auth_sz:end]
    if hash_off + hash_sz > len(auth) or sig_off + sig_sz > len(auth):
        raise AuditError(f"{label}: auth-block range invalid")
    if pub_off + pub_sz > len(aux) or desc_off + desc_sz > len(aux):
        raise AuditError(f"{label}: aux-block range invalid")
    if hash_sz != 32 or auth[hash_off:hash_off + hash_sz] != sha256(blob[:256] + aux):
        raise AuditError(f"{label}: authentication-block SHA256 mismatch")
    pub = aux[pub_off:pub_off + pub_sz]
    sig = auth[sig_off:sig_off + sig_sz]
    if not verify_rsa_sha256(sig, blob[:256] + aux, pub):
        raise AuditError(f"{label}: RSA-2048 signature verification failed")

    descs = []
    p, stop = desc_off, desc_off + desc_sz
    while p < stop:
        if p + 16 > stop:
            raise AuditError(f"{label}: truncated descriptor header")
        tag, n = struct.unpack_from(">QQ", aux, p)
        p += 16
        body = aux[p:p + n]
        if len(body) != n or p + n > stop:
            raise AuditError(f"{label}: truncated descriptor body")
        p += n
        if tag == 2:  # HashDescriptor: 56-byte fields + 60 reserved bytes
            if n < 116 or any(body[56:116]):
                raise AuditError(f"{label}: malformed HashDescriptor")
            image_sz = struct.unpack_from(">Q", body)[0]
            hash_alg = body[8:40].split(b"\0", 1)[0].decode("ascii", "replace")
            name_n, salt_n, digest_n, flags = struct.unpack_from(">IIII", body, 40)
            q = 116
            name = body[q:q + name_n]; q += name_n
            salt = body[q:q + salt_n]; q += salt_n
            digest = body[q:q + digest_n]; q += digest_n
            if q != n:
                raise AuditError(f"{label}: invalid HashDescriptor lengths")
            descs.append({"kind": "hash", "partition": name.decode("utf-8", "replace"),
                          "image_size": image_sz, "algorithm": hash_alg,
                          "salt": salt, "digest": digest, "flags": flags})
        elif tag == 4:  # ChainPartitionDescriptor: 16-byte fields + 60 reserved
            if n < 76 or any(body[16:76]):
                raise AuditError(f"{label}: malformed ChainPartitionDescriptor")
            rollback, name_n, key_n, flags = struct.unpack_from(">IIII", body)
            q = 76
            name = body[q:q + name_n]; q += name_n
            child_key = body[q:q + key_n]; q += key_n
            if q > n or n - q > 7 or any(body[q:]):
                raise AuditError(f"{label}: invalid ChainPartitionDescriptor padding")
            descs.append({"kind": "chain", "partition": name.decode("utf-8", "replace"),
                          "rollback_location": rollback, "public_key": child_key, "flags": flags})
    return {"pubkey": pub, "descriptors": descs}


def parse_boot(path, label):
    data = Path(path).read_bytes()
    if len(data) < 64 or data[-64:-60] != b"AVBf":
        raise AuditError(f"{label}: AVB footer missing")
    major, minor, original_sz, vb_off, vb_sz = struct.unpack_from(">IIQQQ", data, len(data) - 60)
    if (major, minor) != (1, 0) or vb_off + vb_sz > len(data) - 64 or original_sz > len(data):
        raise AuditError(f"{label}: invalid footer")
    vb_blob = data[vb_off:vb_off + vb_sz]
    vb = parse_vbmeta(vb_blob, label + "/embedded-vbmeta")
    return {"data": data, "footer_original_size": original_sz, "vbmeta_blob": vb_blob,
            "vbmeta": vb, "hashes": [d for d in vb["descriptors"] if d["kind"] == "hash"]}


def raw_vbmeta(path, label):
    return parse_vbmeta(Path(path).read_bytes(), label)


def boot_digest(image):
    matches = [d for d in image["hashes"] if d["partition"] == "boot"]
    if len(matches) != 1:
        raise AuditError("expected exactly one boot HashDescriptor")
    d = matches[0]
    if d["algorithm"] != "sha256" or d["image_size"] > len(image["data"]):
        raise AuditError("unsupported or out-of-range boot HashDescriptor")
    actual = sha256(d["salt"] + image["data"][:d["image_size"]])
    return {"image_size": d["image_size"], "footer_original_size": image["footer_original_size"],
            "footer_size_matches_descriptor": d["image_size"] == image["footer_original_size"],
            "digest_matches": actual == d["digest"], "expected": d["digest"].hex(),
            "actual": actual.hex()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lk", required=True)
    ap.add_argument("--original-boot", required=True)
    ap.add_argument("--candidate-boot", required=True)
    ap.add_argument("--root-vbmeta", required=True)
    ap.add_argument("--vbmeta-system", required=True)
    a = ap.parse_args()

    lk = Path(a.lk).read_bytes()
    lk_sha = hashlib.sha256(lk).hexdigest()
    if lk_sha != EXPECTED_LK_SHA256:
        raise AuditError(f"LK SHA256 mismatch: {lk_sha}")
    policy = lk[POLICY_BYTES_OFFSET:POLICY_BYTES_OFFSET + 4]
    if policy != EXPECTED_POLICY:
        raise AuditError(f"LK boot policy row changed: {policy.hex()}")

    original = parse_boot(a.original_boot, "original-boot")
    candidate = parse_boot(a.candidate_boot, "candidate-boot")
    root = raw_vbmeta(a.root_vbmeta, "root-vbmeta")
    system = raw_vbmeta(a.vbmeta_system, "vbmeta-system")

    def child_key(vb, name):
        found = [d for d in vb["descriptors"] if d["kind"] == "chain" and d["partition"] == name]
        if len(found) != 1:
            raise AuditError(f"root vbmeta: expected one {name} chain descriptor")
        return found[0]["public_key"]

    if child_key(root, "boot") != original["vbmeta"]["pubkey"]:
        raise AuditError("root boot chain key != embedded boot vbmeta key")
    if child_key(root, "vbmeta_system") != system["pubkey"]:
        raise AuditError("root vbmeta_system chain key != vbmeta_system key")
    if candidate["vbmeta_blob"] != original["vbmeta_blob"]:
        raise AuditError("candidate changed the OEM-signed embedded vbmeta")

    root_modulus = root["pubkey"][8:264]
    lk_key_offset = lk.find(root_modulus)
    if lk_key_offset < 0:
        raise AuditError("root vbmeta RSA modulus not found in LK trust-key material")

    orig_hash = boot_digest(original)
    cand_hash = boot_digest(candidate)
    if not orig_hash["digest_matches"]:
        raise AuditError("original boot salted HashDescriptor digest does not match")
    if cand_hash["digest_matches"]:
        raise AuditError("candidate unexpectedly matches the original boot digest")
    unlocked_vfy = [(policy[1] >> 1) & 1, (policy[3] >> 1) & 1]
    if unlocked_vfy != [0, 0]:
        raise AuditError("unlocked boot verification policy is not disabled in both SBC states")

    print(json.dumps({
        "lk_sha256": lk_sha,
        "lk_build_id": "k6853v1_64_6360-5cfd6cf-20210414212350-20220215124501",
        "lk_boot_policy_offset": hex(POLICY_ROW_OFFSET),
        "lk_boot_policy_bytes": policy.hex(),
        "unlocked_verify_bits_sbc_disabled_enabled": unlocked_vfy,
        "lk_root_key_modulus_offset": hex(lk_key_offset),
        "root_vbmeta_signature": "PASS",
        "vbmeta_system_signature": "PASS",
        "original_embedded_vbmeta_signature": "PASS",
        "candidate_embedded_vbmeta_signature": "PASS",
        "root_boot_chain_key_match": "PASS",
        "root_vbmeta_system_chain_key_match": "PASS",
        "original_boot_hash": orig_hash,
        "candidate_boot_hash": cand_hash,
        "candidate_embedded_vbmeta_unchanged": True,
        "runtime_LKS_UNLOCK_confirmed": False,
        "result": "STATIC_POLICY_SUPPORTS_TOLERATING_HASH_ERROR_ONLY_IF_RUNTIME_LKS_UNLOCK_AND_THIS_LK_BUILD_IS_RUNNING"
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AuditError, OSError, struct.error) as e:
        print(f"AVB AUDIT FAIL: {e}", file=sys.stderr)
        sys.exit(2)
