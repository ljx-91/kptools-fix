#!/usr/bin/env python3
"""Offline AVB chain and boot HashDescriptor auditor for Y73s images.

This tool never writes images or talks to a device. It verifies AVB metadata
self-hashes/RSA signatures, chained public-key equality, and the boot payload
digest committed by the embedded vbmeta footer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


class AuditError(Exception):
    pass


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from(">Q", data, off)[0]


def checked_slice(data: bytes, off: int, size: int, label: str) -> bytes:
    if off < 0 or size < 0 or off + size > len(data):
        raise AuditError(f"{label}: range outside input")
    return data[off:off + size]


def parse_footer(boot: bytes) -> dict:
    if len(boot) < 64:
        raise AuditError("boot image is too small for AVB footer")
    footer = boot[-64:]
    if footer[:4] != b"AVBf":
        raise AuditError("boot image has no AVBf footer")
    major, minor = struct.unpack_from(">II", footer, 4)
    original_image_size, vbmeta_offset, vbmeta_size = struct.unpack_from(">QQQ", footer, 12)
    if original_image_size > len(boot):
        raise AuditError("AVB footer original_image_size exceeds boot image")
    checked_slice(boot, vbmeta_offset, vbmeta_size, "embedded vbmeta")
    return {
        "version": [major, minor],
        "original_image_size": original_image_size,
        "vbmeta_offset": vbmeta_offset,
        "vbmeta_size": vbmeta_size,
    }


def parse_vbmeta(blob: bytes, label: str) -> dict:
    if len(blob) < 256 or blob[:4] != b"AVB0":
        raise AuditError(f"{label}: missing AVB0 header")
    required_major, required_minor = struct.unpack_from(">II", blob, 4)
    auth_size, aux_size = struct.unpack_from(">QQ", blob, 12)
    algorithm_type = u32(blob, 28)
    hash_offset, hash_size, sig_offset, sig_size = struct.unpack_from(">QQQQ", blob, 32)
    pub_offset, pub_size = struct.unpack_from(">QQ", blob, 64)
    pubmeta_offset, pubmeta_size = struct.unpack_from(">QQ", blob, 80)
    desc_offset, desc_size = struct.unpack_from(">QQ", blob, 96)
    rollback_index = u64(blob, 112)
    flags, rollback_location = struct.unpack_from(">II", blob, 120)

    if 256 + auth_size + aux_size > len(blob):
        raise AuditError(f"{label}: auth/aux blocks exceed vbmeta input")
    auth = checked_slice(blob, 256, auth_size, f"{label} auth block")
    aux = checked_slice(blob, 256 + auth_size, aux_size, f"{label} aux block")
    stored_hash = checked_slice(auth, hash_offset, hash_size, f"{label} auth hash")
    signature = checked_slice(auth, sig_offset, sig_size, f"{label} signature")
    public_key = checked_slice(aux, pub_offset, pub_size, f"{label} public key")
    descriptors = checked_slice(aux, desc_offset, desc_size, f"{label} descriptors")
    if pubmeta_size:
        checked_slice(aux, pubmeta_offset, pubmeta_size, f"{label} public key metadata")

    return {
        "label": label,
        "blob": blob,
        "version": [required_major, required_minor],
        "auth_size": auth_size,
        "aux_size": aux_size,
        "algorithm_type": algorithm_type,
        "stored_hash": stored_hash,
        "signature": signature,
        "public_key": public_key,
        "descriptors_blob": descriptors,
        "rollback_index": rollback_index,
        "flags": flags,
        "rollback_index_location": rollback_location,
    }


def avb_public_modulus(public_key: bytes) -> tuple[int, int]:
    if len(public_key) < 8:
        raise AuditError("AVB public key is truncated")
    bits = u32(public_key, 0)
    if bits != 2048 or len(public_key) != 8 + 2 * (bits // 8):
        raise AuditError(f"unsupported AVB RSA public key: bits={bits}, size={len(public_key)}")
    modulus_bytes = public_key[8:8 + bits // 8]
    return int.from_bytes(modulus_bytes, "big"), bits


def verify_vbmeta_signature(vbmeta: dict) -> dict:
    blob = vbmeta["blob"]
    auth_size = vbmeta["auth_size"]
    aux_size = vbmeta["aux_size"]
    auth = blob[256:256 + auth_size]
    aux = blob[256 + auth_size:256 + auth_size + aux_size]
    digest = hashlib.sha256(blob[:256] + aux).digest()
    if vbmeta["algorithm_type"] != 1:
        raise AuditError(f"{vbmeta['label']}: expected SHA256_RSA2048 (algorithm 1)")
    if len(vbmeta["stored_hash"]) != 32 or vbmeta["stored_hash"] != digest:
        raise AuditError(f"{vbmeta['label']}: authentication hash block mismatch")
    modulus, bits = avb_public_modulus(vbmeta["public_key"])
    signature = vbmeta["signature"]
    if len(signature) != bits // 8:
        raise AuditError(f"{vbmeta['label']}: unexpected RSA signature length")
    exponent = 65537
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= modulus:
        raise AuditError(f"{vbmeta['label']}: RSA signature integer out of range")
    encoded = pow(sig_int, exponent, modulus).to_bytes(bits // 8, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    padding_len = bits // 8 - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info
    if padding_len < 8 or encoded != expected:
        raise AuditError(f"{vbmeta['label']}: RSA PKCS#1 v1.5 signature mismatch")
    return {
        "auth_hash_ok": True,
        "rsa_sha256_signature_ok": True,
        "public_key_sha256": hashlib.sha256(vbmeta["public_key"]).hexdigest(),
        "modulus_hex": vbmeta["public_key"][8:8 + bits // 8].hex(),
    }


def parse_descriptors(vbmeta: dict) -> list[dict]:
    raw = vbmeta["descriptors_blob"]
    result = []
    pos = 0
    while pos < len(raw):
        if len(raw) - pos < 16:
            if any(raw[pos:]):
                raise AuditError(f"{vbmeta['label']}: nonzero trailing descriptor bytes")
            break
        tag, following = struct.unpack_from(">QQ", raw, pos)
        pos += 16
        body = checked_slice(raw, pos, following, f"{vbmeta['label']} descriptor")
        pos += following
        if tag == 2:
            if len(body) < 116:
                raise AuditError(f"{vbmeta['label']}: truncated HashDescriptor")
            image_size = u64(body, 0)
            algorithm = body[8:40].split(b"\0", 1)[0].decode("ascii", "replace")
            name_len, salt_len, digest_len, flags = struct.unpack_from(">IIII", body, 40)
            name = checked_slice(body, 116, name_len, "HashDescriptor partition name").decode("utf-8", "replace")
            salt = checked_slice(body, 116 + name_len, salt_len, "HashDescriptor salt")
            digest = checked_slice(body, 116 + name_len + salt_len, digest_len, "HashDescriptor digest")
            result.append({
                "type": "hash",
                "partition": name,
                "image_size": image_size,
                "algorithm": algorithm,
                "salt": salt,
                "digest": digest,
                "flags": flags,
            })
        elif tag == 4:
            if len(body) < 76:
                raise AuditError(f"{vbmeta['label']}: truncated ChainPartitionDescriptor")
            rollback_location, name_len, key_len, flags = struct.unpack_from(">IIII", body, 0)
            name = checked_slice(body, 76, name_len, "ChainDescriptor partition name").decode("utf-8", "replace")
            key = checked_slice(body, 76 + name_len, key_len, "ChainDescriptor public key")
            result.append({
                "type": "chain",
                "partition": name,
                "rollback_index_location": rollback_location,
                "flags": flags,
                "public_key": key,
            })
        else:
            result.append({"type": "other", "tag": tag, "size": following})
    return result


def find_chain(descriptors: list[dict], partition: str) -> dict:
    for item in descriptors:
        if item.get("type") == "chain" and item.get("partition") == partition:
            return item
    raise AuditError(f"root vbmeta has no chain descriptor for {partition}")


def audit(args) -> dict:
    boot = Path(args.boot).read_bytes()
    root_blob = Path(args.vbmeta).read_bytes()
    vbmeta_system_blob = Path(args.vbmeta_system).read_bytes()
    lk = Path(args.lk).read_bytes()

    footer = parse_footer(boot)
    boot_child_blob = checked_slice(
        boot, footer["vbmeta_offset"], footer["vbmeta_size"], "boot embedded vbmeta"
    )
    root = parse_vbmeta(root_blob, "root vbmeta")
    boot_child = parse_vbmeta(boot_child_blob, "boot embedded vbmeta")
    vbmeta_system = parse_vbmeta(vbmeta_system_blob, "vbmeta_system")
    root_sig = verify_vbmeta_signature(root)
    boot_sig = verify_vbmeta_signature(boot_child)
    system_sig = verify_vbmeta_signature(vbmeta_system)

    root_desc = parse_descriptors(root)
    boot_desc = parse_descriptors(boot_child)
    system_desc = parse_descriptors(vbmeta_system)
    boot_chain = find_chain(root_desc, "boot")
    system_chain = find_chain(root_desc, "vbmeta_system")
    if boot_chain["public_key"] != boot_child["public_key"]:
        raise AuditError("root boot chain key does not match boot embedded vbmeta public key")
    if system_chain["public_key"] != vbmeta_system["public_key"]:
        raise AuditError("root vbmeta_system chain key does not match vbmeta_system public key")

    boot_hash_desc = next(
        (d for d in boot_desc if d.get("type") == "hash" and d.get("partition") == "boot"),
        None,
    )
    if boot_hash_desc is None:
        raise AuditError("boot embedded vbmeta has no boot HashDescriptor")
    if boot_hash_desc["algorithm"] != "sha256":
        raise AuditError("boot HashDescriptor algorithm is not sha256")
    if boot_hash_desc["image_size"] > len(boot):
        raise AuditError("boot HashDescriptor image_size exceeds boot image")
    actual_boot_digest = hashlib.sha256(
        boot_hash_desc["salt"] + boot[:boot_hash_desc["image_size"]]
    ).digest()
    boot_hash_matches = actual_boot_digest == boot_hash_desc["digest"]

    modulus = bytes.fromhex(root_sig["modulus_hex"])
    modulus_offset = lk.find(modulus)
    result = {
        "boot_file": str(Path(args.boot)),
        "boot_size": len(boot),
        "boot_sha256": hashlib.sha256(boot).hexdigest(),
        "avb_footer": footer,
        "embedded_vbmeta_sha256": hashlib.sha256(boot_child_blob).hexdigest(),
        "root_vbmeta_sha256": hashlib.sha256(root_blob).hexdigest(),
        "vbmeta_system_sha256": hashlib.sha256(vbmeta_system_blob).hexdigest(),
        "signatures": {
            "root_vbmeta": root_sig,
            "boot_embedded_vbmeta": boot_sig,
            "vbmeta_system": system_sig,
        },
        "chain_key_matches": {
            "boot": True,
            "vbmeta_system": True,
        },
        "root_public_modulus_found_in_lk": modulus_offset >= 0,
        "root_public_modulus_lk_offset": modulus_offset if modulus_offset >= 0 else None,
        "boot_hash_descriptor": {
            "partition": boot_hash_desc["partition"],
            "image_size": boot_hash_desc["image_size"],
            "salt": boot_hash_desc["salt"].hex(),
            "expected_digest": boot_hash_desc["digest"].hex(),
            "actual_digest": actual_boot_digest.hex(),
            "matches": boot_hash_matches,
        },
        "root_chain_partitions": [
            {"partition": d["partition"], "rollback_index_location": d["rollback_index_location"],
             "public_key_sha256": hashlib.sha256(d["public_key"]).hexdigest()}
            for d in root_desc if d.get("type") == "chain"
        ],
        "boot_embedded_descriptors": [
            {"type": d["type"], "partition": d.get("partition")}
            for d in boot_desc
        ],
        "vbmeta_system_descriptors": [
            {"type": d["type"], "partition": d.get("partition")}
            for d in system_desc
        ],
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot", required=True, help="original or patched Android boot image")
    parser.add_argument("--vbmeta", required=True, help="root vbmeta.img")
    parser.add_argument("--vbmeta-system", required=True, help="vbmeta_system.img")
    parser.add_argument("--lk", required=True, help="matching lk-verified.img")
    args = parser.parse_args()
    try:
        result = audit(args)
    except (OSError, AuditError, struct.error) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    if not result["root_public_modulus_found_in_lk"]:
        print("WARNING: root AVB public modulus was not found in LK", file=sys.stderr)
    return 0 if result["boot_hash_descriptor"]["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
