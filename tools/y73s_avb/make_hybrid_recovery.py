#!/usr/bin/env python3
"""Build a PD2031-style recovery image carrying an OEM vbmeta blob.

This tool preserves the OEM vbmeta bytes; it does not create an OEM signature.
By default it refuses to emit an image unless the selected HashDescriptor
matches the payload. --allow-hash-mismatch is an explicit research-only
override and the resulting image must not be described as AVB-valid.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import tempfile
from pathlib import Path

FOOTER_SIZE = 64
FOOTER_MAGIC = b"AVBf"
VBMETA_MAGIC = b"AVB0"
DEFAULT_TARGET_SIZE = 100_663_296


class ImageError(ValueError):
    pass


def parse_footer(data: bytes, label: str) -> tuple[int, int, int, int, bytes]:
    if len(data) < FOOTER_SIZE:
        raise ImageError(f"{label}: file is smaller than AVB footer")
    footer = data[-FOOTER_SIZE:]
    if footer[:4] != FOOTER_MAGIC:
        raise ImageError(f"{label}: AVBf footer not found at EOF")
    major, minor, original_size, vbmeta_offset, vbmeta_size = struct.unpack_from(
        ">IIQQQ", footer, 4
    )
    if major != 1:
        raise ImageError(f"{label}: unsupported AVB footer major version {major}")
    if minor > 0:
        raise ImageError(f"{label}: unsupported AVB footer minor version {minor}")
    if original_size > len(data) - FOOTER_SIZE:
        raise ImageError(f"{label}: original_image_size exceeds pre-footer area")
    if vbmeta_size == 0 or vbmeta_offset + vbmeta_size > len(data) - FOOTER_SIZE:
        raise ImageError(f"{label}: vbmeta range is empty or outside pre-footer area")
    vbmeta = data[vbmeta_offset:vbmeta_offset + vbmeta_size]
    if len(vbmeta) != vbmeta_size or vbmeta[:4] != VBMETA_MAGIC:
        raise ImageError(f"{label}: footer-selected vbmeta does not start with AVB0")
    return major, minor, original_size, vbmeta_offset, vbmeta_size, footer


def extract_hash_descriptors(vbmeta: bytes) -> list[dict]:
    if len(vbmeta) < 256 or vbmeta[:4] != VBMETA_MAGIC:
        raise ImageError("invalid vbmeta header")
    auth_size, aux_size = struct.unpack_from(">QQ", vbmeta, 12)
    total = 256 + auth_size + aux_size
    if total > len(vbmeta):
        raise ImageError("vbmeta auth/aux blocks exceed selected vbmeta size")
    desc_off, desc_size = struct.unpack_from(">QQ", vbmeta, 96)
    aux_start = 256 + auth_size
    if desc_off + desc_size > aux_size:
        raise ImageError("vbmeta descriptor range exceeds auxiliary block")
    aux = vbmeta[aux_start:total]
    pos, end = desc_off, desc_off + desc_size
    found = []
    while pos < end:
        if pos + 16 > end:
            raise ImageError("truncated AVB descriptor header")
        tag, n = struct.unpack_from(">QQ", aux, pos)
        pos += 16
        if pos + n > end:
            raise ImageError("truncated AVB descriptor body")
        body = aux[pos:pos + n]
        pos += n
        if tag != 2:
            continue
        if n < 116 or any(body[56:116]):
            raise ImageError("malformed AvbHashDescriptor")
        image_size = struct.unpack_from(">Q", body, 0)[0]
        hash_alg = body[8:40].split(b"\0", 1)[0].decode("ascii", "strict")
        name_len, salt_len, digest_len, flags = struct.unpack_from(">IIII", body, 40)
        cursor = 116
        name = body[cursor:cursor + name_len]; cursor += name_len
        salt = body[cursor:cursor + salt_len]; cursor += salt_len
        digest = body[cursor:cursor + digest_len]; cursor += digest_len
        if cursor != n:
            raise ImageError("AvbHashDescriptor variable fields have inconsistent lengths")
        found.append({
            "partition": name.decode("utf-8", "strict"),
            "image_size": image_size,
            "algorithm": hash_alg,
            "salt": salt,
            "digest": digest,
            "flags": flags,
        })
    return found


def check_payload_hash(payload: bytes, vbmeta: bytes, partition: str) -> tuple[bool, str]:
    descriptors = [
        d for d in extract_hash_descriptors(vbmeta)
        if d["partition"] == partition
    ]
    if len(descriptors) != 1:
        raise ImageError(
            f"expected exactly one {partition!r} HashDescriptor; found {len(descriptors)}"
        )
    d = descriptors[0]
    if d["algorithm"] != "sha256":
        raise ImageError(f"unsupported {partition} HashDescriptor algorithm: {d['algorithm']}")
    if d["image_size"] > len(payload):
        return False, (
            f"descriptor image_size {d['image_size']} exceeds payload size {len(payload)}"
        )
    actual = hashlib.sha256(d["salt"] + payload[:d["image_size"]]).digest()
    return actual == d["digest"], (
        f"SHA256(salt || payload[0:{d['image_size']}])="
        f"{actual.hex()}, descriptor={d['digest'].hex()}"
    )


def build_image(payload: bytes, template: bytes, target_size: int,
                partition: str, allow_hash_mismatch: bool) -> tuple[bytes, str]:
    _, _, _, src_offset, vbmeta_size, source_footer = parse_footer(template, "template")
    vbmeta = template[src_offset:src_offset + vbmeta_size]
    if len(vbmeta) != vbmeta_size:
        raise ImageError("short vbmeta extraction")
    matches, detail = check_payload_hash(payload, vbmeta, partition)
    if not matches and not allow_hash_mismatch:
        raise ImageError(
            f"{partition} HashDescriptor mismatch; refusing output. {detail}. "
            "Use --allow-hash-mismatch only for non-flashable research artifacts."
        )

    new_vbmeta_offset = len(payload)
    required = len(payload) + vbmeta_size + FOOTER_SIZE
    if required > target_size:
        raise ImageError(
            f"payload+vbmeta+footer needs {required} bytes; target is {target_size}"
        )
    footer = bytearray(source_footer)
    struct.pack_into(">Q", footer, 12, len(payload))
    struct.pack_into(">Q", footer, 20, new_vbmeta_offset)
    struct.pack_into(">Q", footer, 28, vbmeta_size)
    output = payload + vbmeta + bytes(target_size - required) + bytes(footer)
    # Read-back: prove the footer points at the exact preserved vbmeta bytes.
    _, _, original_size, out_offset, out_size, _ = parse_footer(output, "output")
    if original_size != len(payload) or out_offset != new_vbmeta_offset or out_size != vbmeta_size:
        raise ImageError("output footer read-back mismatch")
    if output[out_offset:out_offset + out_size] != vbmeta:
        raise ImageError("output vbmeta read-back mismatch")
    state = "HASH_MATCH" if matches else "HASH_MISMATCH_RESEARCH_ONLY"
    return output, f"{state}: {detail}"


def atomic_write(path: Path, data: bytes) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recovery_image", type=Path, help="input recovery image with AVB footer")
    parser.add_argument("--template", type=Path, default=Path(__file__).with_name("vivo_avb_footer.bin"))
    parser.add_argument("--output", type=Path, required=True, help="new output path; input is never overwritten")
    parser.add_argument("--target-size", type=int, default=DEFAULT_TARGET_SIZE)
    parser.add_argument("--partition", default="recovery", help="HashDescriptor partition name")
    parser.add_argument("--allow-hash-mismatch", action="store_true",
                        help="research only: emit despite payload hash mismatch; NOT AVB-valid")
    args = parser.parse_args(argv)
    try:
        if args.target_size < FOOTER_SIZE:
            raise ImageError("target size is smaller than AVB footer")
        if args.recovery_image.resolve() == args.output.resolve():
            raise ImageError("output path must differ from input path")
        recovery_data = args.recovery_image.read_bytes()
        _, _, _, recovery_vbmeta_offset, _, _ = parse_footer(recovery_data, "recovery input")
        payload = recovery_data[:recovery_vbmeta_offset]
        template = args.template.read_bytes()
        output, verdict = build_image(
            payload, template, args.target_size, args.partition, args.allow_hash_mismatch
        )
        atomic_write(args.output, output)
        print(f"Output: {args.output}")
        print(f"Bytes: {len(output)}")
        print(f"AVB: {verdict}")
        if "RESEARCH_ONLY" in verdict:
            print("WARNING: output does not satisfy the selected AVB HashDescriptor; do not flash.")
        return 0
    except (OSError, ImageError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
