import hashlib
import importlib.util
import struct
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "tools/y73s_avb/make_hybrid_recovery.py"
SPEC = importlib.util.spec_from_file_location("hybrid", MODULE_PATH)
hybrid = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hybrid)


def make_vbmeta(payload: bytes, partition=b"recovery") -> bytes:
    salt = b"pd2031-test-salt"
    digest = hashlib.sha256(salt + payload).digest()
    body = bytearray(116)
    struct.pack_into(">Q", body, 0, len(payload))
    body[8:40] = b"sha256" + bytes(26)
    name = partition
    struct.pack_into(">IIII", body, 40, len(name), len(salt), len(digest), 0)
    body.extend(name + salt + digest)
    body.extend(bytes((-len(body)) % 8))
    descriptor = struct.pack(">QQ", 2, len(body)) + body
    auth_size, aux_size = 0, 256 + len(descriptor)
    header = bytearray(256)
    header[:4] = b"AVB0"
    struct.pack_into(">QQ", header, 12, auth_size, aux_size)
    struct.pack_into(">QQ", header, 96, 256, len(descriptor))
    return bytes(header) + bytes(256) + descriptor


def make_footered(payload: bytes, vbmeta: bytes, target_size: int) -> bytes:
    footer = bytearray(64)
    footer[:4] = b"AVBf"
    vbmeta_offset = (len(payload) + 63) & ~63
    struct.pack_into(">IIQQQ", footer, 4, 1, 0, len(payload), vbmeta_offset, len(vbmeta))
    padding = target_size - vbmeta_offset - len(vbmeta) - 64
    return payload + bytes(vbmeta_offset - len(payload)) + vbmeta + bytes(padding) + footer


class HybridBuilderTests(unittest.TestCase):
    def test_extracts_vbmeta_at_footer_offset_not_zero(self):
        payload = b"recovery-payload"
        vbmeta = make_vbmeta(payload)
        template = make_footered(b"template-prefix", vbmeta, 2048)
        output, verdict = hybrid.build_image(payload, template, 2048, "recovery", False)
        self.assertIn("HASH_MATCH", verdict)
        _, _, original_size, offset, size, _ = hybrid.parse_footer(output, "test")
        self.assertEqual(original_size, len(payload))
        self.assertEqual(offset, (len(payload) + 63) & ~63)
        self.assertEqual(offset % 64, 0)
        self.assertEqual(size, len(vbmeta))
        self.assertEqual(output[offset:offset + size], vbmeta)

    def test_refuses_hash_mismatch_by_default(self):
        payload = b"changed-recovery"
        signed_payload = b"original-recovery"
        vbmeta = make_vbmeta(signed_payload)
        template = make_footered(b"prefix", vbmeta, 2048)
        with self.assertRaisesRegex(hybrid.ImageError, "HashDescriptor mismatch"):
            hybrid.build_image(payload, template, 2048, "recovery", False)

    def test_rejects_descriptor_size_that_does_not_cover_full_payload(self):
        payload = b"payload-with-tail"
        vbmeta = make_vbmeta(payload[:-4])
        template = make_footered(b"prefix", vbmeta, 2048)
        with self.assertRaisesRegex(hybrid.ImageError, "does not equal payload size"):
            hybrid.build_image(payload, template, 2048, "recovery", False)

    def test_explicit_override_is_marked_research_only(self):
        payload = b"changed-recovery"
        vbmeta = make_vbmeta(b"original-recovery")
        template = make_footered(b"prefix", vbmeta, 2048)
        _, verdict = hybrid.build_image(payload, template, 2048, "recovery", True)
        self.assertIn("HASH_MISMATCH_RESEARCH_ONLY", verdict)

    def test_rejects_bad_footer_bounds(self):
        blob = bytearray(make_footered(b"payload", make_vbmeta(b"payload"), 1024))
        struct.pack_into(">Q", blob, len(blob) - 64 + 20, 0xFFFFFFFF)
        with self.assertRaisesRegex(hybrid.ImageError, "outside pre-footer"):
            hybrid.parse_footer(bytes(blob), "bad")

    def test_rejects_oversized_output(self):
        payload = b"payload"
        vbmeta = make_vbmeta(payload)
        template = make_footered(b"prefix", vbmeta, 1024)
        with self.assertRaisesRegex(hybrid.ImageError, "needs"):
            hybrid.build_image(payload, template, 100, "recovery", False)


if __name__ == "__main__":
    unittest.main()
