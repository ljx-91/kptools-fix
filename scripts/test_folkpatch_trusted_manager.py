#!/usr/bin/env python3
"""Ensure the Y73s KPIMG trusts the exact supplied FolkPatch release signer."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "kernel/patch/android/userd.c").read_text(encoding="utf-8")
expected = "a9eba5b702eb55fb5f4b1a672a7133a16a7bcaea949cde43c812ef26c77de812"

match = re.search(
    r'"me\.yuki\.folk"\s*,\s*\{([^}]*)\}',
    source,
    re.S,
)
assert match, "trusted manager table must contain me.yuki.folk"
actual = "".join(re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))).lower()
assert actual == expected, f"FolkPatch signing digest mismatch: {actual}"
assert '"me.bmax.apatch"' not in source, "upstream APatch must not shadow FolkPatch"
assert '"com.example.apatch"' not in source, "demo manager must not be trusted"
assert len(bytes.fromhex(expected)) == 32
print("PASS: only the supplied FolkPatch signer is trusted by the Y73s KPIMG")
