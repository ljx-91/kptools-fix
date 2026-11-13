#!/usr/bin/env python3
"""Keep the ARM64 pid_vnr CFI branch-stub resolver used by the Y73s kernel."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "tools/kallsym.c").read_text()

def extract_function(text: str, signature: str) -> str:
    start = text.rindex(signature)
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError("unterminated function: " + signature)

fn = extract_function(source, "static int arm64_verify_pid_vnr(")
required = [
    "aarch64_insn_is_b(first)",
    "aarch64_get_branch_offset(first)",
    "target >= 0",
    "target + 4 <= imglen",
    "offset = (int32_t)target",
    "pid_vnr is CFI stub, follow branch to offset",
]
for token in required:
    assert token in fn, f"pid_vnr CFI-stub resolver lost required guard: {token}"

print("PASS: pid_vnr CFI branch stubs are followed with image bounds checks")
