#!/usr/bin/env python3
"""Regression test for the zeroed EXTRA_TYPE_NONE terminator written by kptools."""

from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "tools/patch.c").read_text()

def extract_function(text: str, signature: str) -> str:
    start = text.index(signature)
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

helper = extract_function(source, "static bool is_empty_extra_terminator(")
parser_start = source.index("while (remaining >= sizeof(patch_extra_item_t))")
parser_end = source.index("return 0;", parser_start)
parser = source[parser_start:parser_end]
assert parser.index("item->type == EXTRA_TYPE_NONE") < parser.index("memcmp(item->magic, EXTRA_HDR_MAGIC")
assert "is_empty_extra_terminator(item)" in parser
assert "for (size_t i = sizeof(*item); i < remaining; i++)" in parser

fixture = r"""
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef int32_t extra_item_type;
typedef struct {
    char magic[4];
    int32_t priority;
    int32_t args_size;
    int32_t con_size;
    extra_item_type type;
    char name[32];
    char event[32];
    int32_t flags;
} patch_extra_item_t;
""" + helper + r"""
int main(void) {
    patch_extra_item_t empty = {0};
    if (!is_empty_extra_terminator(&empty)) return 1;
    patch_extra_item_t bad_magic = {0};
    memcpy(bad_magic.magic, "kpe", 4);
    if (is_empty_extra_terminator(&bad_magic)) return 2;
    patch_extra_item_t nonzero_type = {0};
    nonzero_type.type = 1;
    if (is_empty_extra_terminator(&nonzero_type)) return 3;
    return 0;
}
"""
with tempfile.TemporaryDirectory() as td:
    c_file = Path(td) / "test.c"
    exe = Path(td) / "test"
    c_file.write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(c_file), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

print("PASS: zeroed extra terminator accepted; malformed terminators rejected")
