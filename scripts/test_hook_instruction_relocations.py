#!/usr/bin/env python3
"""Compile and execute the real AArch64 inline-hook relocation paths from hook.c.

This is a host-side unit test of generated instruction words and relocated
literal/branch targets. It is not an AArch64 CPU emulator or device test.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HOOK_SOURCE = ROOT / "kernel/base/hook.c"


def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"function not found: {signature}")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError(f"function body not found: {signature}")

    depth = 0
    pos = brace
    while pos < len(source):
        if source.startswith("//", pos):
            end = source.find("\n", pos)
            pos = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                raise RuntimeError("unterminated C comment")
            pos = end + 2
            continue
        if source[pos] == '"':
            pos += 1
            while pos < len(source):
                if source[pos] == "\\":
                    pos += 2
                elif source[pos] == '"':
                    pos += 1
                    break
                else:
                    pos += 1
            continue
        if source[pos] == "'":
            pos += 1
            while pos < len(source):
                if source[pos] == "\\":
                    pos += 2
                elif source[pos] == "'":
                    pos += 1
                    break
                else:
                    pos += 1
            continue
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
        pos += 1
    raise RuntimeError(f"unterminated function: {signature}")


def build_harness(source_text: str) -> str:
    definitions_start = source_text.index("typedef uint32_t inst_type_t;")
    definitions_end = source_text.index("// static uint64_t sign_extend", definitions_start)
    definitions = source_text[definitions_start:definitions_end]

    signatures = [
        "static int32_t relo_inst_len(",
        "static int is_in_tramp(",
        "static int is_page_in_tramp(",
        "static uint64_t relo_in_tramp(",
        "static hook_err_t relo_branch_pc(",
        "static hook_err_t relo_branch_at(",
        "static hook_err_t relo_call_at(",
        "static __noinline hook_err_t relo_b(",
        "static __noinline hook_err_t relo_adr(",
        "static __noinline hook_err_t relo_ldr(",
        "static __noinline hook_err_t relo_cb(",
        "static __noinline hook_err_t relo_tb(",
        "static __noinline hook_err_t relo_ignore(",
        "static uint32_t can_b_rel(",
        "int32_t branch_relative(",
        "int32_t branch_absolute(",
        "int32_t ret_absolute(",
        "int32_t branch_from_to(",
        "static __noinline hook_err_t relocate_inst(",
    ]
    functions = "\n\n".join(extract_function(source_text, item) for item in signatures)

    prefix = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

typedef int hook_err_t;

#define HOOK_NO_ERR 0
#define HOOK_BAD_RELO 17
#define ARM64_NOP 0xD503201FU
#define __noinline

#define bits32(n, high, low) \
    ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? \
     ((n) | (0xFFFFFFFFFFFFFFFFULL << (len))) : (n))

"""
    harness = r"""

#define CHECK(expr, label) do { \
    if (!(expr)) { \
        fprintf(stderr, "[FAIL] %s (line %d)\n", label, __LINE__); \
        return 1; \
    } \
    printf("[PASS] %s\n", label); \
} while (0)

static void init_hook(hook_t *hook, uint64_t origin, uint64_t relo)
{
    memset(hook, 0, sizeof(*hook));
    hook->origin_addr = origin;
    hook->relo_addr = relo;
    hook->tramp_insts_num = 4;
}

static uint64_t literal64(const hook_t *hook, unsigned int word)
{
    return (uint64_t)hook->relo_insts[word] |
           ((uint64_t)hook->relo_insts[word + 1] << 32);
}

static uint32_t encode_imm19(uint32_t opcode, int32_t byte_offset)
{
    return opcode | ((((uint32_t)(byte_offset >> 2)) & 0x7ffffU) << 5);
}

static uint32_t encode_imm26(uint32_t opcode, int32_t byte_offset)
{
    return opcode | (((uint32_t)(byte_offset >> 2)) & 0x03ffffffU);
}

static uint32_t encode_adr(unsigned int rd, int32_t byte_offset)
{
    uint32_t imm = (uint32_t)byte_offset & 0x1fffffU;
    return 0x10000000U | ((imm & 3U) << 29) |
           (((imm >> 2) & 0x7ffffU) << 5) | (rd & 31U);
}

static uint32_t encode_adrp(unsigned int rd, int32_t page_offset)
{
    uint32_t imm = (uint32_t)page_offset & 0x1fffffU;
    return 0x90000000U | ((imm & 3U) << 29) |
           (((imm >> 2) & 0x7ffffU) << 5) | (rd & 31U);
}

static uint32_t encode_literal(uint32_t opcode, unsigned int rt,
                              int32_t byte_offset)
{
    return opcode | ((((uint32_t)(byte_offset >> 2)) & 0x7ffffU) << 5) |
           (rt & 31U);
}

static uint64_t decode_b_target(uint64_t pc, uint32_t inst)
{
    int64_t imm = (int64_t)(inst & 0x03ffffffU);
    if (imm & 0x02000000LL) imm -= 0x04000000LL;
    return pc + (uint64_t)(imm * 4);
}

static uint64_t decode_cond_target(uint64_t pc, uint32_t inst)
{
    int64_t imm = (int64_t)((inst >> 5) & 0x7ffffU);
    if (imm & 0x40000LL) imm -= 0x80000LL;
    return pc + (uint64_t)(imm * 4);
}

static uint64_t decode_tb_target(uint64_t pc, uint32_t inst)
{
    int64_t imm = (int64_t)((inst >> 5) & 0x3fffU);
    if (imm & 0x2000LL) imm -= 0x4000LL;
    return pc + (uint64_t)(imm * 4);
}

static int test_b_internal_remap(void)
{
    hook_t h;
    uint32_t b = encode_imm26(0x14000000U, 4);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = b;
    CHECK(relocate_inst(&h, h.origin_addr, b) == HOOK_NO_ERR, "B relocation succeeds");
    CHECK(h.relo_insts_num == 2, "B expands to a two-word direct branch sequence");
    CHECK((h.relo_insts[0] & 0xFC000000U) == 0x14000000U &&
          decode_b_target(h.relo_addr, h.relo_insts[0]) == h.relo_addr + 8,
          "B maps an internal target with no X16/X17 scratch clobber");
    CHECK(h.relo_insts[1] == ARM64_NOP, "B leaves aligned fall-through padding");
    return 0;
}

static int test_bl_and_conditional_branch(void)
{
    hook_t h;
    uint32_t bl = encode_imm26(0x94000000U, 0x200);
    init_hook(&h, 0x10000000ULL, 0x18000000ULL);
    h.origin_insts[0] = bl;
    CHECK(relocate_inst(&h, h.origin_addr, bl) == HOOK_NO_ERR, "BL relocation succeeds");
    CHECK(h.relo_insts_num == 8, "BL keeps an eight-word padded sequence for stable mapping");
    CHECK((h.relo_insts[0] & 0xFC000000U) == 0x94000000U &&
          decode_b_target(h.relo_addr, h.relo_insts[0]) == h.origin_addr + 0x200,
          "BL encodes a direct call without using X16/X17");
    CHECK(h.relo_insts[1] == ARM64_NOP && h.relo_insts[7] == ARM64_NOP,
          "BL padding returns to the next relocated instruction");

    uint32_t bc = encode_imm19(0x54000001U, 4);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = bc;
    CHECK(relocate_inst(&h, h.origin_addr, bc) == HOOK_NO_ERR,
          "B.cond relocation succeeds");
    CHECK(h.relo_insts_num == 2, "B.cond expands to two direct-branch words");
    CHECK(h.relo_insts[0] == (((bc & 0xFF00001FU) | 0x40U) ^ 1U) &&
          decode_cond_target(h.relo_addr, h.relo_insts[0]) == h.relo_addr + 8,
          "B.cond inverts condition to skip the B on the original not-taken path");
    CHECK((h.relo_insts[1] & 0xFC000000U) == 0x14000000U &&
          decode_b_target(h.relo_addr + 4, h.relo_insts[1]) == h.relo_addr + 8,
          "B.cond taken edge uses a register-preserving direct B");

    return 0;
}

static int test_adr_and_adrp(void)
{
    hook_t h;
    uint32_t adr = encode_adr(9, 0x1234);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = adr;
    CHECK(relocate_inst(&h, h.origin_addr, adr) == HOOK_NO_ERR, "ADR relocation succeeds");
    CHECK(h.relo_insts_num == 4, "ADR expands to four words");
    CHECK(literal64(&h, 2) == h.origin_addr + 0x1234,
          "ADR embeds the original absolute address");

    uint32_t adr_internal = encode_adr(3, 8);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = adr_internal;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, adr_internal) == -HOOK_BAD_RELO,
          "ADR into overwritten prologue is rejected");
    CHECK(h.relo_insts[0] == 0xA5A5A5A5U && h.relo_insts_num == 0,
          "rejected ADR leaves relocation output untouched");

    uint32_t adrp = encode_adrp(12, 2);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = adrp;
    CHECK(relocate_inst(&h, h.origin_addr, adrp) == HOOK_NO_ERR, "ADRP outside trampoline page succeeds");
    CHECK(literal64(&h, 2) == 0x10002000ULL, "ADRP embeds its 4-KiB page address");

    uint32_t adrp_overlap = encode_adrp(12, 0);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = adrp_overlap;
    CHECK(relocate_inst(&h, h.origin_addr, adrp_overlap) == -HOOK_BAD_RELO,
          "ADRP page overlapping overwritten prologue is rejected");
    return 0;
}

static int test_scalar_literal_loads(void)
{
    hook_t h;
    uint32_t ldr_x0 = encode_literal(0x58000000U, 0, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_x0;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_x0) == HOOK_NO_ERR,
          "LDR X0 literal relocation succeeds");
    CHECK(h.relo_insts_num == 6, "LDR X0 expands to six words");
    CHECK(h.relo_insts[0] == 0x58000080U &&
          h.relo_insts[1] == 0xF9400000U &&
          h.relo_insts[2] == 0x14000004U,
          "LDR X0 veneer uses address load, memory load and literal skip");
    CHECK(literal64(&h, 4) == h.origin_addr + 0x1000,
          "LDR X0 literal points to the original data");

    uint32_t ldr_w5 = encode_literal(0x18000000U, 5, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_w5;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_w5) == HOOK_NO_ERR,
          "LDR W5 literal relocation succeeds");
    CHECK(h.relo_insts[0] == 0x58000085U &&
          h.relo_insts[1] == 0xB94000A5U &&
          literal64(&h, 4) == h.origin_addr + 0x1000,
          "LDR W5 widens its address load and preserves W-register semantics");

    uint32_t ldrsw_x3 = encode_literal(0x98000000U, 3, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldrsw_x3;
    CHECK(relocate_inst(&h, h.origin_addr, ldrsw_x3) == HOOK_NO_ERR,
          "LDRSW X3 literal relocation succeeds");
    CHECK(h.relo_insts[1] == 0xB9800063U,
          "LDRSW X3 uses signed word load into the destination register");

    uint32_t ldr_xzr = encode_literal(0x58000000U, 31, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_xzr;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_xzr) == HOOK_NO_ERR,
          "LDR XZR literal relocation succeeds");
    CHECK(h.relo_insts_num == 7, "LDR XZR uses its seven-word special expansion");
    CHECK(h.relo_insts[0] == 0xA9BF47F0U &&
          h.relo_insts[1] == 0x58000091U &&
          h.relo_insts[2] == 0xF940023FU &&
          h.relo_insts[3] == 0xA8C147F0U &&
          h.relo_insts[4] == 0x14000003U,
          "LDR XZR preserves X16/X17 and performs the zero-register load");
    CHECK(literal64(&h, 5) == h.origin_addr + 0x1000,
          "LDR XZR literal is stored after the control sequence");

    uint32_t ldr_wzr = encode_literal(0x18000000U, 31, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_wzr;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_wzr) == HOOK_NO_ERR,
          "LDR WZR literal relocation succeeds");
    CHECK(h.relo_insts_num == 7 && h.relo_insts[2] == 0xB940023FU,
          "LDR WZR performs the actual 32-bit memory access");

    uint32_t ldrsw_wzr = encode_literal(0x98000000U, 31, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldrsw_wzr;
    CHECK(relocate_inst(&h, h.origin_addr, ldrsw_wzr) == HOOK_NO_ERR,
          "LDRSW XZR literal relocation succeeds");
    CHECK(h.relo_insts[2] == 0xB980023FU,
          "LDRSW XZR uses the sign-extending memory operation");
    return 0;
}

static int test_prefetch_and_simd_literals(void)
{
    hook_t h;
    uint32_t prfm = encode_literal(0xD8000000U, 5, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = prfm;
    CHECK(relocate_inst(&h, h.origin_addr, prfm) == HOOK_NO_ERR,
          "PRFM literal relocation succeeds");
    CHECK(h.relo_insts_num == 8 && h.relo_insts[2] == 0xF9800225U,
          "PRFM emits the matching register hint");
    CHECK(literal64(&h, 6) == h.origin_addr + 0x1000,
          "PRFM veneer contains the original address");

    uint32_t ldr_s4 = encode_literal(0x1C000000U, 4, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_s4;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_s4) == HOOK_NO_ERR,
          "LDR S4 literal relocation succeeds");
    CHECK(h.relo_insts[2] == 0xBD400224U,
          "SIMD scalar single-precision load uses the S-register opcode");

    uint32_t ldr_d6 = encode_literal(0x5C000000U, 6, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_d6;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_d6) == HOOK_NO_ERR,
          "LDR D6 literal relocation succeeds");
    CHECK(h.relo_insts[2] == 0xFD400226U,
          "SIMD double-precision load uses the D-register opcode");

    uint32_t ldr_q17 = encode_literal(0x9C000000U, 17, 0x1000);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_q17;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_q17) == HOOK_NO_ERR,
          "LDR Q17 literal relocation succeeds");
    CHECK(h.relo_insts_num == 8 && h.relo_insts[2] == 0x3DC00231U,
          "SIMD 128-bit load uses the Q-register operation");
    CHECK(h.relo_insts[0] == 0xA9BF47F0U &&
          h.relo_insts[3] == 0xA8C147F0U,
          "SIMD literal veneer restores scratch registers");
    CHECK(literal64(&h, 6) == h.origin_addr + 0x1000,
          "SIMD veneer contains the original literal address");
    return 0;
}

static int test_compare_and_test_branches(void)
{
    hook_t h;
    uint32_t cbz = encode_imm19(0x34000005U, 8);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = cbz;
    h.origin_insts[1] = ARM64_NOP;
    CHECK(relocate_inst(&h, h.origin_addr, cbz) == HOOK_NO_ERR, "CBZ relocation succeeds");
    CHECK(h.relo_insts_num == 2, "CBZ expands to two direct-branch words");
    CHECK(h.relo_insts[0] == (((cbz ^ 0x01000000U) & 0xFF00001FU) | 0x40U) &&
          decode_cond_target(h.relo_addr, h.relo_insts[0]) == h.relo_addr + 8,
          "CBZ inversion skips the B only when the original condition is false");
    CHECK((h.relo_insts[1] & 0xFC000000U) == 0x14000000U &&
          decode_b_target(h.relo_addr + 4, h.relo_insts[1]) == h.relo_addr + 16,
          "CBZ taken edge uses a scratch-free direct B");

    uint32_t cbnz = encode_imm19(0x35000005U, 8);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = cbnz;
    h.origin_insts[1] = ARM64_NOP;
    CHECK(relocate_inst(&h, h.origin_addr, cbnz) == HOOK_NO_ERR,
          "CBNZ relocation succeeds");
    CHECK(h.relo_insts[0] == (((cbnz ^ 0x01000000U) & 0xFF00001FU) | 0x40U) &&
          decode_cond_target(h.relo_addr, h.relo_insts[0]) == h.relo_addr + 8 &&
          decode_b_target(h.relo_addr + 4, h.relo_insts[1]) == h.relo_addr + 16,
          "CBNZ inversion and direct B preserve both control-flow paths");

    uint32_t tbz = 0x36000000U | (9U << 19) | (2U << 5) | 3U;
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = tbz;
    h.origin_insts[1] = ARM64_NOP;
    CHECK(relocate_inst(&h, h.origin_addr, tbz) == HOOK_NO_ERR,
          "TBZ relocation succeeds");
    CHECK(h.relo_insts[0] == (((tbz ^ 0x01000000U) & 0xFFF8001FU) | 0x40U) &&
          decode_tb_target(h.relo_addr, h.relo_insts[0]) == h.relo_addr + 8 &&
          decode_b_target(h.relo_addr + 4, h.relo_insts[1]) == h.relo_addr + 16,
          "TBZ inversion preserves tested bit and uses a scratch-free B");

    uint32_t tbnz = 0x37000000U | (9U << 19) | (2U << 5) | 3U;
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = tbnz;
    h.origin_insts[1] = ARM64_NOP;
    CHECK(relocate_inst(&h, h.origin_addr, tbnz) == HOOK_NO_ERR, "TBNZ relocation succeeds");
    CHECK(h.relo_insts_num == 2, "TBNZ expands to two direct-branch words");
    CHECK(h.relo_insts[0] == (((tbnz ^ 0x01000000U) & 0xFFF8001FU) | 0x40U) &&
          decode_tb_target(h.relo_addr, h.relo_insts[0]) == h.relo_addr + 8 &&
          decode_b_target(h.relo_addr + 4, h.relo_insts[1]) == h.relo_addr + 16,
          "TBNZ preserves bit index and both control-flow edges without scratch registers");
    return 0;
}

static int test_internal_mapping_special_length_and_unknown(void)
{
    hook_t h;
    uint32_t ldr_into_prologue = encode_literal(0x58000000U, 2, 8);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_into_prologue;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, ldr_into_prologue) == -HOOK_BAD_RELO,
          "literal data load into overwritten prologue is rejected");
    CHECK(h.relo_insts_num == 0 && h.relo_insts[0] == 0xA5A5A5A5U,
          "rejected literal load leaves relocation output untouched");

    uint32_t prfm_into_prologue = encode_literal(0xD8000000U, 2, 8);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = prfm_into_prologue;
    h.origin_insts[1] = ARM64_NOP;
    CHECK(relocate_inst(&h, h.origin_addr, prfm_into_prologue) == HOOK_NO_ERR,
          "PRFM into overwritten prologue is remapped");
    CHECK(literal64(&h, 6) == h.relo_addr + 40,
          "PRFM target follows expanded instructions in the relocated range");

    uint32_t ldr_xzr = encode_literal(0x58000000U, 31, 0x1000);
    uint32_t b_to_next = encode_imm26(0x14000000U, 4);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ldr_xzr;
    h.origin_insts[1] = b_to_next;
    CHECK(relo_in_tramp(&h, h.origin_addr + 4) == h.relo_addr + 28,
          "internal target map accounts for seven-word XZR expansion");
    h.relo_insts_num = 7;
    CHECK(relocate_inst(&h, h.origin_addr + 4, b_to_next) == HOOK_NO_ERR,
          "branch following XZR special expansion relocates");
    CHECK(decode_b_target(h.relo_addr + 28, h.relo_insts[7]) == h.relo_addr + 36 &&
          h.relo_insts[8] == ARM64_NOP,
          "following B preserves registers and remaps the target after expanded instructions");

    uint32_t nop = ARM64_NOP;
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = nop;
    CHECK(relocate_inst(&h, h.origin_addr, nop) == HOOK_NO_ERR,
          "unclassified instruction uses passthrough relocation");
    CHECK(h.relo_insts_num == 2 && h.relo_insts[0] == nop &&
          h.relo_insts[1] == ARM64_NOP,
          "passthrough preserves instruction and appends padding NOP");
    return 0;
}

static int test_negative_pc_relative_branch(void)
{
    hook_t h;
    uint32_t negative_b = encode_imm26(0x14000000U, -4);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ARM64_NOP;
    h.origin_insts[1] = ARM64_NOP;
    h.origin_insts[2] = negative_b;
    h.relo_insts_num = 4;
    CHECK(relocate_inst(&h, h.origin_addr + 8, negative_b) == HOOK_NO_ERR,
          "negative B relocation sign-extends its displacement");
    CHECK(decode_b_target(h.relo_addr + 16, h.relo_insts[4]) == h.relo_addr + 8,
          "negative B target maps backward into the relocated prologue");

    uint32_t negative_bc = encode_imm19(0x54000001U, -4);
    init_hook(&h, 0x10000000ULL, 0x20000000ULL);
    h.origin_insts[0] = ARM64_NOP;
    h.origin_insts[1] = ARM64_NOP;
    h.origin_insts[2] = negative_bc;
    h.relo_insts_num = 4;
    CHECK(relocate_inst(&h, h.origin_addr + 8, negative_bc) == HOOK_NO_ERR,
          "negative B.cond relocation sign-extends its displacement");
    CHECK(decode_cond_target(h.relo_addr + 16, h.relo_insts[4]) == h.relo_addr + 24 &&
          decode_b_target(h.relo_addr + 20, h.relo_insts[5]) == h.relo_addr + 8,
          "negative B.cond preserves the not-taken edge and remaps the taken edge");
    return 0;
}

static int test_out_of_range_control_flow_rejected(void)
{
    hook_t h;
    uint32_t b = encode_imm26(0x14000000U, 0x200);
    uint32_t bc = encode_imm19(0x54000001U, 0x200);
    uint32_t cbz = encode_imm19(0x34000001U, 0x200);
    uint32_t tbz = 0x36000000U | ((0x200U >> 2) << 5) | 1U;

    init_hook(&h, 0x10000000ULL, 0x90000000ULL);
    h.origin_insts[0] = b;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, b) == -HOOK_BAD_RELO &&
          h.relo_insts_num == 0 && h.relo_insts[0] == 0xA5A5A5A5U,
          "out-of-range B fails closed without modifying relocation output");

    uint32_t bl = encode_imm26(0x94000000U, 0x200);
    init_hook(&h, 0x10000000ULL, 0x90000000ULL);
    h.origin_insts[0] = bl;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, bl) == -HOOK_BAD_RELO &&
          h.relo_insts_num == 0 && h.relo_insts[0] == 0xA5A5A5A5U,
          "out-of-range BL fails closed without an X17 absolute call veneer");

    init_hook(&h, 0x10000000ULL, 0x90000000ULL);
    h.origin_insts[0] = bc;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, bc) == -HOOK_BAD_RELO &&
          h.relo_insts_num == 0 && h.relo_insts[0] == 0xA5A5A5A5U,
          "out-of-range B.cond fails closed before writing an inverted condition");

    init_hook(&h, 0x10000000ULL, 0x90000000ULL);
    h.origin_insts[0] = cbz;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, cbz) == -HOOK_BAD_RELO &&
          h.relo_insts_num == 0 && h.relo_insts[0] == 0xA5A5A5A5U,
          "out-of-range CBZ fails closed without emitting a scratch-register veneer");

    init_hook(&h, 0x10000000ULL, 0x90000000ULL);
    h.origin_insts[0] = tbz;
    h.relo_insts[0] = 0xA5A5A5A5U;
    CHECK(relocate_inst(&h, h.origin_addr, tbz) == -HOOK_BAD_RELO &&
          h.relo_insts_num == 0 && h.relo_insts[0] == 0xA5A5A5A5U,
          "out-of-range TBZ fails closed without modifying relocation output");
    return 0;
}

static int test_branch_back_encodings(void)
{
    uint32_t words[8];
    uint64_t src = 0x20000000ULL;
    uint64_t dst;

    CHECK(can_b_rel(src, src + 0x07FFFFFCULL),
          "B positive range maximum is accepted");
    CHECK(!can_b_rel(src, src + 0x08000000ULL),
          "B positive out-of-range target is rejected");
    CHECK(can_b_rel(src, src - 0x08000000ULL),
          "B negative range minimum is accepted");
    CHECK(!can_b_rel(src, src - 0x08000004ULL),
          "B negative out-of-range target is rejected");
    CHECK(!can_b_rel(src, src + 2) && !can_b_rel(src + 2, src + 4),
          "B rejects unaligned source or destination");

    memset(words, 0xA5, sizeof(words));
    dst = src + 0x07FFFFFCULL;
    CHECK(branch_relative(words, src, dst) == 2,
          "branch_relative emits a two-word in-range branch");
    CHECK(words[0] == 0x15FFFFFFU && words[1] == ARM64_NOP,
          "positive maximum branch encodes the signed imm26 boundary");

    memset(words, 0xA5, sizeof(words));
    dst = src - 0x08000000ULL;
    CHECK(branch_relative(words, src, dst) == 2,
          "branch_relative emits the negative range boundary");
    CHECK(words[0] == 0x16000000U && words[1] == ARM64_NOP,
          "negative minimum branch encodes the signed imm26 boundary");

    memset(words, 0xA5, sizeof(words));
    CHECK(branch_relative(words, src, src + 0x08000000ULL) == 0 &&
          words[0] == 0xA5A5A5A5U,
          "out-of-range relative branch leaves output untouched");

    memset(words, 0, sizeof(words));
    CHECK(branch_from_to(words, src, src + 0x100) == 2 &&
          words[0] == 0x14000040U && words[1] == ARM64_NOP,
          "branch-back uses the relative form when reachable");

    memset(words, 0xA5, sizeof(words));
    CHECK(branch_from_to(words, src, src + 0x08000000ULL) == 0,
          "out-of-range branch-back is rejected instead of clobbering X17");
    CHECK(words[0] == 0xA5A5A5A5U && words[1] == 0xA5A5A5A5U,
          "rejected branch-back leaves the output untouched");

    memset(words, 0, sizeof(words));
    CHECK(branch_absolute(words, 0xFFFFFFC012345678ULL) == 4 &&
          words[0] == 0x58000051U && words[1] == 0xD61F0220U &&
          ((uint64_t)words[2] | ((uint64_t)words[3] << 32)) ==
              0xFFFFFFC012345678ULL,
          "entry patch absolute branch embeds the full 64-bit destination");
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= test_b_internal_remap();
    failed |= test_bl_and_conditional_branch();
    failed |= test_adr_and_adrp();
    failed |= test_scalar_literal_loads();
    failed |= test_prefetch_and_simd_literals();
    failed |= test_compare_and_test_branches();
    failed |= test_internal_mapping_special_length_and_unknown();
    failed |= test_negative_pc_relative_branch();
    failed |= test_branch_back_encodings();
    failed |= test_out_of_range_control_flow_rejected();
    if (failed) return 1;
    puts("[PASS] hook.c AArch64 instruction relocation paths executed");
    return 0;
}
"""
    return prefix + definitions + r"""
typedef struct hook {
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    uint32_t tramp_insts_num;
    uint32_t origin_insts[16];
    int32_t relo_insts_num;
    uint32_t relo_insts[256];
} hook_t;
""" + functions + harness


def main() -> int:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        raise SystemExit("no host C compiler (cc/gcc/clang) available")

    source_text = HOOK_SOURCE.read_text(encoding="utf-8")
    generated = build_harness(source_text)

    with tempfile.TemporaryDirectory(prefix="kp-hook-reloc-test-") as tmp:
        tmpdir = Path(tmp)
        c_file = tmpdir / "hook_relocation_test.c"
        binary = tmpdir / "hook_relocation_test"
        c_file.write_text(generated, encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", "-Wno-sign-compare",
             str(c_file), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)

    print("[PASS] actual hook.c relocation functions compiled and executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
