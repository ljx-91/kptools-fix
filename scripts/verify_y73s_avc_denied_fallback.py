#!/usr/bin/env python3
"""Guard the exact Y73s 4.14.141 hidden avc_denied fallback.

The optional image argument validates the recovered original kernel.Image.
Without it, CI checks the C fingerprint, architecture/version/length gates,
caller-branch target, Android fail-closed wiring, and AVC hook ordering.
"""
from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FUNCTION_OFFSET = 0x0069141C
CALLER_OFFSET = 0x00691D74
IMAGE_SIZE = 47_517_708
IMAGE_SHA256 = "345bfab8217669cb84ed004916efea4fae06e6b169c70e1be2ec9ac3ad4f093e"
CALLER_BL = 0x97FFFDAA
EXPECTED = [
    0x37000166, 0xB000CE6B, 0xB948AD6B, 0x2A0203EA,
    0x2A0103E8, 0x2A0003E9, 0x340000EB, 0x394040EB,
    0x370000AB, 0x321C77E0, 0xD65F03C0, 0x321C77E0,
    0xD65F03C0, 0xD10083FF, 0xA9017BFD, 0x910043FD,
    0xB9400CE7, 0xB9000BE6, 0x320003E0, 0x2A0303E1,
    0x2A0403E2, 0x2A0503E3, 0x2A0903E4, 0x2A0803E5,
    0x2A0A03E6, 0xF90003FF, 0x97FFFECB, 0xA9417BFD,
    0x2A1F03E0, 0x910083FF, 0xD65F03C0,
]


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print("[PASS] " + message)


def branch_target(pc, insn):
    imm26 = insn & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return pc + (imm26 << 2)


def verify_image(data):
    require(len(data) == IMAGE_SIZE, "original Y73s Image length matches the exact build")
    require(hashlib.sha256(data).hexdigest() == IMAGE_SHA256,
            "original Y73s Image SHA-256 matches the recovered stock kernel")
    actual = [int.from_bytes(data[FUNCTION_OFFSET + i * 4:FUNCTION_OFFSET + i * 4 + 4],
                             "little") for i in range(len(EXPECTED))]
    require(actual == EXPECTED, "all 31 avc_denied entry instructions match")
    caller = int.from_bytes(data[CALLER_OFFSET:CALLER_OFFSET + 4], "little")
    require(caller == CALLER_BL, "caller instruction matches the expected ARM64 BL")
    require((caller & 0xFC000000) == 0x94000000 and
            branch_target(CALLER_OFFSET, caller) == FUNCTION_OFFSET,
            "caller BL resolves exactly to the fingerprinted avc_denied entry")


def main():
    symbol = (ROOT / "tools/symbol.c").read_text(encoding="utf-8")
    patch = (ROOT / "tools/patch.c").read_text(encoding="utf-8")
    accctl = (ROOT / "kernel/patch/common/accctl.c").read_text(encoding="utf-8")

    helper = symbol.split("static int32_t resolve_y73s_avc_denied_fingerprint(", 1)[1].split(
        "int fillin_patch_config(", 1
    )[0]
    array = re.search(r"static const uint32_t expected\[\]\s*=\s*\{(.*?)\};", helper, re.S)
    require(array is not None, "Y73s avc_denied fingerprint array exists")
    source_words = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", array.group(1))]
    require(source_words == EXPECTED, "C fingerprint exactly matches the independently verified 31-word sequence")
    for token, message in [
        ("kallsym->arch != ARM64", "fallback is ARM64-only"),
        ("kallsym->version.major != 4", "fallback requires Linux 4.14 major"),
        ("kallsym->version.minor != 14", "fallback requires Linux 4.14 minor"),
        ("kallsym->version.patch != 141", "fallback requires Linux 4.14.141 patchlevel"),
        ("imglen != 47517708", "fallback requires the exact original Image length"),
        ("target_is_be", "fallback rejects big-endian images"),
        ("aarch64_insn_is_bl(caller)", "fallback validates the caller instruction is BL"),
        ("(int64_t)caller_offset + aarch64_get_branch_offset(caller) != function_offset",
         "fallback validates the caller BL target equals the candidate entry"),
    ]:
        require(token in helper, message)

    assignment = symbol.split('symbol->avc_denied = try_get_symbol_offset_zero', 1)[1].split(
        'symbol->slow_avc_audit', 1
    )[0]
    require("resolve_y73s_avc_denied_fingerprint" in assignment and
            assignment.index("resolve_y73s_avc_denied_fingerprint") <
            assignment.index('if (!symbol->avc_denied && is_android)'),
            "fingerprinted fallback runs before Android's fail-closed avc_denied requirement")
    require("fillin_patch_config(&kallsym, kallsym_kimg, ori_kimg_len, &setup->patch_config, "
            "kinfo->is_be, is_android);" in patch,
            "kptools passes the actual Android image flag into patch-config validation")

    avc = accctl.split("int bypass_selinux()", 1)[1]
    require("patch_config->avc_denied" in avc and
            avc.index("return 0;") < avc.index("patch_config->slow_avc_audit"),
            "avc_denied is the primary SELinux decision hook")
    require("patch_config->slow_avc_audit" in avc,
            "slow_avc_audit remains a secondary audit fallback, not a permission-decision substitute")
    require("slow_avc_audit runs after the SELinux decision" in avc and
            "return primary_rc;" in avc[avc.index("patch_config->slow_avc_audit"):],
            "secondary audit hook never masks a missing or failed SELinux decision hook")
    require("avd = (struct av_decision *)_flags;" in accctl and
            "if ((uint64_t)_state <= 0xffffffffL)" in accctl,
            "AVC replacement preserves the legacy eight-register Y73s argument layout")

    if len(sys.argv) > 1:
        verify_image(Path(sys.argv[1]).read_bytes())
    else:
        require(branch_target(CALLER_OFFSET, CALLER_BL) == FUNCTION_OFFSET,
                "recorded caller BL target matches the fallback function offset")
    print("[PASS] Y73s avc_denied fallback audit complete")


if __name__ == "__main__":
    main()
