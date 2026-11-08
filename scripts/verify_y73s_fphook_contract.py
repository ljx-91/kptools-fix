#!/usr/bin/env python3
"""Source regression checks for function-pointer hook patch failure handling."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
src = (root / "kernel/base/fphook.c").read_text()
hdr = (root / "kernel/include/hook.h").read_text()
acc = (root / "kernel/patch/common/accctl.c").read_text()
hmem = (root / "kernel/base/hmem.c").read_text()
hook = (root / "kernel/base/hook.c").read_text()
rcu = (root / "kernel/linux/include/linux/rcupdate.h").read_text()
start = (root / "kernel/base/start.c").read_text()

checks = {
    "CFI resolver accepts .cfi implementation": "suffix_is_cfi_jump_table(name + i + 1)" in start and "Keep the instrumented implementation (.cfi)" in start,
    "CFI resolver rejects .cfi_jt jump-table stub": "suffix[3] == '_' && suffix[4] == 'j' && suffix[5] == 't'" in start,
    "synchronize_rcu wrapper calls synchronize_rcu target": "static inline void synchronize_rcu(void)" in rcu and "kfunc_call(synchronize_rcu);" in rcu,
    "synchronize_rcu wrapper no longer maps to tasks rude barrier": "kfunc_call(rcu_barrier_tasks_rude)" not in rcu[rcu.index("static inline void synchronize_rcu(void)"):rcu.index("static inline unsigned long get_completed_synchronize_rcu")],
    "fp_hook returns hotpatch status": "return hotpatch((void **)addrs, values, 2);" in src,
    "fp_unhook returns hotpatch status": "return hotpatch((void **)addrs, values, 2);" in src and
        "int fp_unhook(uintptr_t fp_addr, void *backup)" in src,
    "public declarations return status": "int fp_hook(uintptr_t fp_addr, void *replace, void **backup);" in hdr and
        "int fp_unhook(uintptr_t fp_addr, void *backup);" in hdr,
    "origin backup saved before patch": src.index("*backup = (void *)original;") <
        src.index("return hotpatch((void **)addrs, values, 2);"),
    "chain preparation failure frees allocation": "if (err) {\n            hook_mem_free(chain);\n            return err;" in src,
    "uncertain install retains chain": "patch rollback uncertain" in src and
        "return -HOOK_PATCH_UNCERTAIN;" in src,
    "restore failure retains chain": "if (rc) {\n        logkv(\"Unwrap func pointer:" in src and
        "retaining chain memory" in src,
    "SELinux SID published after context string": acc.index("all_allow_sctx[sizeof(all_allow_sctx) - 1] =") <
        acc.index("WRITE_ONCE(all_allow_sid, sid);"),
    "SELinux SID consumers use READ_ONCE": "set_security_override(new, READ_ONCE(all_allow_sid))" in acc and
        "if (ssid == all_allow_sid)" not in acc and
        "if (all_allow_sid != SECSID_NULL)" not in acc,
    "retired hook slots are not reused": "warp->using = 2;" in hmem and
        "if ((wrap->using == 1 || wrap->using == 3) && wrap->addr == origin_addr)" in hmem,
    "inline hook retirement on successful restore": "hook_mem_retire(hook);" in hook and
        "hook_mem_retire(chain);" in hook,
    "function-pointer chain retirement on successful restore": "hook_mem_retire(chain);" in src,
}
for label, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + label)
if not all(checks.values()):
    raise SystemExit(1)
