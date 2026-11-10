#!/usr/bin/env python3
"""Execute the real 4.14 SELinux pending-cred helpers from accctl.c."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def extract_function(source, signature):
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing function: {signature}")
    brace = source.find("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise RuntimeError(f"unterminated function: {signature}")


def main():
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("no host C compiler")
    source = (ROOT / "lkm/supercall/accctl.c").read_text(encoding="utf-8")
    gstart = source.find("typedef int (*kp_secctx_to_secid_fn_t)")
    gend = source.find("int kp_accctl_init(void)", gstart)
    if gstart < 0 or gend < 0:
        raise RuntimeError("missing production accctl globals")
    globals_source = source[gstart:gend]
    functions = "\n\n".join([
        extract_function(source, "int kp_accctl_init(void)"),
        extract_function(source, "static int kp_selinux_set_cred_context("),
        extract_function(source, "static void fill_caps("),
        extract_function(source, "static int su_cred("),
        extract_function(source, "int kp_apply_su_cred("),
        extract_function(source, "int kp_task_su("),
    ])
    prefix = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
typedef unsigned int u32;
typedef unsigned int uid_t;
typedef unsigned int kuid_t;
typedef unsigned int kgid_t;
typedef int pid_t;
typedef unsigned long kernel_cap_t;
#define SUPERCALL_SCONTEXT_LEN 0x60
#define INVALID_ID UINT32_MAX
static bool invalid_id_mapping;
static kuid_t make_kuid(int ns, uid_t uid) { (void)ns; return invalid_id_mapping ? INVALID_ID : uid; }
static kgid_t make_kgid(int ns, uid_t gid) { (void)ns; return invalid_id_mapping ? INVALID_ID : gid; }
#define uid_valid(id) ((id) != INVALID_ID)
#define gid_valid(id) ((id) != INVALID_ID)
#define KERNEL_VERSION(a,b,c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(4,14,141)
#define CONFIG_SECURITY_SELINUX 1
#define CAP_FULL_SET ((kernel_cap_t)0xffffUL)
#define ALL_ALLOW_SCONTEXT_MAGISK "u:r:magisk:s0"
struct cred {
    uid_t uid, euid, fsuid, suid;
    uid_t gid, egid, fsgid, sgid;
    kernel_cap_t cap_effective, cap_permitted, cap_inheritable;
    kernel_cap_t cap_bset, cap_ambient;
    void *security;
};
static int secctx_calls;

static int secctx_stub(const char *ctx, u32 len, u32 *sid)
{
    secctx_calls++;
    if (len != strlen(ctx) || strcmp(ctx, "u:r:magisk:s0"))
        return -EINVAL;
    *sid = 0x42;
    return 0;
}
static void *kp_resolve_symbol(const char *name)
{
    if (!strcmp(name, "security_secctx_to_secid"))
        return (void *)secctx_stub;
    if (!strcmp(name, "selinux_blob_sizes"))
        return NULL;
    return NULL;
}
static int current_user_ns(void) { return 0; }
#define logkw(...) ((void)0)
#define logki(...) ((void)0)
"""
    tests = r"""
int main(void)
{
    unsigned char pending_security[64] = {0};
    struct cred pending = { .security = pending_security };
    struct cred *cred = &pending;
    int rc;

    rc = kp_accctl_init();
    if (rc || kp_selinux_cred_offset != 0 || !kp_security_secctx_to_secid_fn) {
        fprintf(stderr, "4.14 legacy single-SELinux layout fallback failed: rc=%d offset=%d resolver=%p\n",
                rc, kp_selinux_cred_offset, (void *)kp_security_secctx_to_secid_fn);
        return 1;
    }
    puts("[PASS] upstream 4.14 single-SELinux cred blob uses offset zero when no vendor blob table exists");
    puts("[PASS] security_secctx_to_secid is resolved dynamically from KALLSYMS");

    rc = kp_apply_su_cred(&cred, 0, "u:r:magisk:s0");
    if (rc || cred != &pending || pending.uid || pending.euid ||
        pending.gid || pending.egid || pending.cap_effective != CAP_FULL_SET ||
        *(u32 *)(pending_security + 4) != 0x42 || secctx_calls != 1) {
        fprintf(stderr, "pending cred translabel failed: rc=%d uid=%u sid=%u\n",
                rc, pending.uid, *(u32 *)(pending_security + 4));
        return 1;
    }
    puts("[PASS] pending exec cred receives root IDs, full caps and Magisk SID");

    {
        char unterminated[SUPERCALL_SCONTEXT_LEN];
        unsigned char bad_security[64] = {0};
        struct cred bad = { .security = bad_security };
        struct cred *bad_ptr = &bad;
        int before_calls = secctx_calls;
        memset(unterminated, 'X', sizeof(unterminated));
        rc = kp_apply_su_cred(&bad_ptr, 0, unterminated);
        if (rc || bad_ptr != &kernel_cred || secctx_calls != before_calls) {
            fprintf(stderr, "unterminated fixed-size SELinux context was not rejected safely\\n");
            return 1;
        }
        puts("[PASS] unterminated fixed-size SELinux context is rejected without over-read");
    }

    {
        unsigned char bad_security[64] = {0};
        struct cred bad = { .security = bad_security };
        struct cred *bad_ptr = &bad;
        invalid_id_mapping = true;
        rc = kp_apply_su_cred(&bad_ptr, 0, "u:r:magisk:s0");
        invalid_id_mapping = false;
        if (rc != -EINVAL || bad_ptr != &bad || bad.uid || bad.cap_effective) {
            fprintf(stderr, "unmapped UID/GID was not rejected before cred mutation\\n");
            return 1;
        }
        puts("[PASS] unmapped UID/GID rejected before credential mutation");
    }

    if (kp_task_su(123, 0, "u:r:magisk:s0") != -EOPNOTSUPP) {
        fprintf(stderr, "cross-task SU did not fail closed\\n");
        return 1;
    }
    puts("[PASS] cross-task SU ABI is disabled fail-closed");

    {
        unsigned char bad_security[64] = {0};
        struct cred bad = { .security = bad_security };
        struct cred *bad_ptr = &bad;
        rc = kp_apply_su_cred(&bad_ptr, 0, "u:r:missing:s0");
        if (rc != -EINVAL || bad_ptr != &bad) {
            fprintf(stderr, "invalid SELinux context did not fail closed\\n");
            return 1;
        }
    }
    puts("[PASS] invalid SELinux context refuses SU commit and preserves caller ownership");
    return 0;
}
"""
    code = prefix + "\n" + globals_source + "\n" + functions + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="y73s-414-accctl-") as tmp:
        cfile = Path(tmp) / "accctl_cred.c"
        binary = Path(tmp) / "accctl_cred"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", str(cfile), "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] Y73S 4.14 pending SELinux credential fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
