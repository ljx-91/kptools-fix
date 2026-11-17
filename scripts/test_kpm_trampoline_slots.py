#!/usr/bin/env python3
"""Host-execute the production KPM callback trampoline slot allocator."""
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

    source = (ROOT / "lkm/kpm/module.c").read_text(encoding="utf-8")
    allocator = extract_function(source, "static int kp_callback_tramp_slot_alloc(")
    release = extract_function(source, "static void kp_callback_tramp_slot_free(")

    prefix = r"""
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAGE_SIZE 4096UL
#define BITS_PER_LONG 64UL
#define KP_CALLBACK_TRAMP_SLOT_SIZE 16UL
#define KP_CALLBACK_TRAMP_SLOT_COUNT (PAGE_SIZE / KP_CALLBACK_TRAMP_SLOT_SIZE)
static pthread_mutex_t module_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long kp_callback_tramp_slots[
    (KP_CALLBACK_TRAMP_SLOT_COUNT + BITS_PER_LONG - 1) / BITS_PER_LONG];
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; pthread_mutex_lock(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); pthread_mutex_unlock(lock); } while (0)
"""

    tests = r"""
#define THREADS 32
#define SLOTS_PER_THREAD (KP_CALLBACK_TRAMP_SLOT_COUNT / THREADS)
static unsigned long allocated[KP_CALLBACK_TRAMP_SLOT_COUNT];
static int thread_rc[THREADS];
static pthread_barrier_t start_barrier;

struct worker_arg { unsigned int id; };

static void *allocate_worker(void *opaque)
{
    struct worker_arg *arg = opaque;
    unsigned int base = arg->id * SLOTS_PER_THREAD;
    (void)pthread_barrier_wait(&start_barrier);
    for (unsigned int i = 0; i < SLOTS_PER_THREAD; ++i) {
        unsigned long slot = (unsigned long)-1;
        int rc = kp_callback_tramp_slot_alloc(&slot);
        if (rc || slot >= KP_CALLBACK_TRAMP_SLOT_COUNT) {
            thread_rc[arg->id] = rc ? rc : -1;
            return NULL;
        }
        allocated[base + i] = slot;
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    struct worker_arg args[THREADS];
    bool seen[KP_CALLBACK_TRAMP_SLOT_COUNT] = { false };
    unsigned long extra = (unsigned long)-1, replacement = (unsigned long)-1;
    int rc;

    if (pthread_barrier_init(&start_barrier, NULL, THREADS)) return 1;
    for (unsigned int i = 0; i < THREADS; ++i) {
        args[i].id = i;
        if (pthread_create(&threads[i], NULL, allocate_worker, &args[i])) return 1;
    }
    for (unsigned int i = 0; i < THREADS; ++i)
        if (pthread_join(threads[i], NULL) || thread_rc[i]) return 1;
    pthread_barrier_destroy(&start_barrier);

    for (unsigned int i = 0; i < KP_CALLBACK_TRAMP_SLOT_COUNT; ++i) {
        if (allocated[i] >= KP_CALLBACK_TRAMP_SLOT_COUNT || seen[allocated[i]]) {
            fprintf(stderr, "concurrent slot allocation duplicated or escaped bounds\n");
            return 1;
        }
        seen[allocated[i]] = true;
    }
    puts("[PASS] concurrent callback iterators receive unique trampoline slots");

    rc = kp_callback_tramp_slot_alloc(&extra);
    if (rc != -EBUSY) {
        fprintf(stderr, "full trampoline page returned %d instead of -EBUSY\n", rc);
        return 1;
    }
    puts("[PASS] exhausted trampoline slot pool fails closed");

    kp_callback_tramp_slot_free(KP_CALLBACK_TRAMP_SLOT_COUNT);
    kp_callback_tramp_slot_free(allocated[0]);
    kp_callback_tramp_slot_free(allocated[0]);
    rc = kp_callback_tramp_slot_alloc(&replacement);
    if (rc || replacement != allocated[0]) {
        fprintf(stderr, "released slot was not safely reusable: rc=%d slot=%lu expected=%lu\n",
                rc, replacement, allocated[0]);
        return 1;
    }
    puts("[PASS] slot release is idempotent and permits reuse without disturbing other slots");

    kp_callback_tramp_slot_free(replacement);
    for (unsigned int i = 1; i < KP_CALLBACK_TRAMP_SLOT_COUNT; ++i)
        kp_callback_tramp_slot_free(allocated[i]);
    memset(seen, 0, sizeof(seen));
    for (unsigned int i = 0; i < KP_CALLBACK_TRAMP_SLOT_COUNT; ++i) {
        unsigned long slot = (unsigned long)-1;
        if (kp_callback_tramp_slot_alloc(&slot) || slot >= KP_CALLBACK_TRAMP_SLOT_COUNT || seen[slot])
            return 1;
        seen[slot] = true;
        allocated[i] = slot;
    }
    if (kp_callback_tramp_slot_alloc(&extra) != -EBUSY) return 1;
    for (unsigned int i = 0; i < KP_CALLBACK_TRAMP_SLOT_COUNT; ++i)
        kp_callback_tramp_slot_free(allocated[i]);
    puts("[PASS] full slot pool can be reclaimed and allocated again");
    return 0;
}
"""

    code = prefix + "\n" + allocator + "\n" + release + "\n" + tests
    with tempfile.TemporaryDirectory(prefix="kpm-trampoline-slots-") as tmp:
        cfile = Path(tmp) / "trampoline_slots.c"
        binary = Path(tmp) / "trampoline_slots"
        cfile.write_text(code, encoding="utf-8")
        subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-parameter", "-pthread", str(cfile), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("[PASS] production KPM trampoline slot allocator host-executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
