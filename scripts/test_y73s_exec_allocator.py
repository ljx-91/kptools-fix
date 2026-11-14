#!/usr/bin/env python3
"""Static contract and deterministic model tests for the Y73S exec page-run allocator."""

from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "kernel/base/exec_alloc.c").read_text()
HEADER = (ROOT / "kernel/include/kpmalloc.h").read_text()
START = (ROOT / "kernel/base/start.c").read_text()
MAKEFILE = (ROOT / "kernel/Makefile").read_text()

REQUIRED_SOURCE = (
    "KP_EXEC_MAX_PAGES 1024U",
    "KP_EXEC_PAGE_INTERIOR 0xffffU",
    "kp_private_spin_lock(&exec_allocator_lock)",
    "offset % a->page_bytes",
    "pages == KP_EXEC_PAGE_INTERIOR",
    "bytes > (size_t)-1 - (a->page_bytes - 1)",
    "return -EOVERFLOW",
    "memcpy(replacement, ptr, copy_bytes)",
    "tlsf_malloc(kp_rw_mem, sizeof(*a))",
)
for token in REQUIRED_SOURCE:
    assert token in SOURCE, f"missing allocator contract: {token}"

assert "return kp_exec_malloc(bytes);" in HEADER
assert "return kp_exec_memalign(align, bytes);" in HEADER
assert "return kp_exec_realloc(ptr, size);" in HEADER
assert "kp_exec_free(ptr);" in HEADER
assert "kp_rox_mem" not in START
assert "kp_exec_allocator_init((void *)_kp_rox_start" in START
assert "BASE_SRCS += base/exec_alloc.c" in MAKEFILE


class PageRunAllocator:
    def __init__(self, pages=1024, base=0x10000000, page_size=4096):
        self.pages = pages
        self.base = base
        self.page = page_size
        self.state = [0] * pages  # 0 free, -1 continuation, positive run head

    def alloc(self, size, alignment=None):
        if size <= 0:
            return None
        alignment = alignment or self.page
        if alignment & (alignment - 1):
            return None
        if alignment < self.page:
            alignment = self.page
        count = (size + self.page - 1) // self.page
        if count > self.pages:
            return None
        i = 0
        while i <= self.pages - count:
            addr = self.base + i * self.page
            if addr & (alignment - 1):
                i += 1
                continue
            j = 0
            while j < count and self.state[i + j] == 0:
                j += 1
            if j != count:
                i += j + 1
                continue
            self.state[i] = count
            for k in range(1, count):
                self.state[i + k] = -1
            return addr
        return None

    def head(self, ptr):
        if ptr is None or ptr < self.base:
            return None
        delta = ptr - self.base
        if delta >= self.pages * self.page or delta % self.page:
            return None
        i = delta // self.page
        count = self.state[i]
        if count <= 0 or i + count > self.pages:
            return None
        if any(x != -1 for x in self.state[i + 1:i + count]):
            return None
        return i, count

    def free(self, ptr):
        h = self.head(ptr)
        if h is None:
            return False
        i, count = h
        self.state[i:i + count] = [0] * count
        return True

    def realloc(self, ptr, size):
        if ptr is None:
            return self.alloc(size)
        if size == 0:
            self.free(ptr)
            return None
        h = self.head(ptr)
        if h is None:
            return None
        i, old_count = h
        new_count = (size + self.page - 1) // self.page
        if new_count > self.pages:
            return None
        if new_count <= old_count:
            self.state[i + new_count:i + old_count] = [0] * (old_count - new_count)
            self.state[i] = new_count
            return ptr
        if i + new_count <= self.pages and all(
            x == 0 for x in self.state[i + old_count:i + new_count]
        ):
            for k in range(i + old_count, i + new_count):
                self.state[k] = -1
            self.state[i] = new_count
            return ptr
        new_ptr = self.alloc(size)
        if new_ptr is None:
            return None
        self.free(ptr)
        return new_ptr

    def assert_consistent(self):
        occupied = set()
        for i, count in enumerate(self.state):
            if count > 0:
                assert i + count <= self.pages
                assert all(self.state[j] == -1 for j in range(i + 1, i + count))
                run = set(range(i, i + count))
                assert not (occupied & run)
                occupied |= run
            elif count == -1:
                assert i in occupied or any(
                    start < i < start + length
                    for start, length in enumerate(self.state) if length > 0
                )
            else:
                assert count == 0


def run_tests():
    a = PageRunAllocator()
    p0 = a.alloc(1)
    p1 = a.alloc(4097)
    assert p0 == a.base and p1 == a.base + a.page
    assert not a.free(p1 + a.page)  # interior page is not a valid free base
    assert a.free(p0)
    assert not a.free(p0)  # double free
    assert a.alloc(1, 65536) % 65536 == 0

    b = PageRunAllocator(pages=12)
    x, y, z = b.alloc(4 * b.page), b.alloc(4 * b.page), b.alloc(4 * b.page)
    assert x is not None and y is not None and z is not None
    assert b.free(y)
    assert b.alloc(5 * b.page) is None  # fragmented, no contiguous extent
    assert b.alloc(4 * b.page) == y

    c = PageRunAllocator(pages=1024)
    allocated = [c.alloc(c.page) for _ in range(1024)]
    assert all(p is not None for p in allocated)
    assert c.alloc(1) is None
    for p in allocated[::2]:
        assert c.free(p)
    assert c.alloc(2 * c.page) is None
    assert c.alloc(1) is not None

    d = PageRunAllocator(pages=16)
    q = d.alloc(2 * d.page)
    assert d.realloc(q, 4 * d.page) == q  # in-place growth
    assert d.realloc(q, d.page) == q      # shrink
    assert d.realloc(q, 8 * d.page) == q  # grow after shrink
    assert d.realloc(q, 0) is None
    assert d.alloc(17 * d.page) is None

    rng = random.Random(0x7373)
    e = PageRunAllocator(pages=128)
    live = []
    for _ in range(6000):
        if live and rng.randrange(3) == 0:
            index = rng.randrange(len(live))
            ptr = live.pop(index)
            assert e.free(ptr)
        else:
            ptr = e.alloc(rng.randrange(1, 9) * e.page,
                          rng.choice((e.page, 2 * e.page, 4 * e.page, 8 * e.page)))
            if ptr is not None:
                assert ptr not in live
                live.append(ptr)
        e.assert_consistent()


if __name__ == "__main__":
    run_tests()
    print("[PASS] Y73S executable page-run allocator contract/model tests")
