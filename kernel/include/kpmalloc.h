#ifndef _KP_KPMALLOC_H_
#define _KP_KPMALLOC_H_

#include <tlsf.h>

extern tlsf_t kp_rw_mem;

/* Initialized once after the RW TLSF pool and executable arena are mapped. */
int kp_exec_allocator_init(void *base, size_t bytes, size_t runtime_page_size);
void *kp_exec_malloc(size_t bytes);
void *kp_exec_memalign(size_t align, size_t bytes);
void *kp_exec_realloc(void *ptr, size_t size);
void kp_exec_free(void *ptr);

static inline void *kp_malloc_exec(size_t bytes)
{
    return kp_exec_malloc(bytes);
}

static inline void *kp_memalign_exec(size_t align, size_t bytes)
{
    return kp_exec_memalign(align, bytes);
}

static inline void *kp_realloc_exec(void *ptr, size_t size)
{
    return kp_exec_realloc(ptr, size);
}

static inline void kp_free_exec(void *ptr)
{
    kp_exec_free(ptr);
}

static inline void *kp_malloc(size_t bytes)
{
    return tlsf_malloc(kp_rw_mem, bytes);
}

static inline void *kp_memalign(size_t align, size_t bytes)
{
    return tlsf_memalign(kp_rw_mem, align, bytes);
}

static inline void *kp_realloc(void *ptr, size_t size)
{
    return tlsf_realloc(kp_rw_mem, ptr, size);
}

static inline void kp_free(void *ptr)
{
    tlsf_free(kp_rw_mem, ptr);
}

#endif
