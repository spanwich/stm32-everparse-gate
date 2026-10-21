/* memcpy/memset built on Low*-verified loops (A1v, 2026-10-22), behind
 * GATEWAY_FAST_MEMOPS. Replaces newlib-nano's byte loops, which FreeRTOS runs
 * inside the kernel critical section for every ~1.5 KB queue copy.
 *
 * ../Generated/Memops/Memops.c is KaRaMeL's extraction of Memops.Low.fst
 * (paper-experiments/verified-memops), included verbatim. Each loop is proved
 * memory safe and functionally correct: it writes only its destination, which
 * afterwards equals the source (copy) or n copies of the value (fill); the word
 * loops are unrolled by four. replicate(b) is proved to have every byte equal b.
 *
 * This shim is the unverified remainder (trusted, reviewed):
 *  - alignment dispatch: when source and destination share alignment, split
 *    [0, n) into a byte head up to the next word boundary, whole words, and a
 *    byte tail; otherwise copy bytes only (no unaligned word access);
 *  - reinterpreting word-aligned byte memory as uint32_t words;
 *  - establishing the loops' preconditions: lengths as computed here; liveness
 *    and, for memcpy, non-overlap are the caller's ISO C obligations.
 * Cost depends only on n and the pointers' alignment, never on the data.
 * Every function in this file starts on a 32-byte boundary, so its position
 * relative to the flash fetch lines does not change between builds. */
#include "paper_experiment.h"
#if GATEWAY_ITCM && !GATEWAY_FAST_MEMOPS
#error "GATEWAY_ITCM places the verified memops in ITCM; set GATEWAY_FAST_MEMOPS = 1"
#endif
#if GATEWAY_FAST_MEMOPS
#include <stddef.h>
#include <stdint.h>

/* -Os: the same level as all other verified generated code (Gateway/Generated
 * is -Os in both build configurations). GCC must not turn the verified loops
 * back into memcpy/memset calls (which would recurse), nor reorder accesses
 * across the byte/word reinterpretation. */
#pragma GCC optimize("Os", "no-tree-loop-distribute-patterns", "no-strict-aliasing")

/* 32-byte alignment pins every function's position relative to the flash fetch
 * lines. GCC merges these attributes into the verbatim definitions below. */
#define GATEWAY_MEMOPS_ALIGNED __attribute__((aligned(32)))
GATEWAY_MEMOPS_ALIGNED void Memops_Low_copy_u8(uint8_t *dst, uint8_t *src, uint32_t n);
GATEWAY_MEMOPS_ALIGNED void Memops_Low_fill_u8(uint8_t *dst, uint32_t n, uint8_t v);
GATEWAY_MEMOPS_ALIGNED void Memops_Low_copy_u32(uint32_t *dst, uint32_t *src, uint32_t n);
GATEWAY_MEMOPS_ALIGNED void Memops_Low_fill_u32(uint32_t *dst, uint32_t n, uint32_t w);
GATEWAY_MEMOPS_ALIGNED uint32_t Memops_Low_replicate(uint8_t b);
#include "../Generated/Memops/Memops.c"

GATEWAY_MEMOPS_ALIGNED void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    uint8_t *s = (uint8_t *)(uintptr_t)src;   /* the loops never write src */
    if ((((uintptr_t)d ^ (uintptr_t)s) & 3u) == 0u) {
        size_t head = (4u - ((uintptr_t)d & 3u)) & 3u;
        if (head > n) head = n;
        Memops_Low_copy_u8(d, s, (uint32_t)head);
        d += head; s += head; n -= head;
        size_t words = n >> 2;
        Memops_Low_copy_u32((uint32_t *)(void *)d, (uint32_t *)(void *)s, (uint32_t)words);
        d += words << 2; s += words << 2; n &= 3u;
    }
    Memops_Low_copy_u8(d, s, (uint32_t)n);
    return dst;
}

GATEWAY_MEMOPS_ALIGNED void *memset(void *dst, int value, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    uint8_t byte = (uint8_t)value;
    size_t head = (4u - ((uintptr_t)d & 3u)) & 3u;
    if (head > n) head = n;
    Memops_Low_fill_u8(d, (uint32_t)head, byte);
    d += head; n -= head;
    size_t words = n >> 2;
    Memops_Low_fill_u32((uint32_t *)(void *)d, (uint32_t)words, Memops_Low_replicate(byte));
    d += words << 2; n &= 3u;
    Memops_Low_fill_u8(d, (uint32_t)n, byte);
    return dst;
}
#endif
