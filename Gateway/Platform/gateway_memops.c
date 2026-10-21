/* Word-at-a-time memcpy/memset (A1, 2026-10-22), behind GATEWAY_FAST_MEMOPS.
 *
 * newlib-nano's memcpy/memset copy one byte per loop iteration. FreeRTOS copies
 * every queue item with memcpy inside a critical section, so the byte loop sets
 * the gateway's longest interrupt-disabled intervals (~1.5 KB pipeline messages,
 * 13.1-13.7k cycles with caches off). These strong definitions replace the
 * library versions at link time.
 *
 * Determinism: the cost depends only on n and on the relative alignment of the
 * pointers, never on the data. When source and destination share alignment the
 * bulk moves 16 bytes per iteration with word accesses; otherwise it falls back
 * to bytes (no unaligned word accesses, which would fault on device memory).
 * Semantics are those of ISO C memcpy/memset; overlapping memcpy is undefined
 * as usual (memmove is unchanged). */
#include "paper_experiment.h"
#if GATEWAY_ITCM && !GATEWAY_FAST_MEMOPS
#error "GATEWAY_ITCM places the word-at-a-time memops in ITCM; set GATEWAY_FAST_MEMOPS = 1"
#endif
#if GATEWAY_FAST_MEMOPS
#include <stddef.h>
#include <stdint.h>

typedef uint32_t __attribute__((may_alias)) gateway_word_t;

/* Keep GCC from recognising these loops as memcpy/memset and calling
 * themselves recursively. */
#define GATEWAY_MEMOPS_ATTR __attribute__((optimize("no-tree-loop-distribute-patterns"), used))

GATEWAY_MEMOPS_ATTR void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if ((((uintptr_t)d ^ (uintptr_t)s) & 3u) == 0u) {
        while (n != 0u && ((uintptr_t)d & 3u) != 0u) { *d++ = *s++; n--; }
        gateway_word_t *dw = (gateway_word_t *)(void *)d;
        const gateway_word_t *sw = (const gateway_word_t *)(const void *)s;
        while (n >= 16u) {
            gateway_word_t a = sw[0], b = sw[1], c = sw[2], e = sw[3];
            dw[0] = a; dw[1] = b; dw[2] = c; dw[3] = e;
            dw += 4; sw += 4; n -= 16u;
        }
        while (n >= 4u) { *dw++ = *sw++; n -= 4u; }
        d = (uint8_t *)dw;
        s = (const uint8_t *)sw;
    }
    while (n != 0u) { *d++ = *s++; n--; }
    return dst;
}

GATEWAY_MEMOPS_ATTR void *memset(void *dst, int value, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t byte = (uint8_t)value;
    while (n != 0u && ((uintptr_t)d & 3u) != 0u) { *d++ = byte; n--; }
    const gateway_word_t word = (gateway_word_t)byte * 0x01010101u;
    gateway_word_t *dw = (gateway_word_t *)(void *)d;
    while (n >= 16u) { dw[0] = word; dw[1] = word; dw[2] = word; dw[3] = word; dw += 4; n -= 16u; }
    while (n >= 4u) { *dw++ = word; n -= 4u; }
    d = (uint8_t *)dw;
    while (n != 0u) { *d++ = byte; n--; }
    return dst;
}
#endif
