#ifndef PAPER_ALLOC_H
#define PAPER_ALLOC_H
#include <stdint.h>
typedef struct { uint32_t freertos, libc, newlib, lwip_heap, lwip_pool; } PaperAllocCounts;
void paper_alloc_begin(void);
PaperAllocCounts paper_alloc_end(void);
#endif
