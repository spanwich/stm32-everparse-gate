/* Linker --wrap instrumentation for a separately labelled M1 image. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_ALLOC
#include "paper_alloc.h"
#include "FreeRTOS.h"
#include "task.h"
#include <stddef.h>
#include <stdint.h>
struct _reent;
static volatile uint32_t active;
static TaskHandle_t owner;
static volatile PaperAllocCounts counts;

void paper_alloc_begin(void)
{
    counts=(PaperAllocCounts){0};
    owner=xTaskGetCurrentTaskHandle();
    active=1;
}
PaperAllocCounts paper_alloc_end(void)
{
    active=0;
    owner=NULL;
    return (PaperAllocCounts){counts.freertos,counts.libc,counts.newlib,
                              counts.lwip_heap,counts.lwip_pool};
}

extern void *__real_pvPortMalloc(size_t);
void *__wrap_pvPortMalloc(size_t size)
{ if(active && xTaskGetCurrentTaskHandle()==owner) ++counts.freertos; return __real_pvPortMalloc(size); }
extern void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{ if(active && xTaskGetCurrentTaskHandle()==owner) ++counts.libc; return __real_malloc(size); }
extern void *__real__malloc_r(struct _reent *,size_t);
void *__wrap__malloc_r(struct _reent *reent,size_t size)
{ if(active && xTaskGetCurrentTaskHandle()==owner) ++counts.newlib; return __real__malloc_r(reent,size); }
extern void *__real_mem_malloc(size_t);
void *__wrap_mem_malloc(size_t size)
{ if(active && xTaskGetCurrentTaskHandle()==owner) ++counts.lwip_heap; return __real_mem_malloc(size); }
extern void *__real_memp_malloc(int);
void *__wrap_memp_malloc(int type)
{ if(active && xTaskGetCurrentTaskHandle()==owner) ++counts.lwip_pool; return __real_memp_malloc(type); }
#endif
