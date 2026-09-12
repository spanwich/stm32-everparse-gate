#ifndef GATEWAY_LWIP_CC_H
#define GATEWAY_LWIP_CC_H
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include "gateway_platform.h"
typedef unsigned int sys_prot_t;
#define LWIP_ERRNO_STDINCLUDE 1
#define LWIP_TIMEVAL_PRIVATE 0
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_FIELD(x) x
#define LWIP_PLATFORM_ASSERT(x) gateway_assert_failed(__FILE__, __LINE__)
#define LWIP_PLATFORM_DIAG(x) do { } while(0)
#define LWIP_RAND() ((uint32_t)rand())
#endif
