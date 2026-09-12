/* Handwritten platform secure-clear adapter. Volatile stores survive optimization. */
#include "gateway_clear.h"
#include <stdint.h>
void gateway_clear(void *buffer, size_t length)
{
    volatile uint8_t *p = buffer;
    while (length--) *p++ = 0;
}
/* HACL runtime ABI; ARM size_t is 32-bit, all callers pass bounded objects. */
void Lib_Memzero0_memzero0(void *buffer, uint64_t length)
{
    gateway_clear(buffer, (size_t)length);
}
