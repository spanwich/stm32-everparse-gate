

#ifndef Memops_H
#define Memops_H

#include <stdint.h>

void Memops_Low_copy_u8(uint8_t *dst, uint8_t *src, uint32_t n);

void Memops_Low_fill_u8(uint8_t *dst, uint32_t n, uint8_t v);

void Memops_Low_copy_u32(uint32_t *dst, uint32_t *src, uint32_t n);

void Memops_Low_fill_u32(uint32_t *dst, uint32_t n, uint32_t w);

uint32_t Memops_Low_replicate(uint8_t b);


#define Memops_H_DEFINED
#endif /* Memops_H */
