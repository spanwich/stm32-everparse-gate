

#include "Memops.h"

void Memops_Low_copy_u8(uint8_t *dst, uint8_t *src, uint32_t n)
{
  for (uint32_t i = 0U; i < n; i++)
  {
    dst[i] = src[i];
  }
}

void Memops_Low_fill_u8(uint8_t *dst, uint32_t n, uint8_t v)
{
  for (uint32_t i = 0U; i < n; i++)
  {
    dst[i] = v;
  }
}

void Memops_Low_copy_u32(uint32_t *dst, uint32_t *src, uint32_t n)
{
  uint32_t blocks = n / 4U;
  for (uint32_t i = 0U; i < blocks; i++)
  {
    uint32_t o = i * 4U;
    uint32_t a = src[o];
    uint32_t b = src[o + 1U];
    uint32_t c = src[o + 2U];
    uint32_t d = src[o + 3U];
    dst[o] = a;
    dst[o + 1U] = b;
    dst[o + 2U] = c;
    dst[o + 3U] = d;
  }
  uint32_t tail = blocks * 4U;
  for (uint32_t i = tail; i < n; i++)
  {
    dst[i] = src[i];
  }
}

void Memops_Low_fill_u32(uint32_t *dst, uint32_t n, uint32_t w)
{
  uint32_t blocks = n / 4U;
  for (uint32_t i = 0U; i < blocks; i++)
  {
    uint32_t o = i * 4U;
    dst[o] = w;
    dst[o + 1U] = w;
    dst[o + 2U] = w;
    dst[o + 3U] = w;
  }
  uint32_t tail = blocks * 4U;
  for (uint32_t i = tail; i < n; i++)
  {
    dst[i] = w;
  }
}

uint32_t Memops_Low_replicate(uint8_t b)
{
  return (uint32_t)b * 0x01010101U;
}

