

#ifndef internal_EverParse_H
#define internal_EverParse_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

typedef struct SLICE_s
{
  uint8_t *base;
  uint32_t len;
}
SLICE;

#if defined(__cplusplus)
}
#endif

#define internal_EverParse_H_DEFINED
#endif /* internal_EverParse_H */
