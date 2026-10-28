

#ifndef GlueRate_H
#define GlueRate_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

typedef struct GLUE_RATESPEC_RSTATE_s
{
  uint8_t count;
  uint64_t start;
}
GLUE_RATESPEC_RSTATE;

void GlueRateRateInit(GLUE_RATESPEC_RSTATE *St);

uint8_t GlueRateRateStep(GLUE_RATESPEC_RSTATE *St, uint64_t Now, uint64_t W);

void
GlueRateCountAndIdentify(
  GLUE_RATESPEC_RSTATE *St,
  uint64_t Now,
  uint64_t W,
  uint8_t *Frame,
  uint8_t Role,
  uint16_t Scope,
  uint8_t Sl,
  uint8_t *Subj
);

#if defined(__cplusplus)
}
#endif

#define GlueRate_H_DEFINED
#endif /* GlueRate_H */
