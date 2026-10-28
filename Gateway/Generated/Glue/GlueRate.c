

#include "GlueRate.h"

#include "GlueFront.h"

static uint8_t Next(uint8_t C)
{
  if (C < 255U)
  {
    return (uint32_t)C + 1U;
  }
  return C;
}

void GlueRateRateInit(GLUE_RATESPEC_RSTATE *St)
{
  St[0U] = ((GLUE_RATESPEC_RSTATE){ .count = 0U, .start = 0ULL });
}

uint8_t GlueRateRateStep(GLUE_RATESPEC_RSTATE *St, uint64_t Now, uint64_t W)
{
  GLUE_RATESPEC_RSTATE s = St[0U];
  BOOLEAN e;
  if (Now < s.start)
  {
    e = TRUE;
  }
  else
  {
    e = (Now - s.start) >= W;
  }
  uint8_t c;
  if (e)
  {
    c = 1U;
  }
  else
  {
    c = Next(s.count);
  }
  uint64_t t;
  if (e)
  {
    t = Now;
  }
  else
  {
    t = s.start;
  }
  St[0U] = ((GLUE_RATESPEC_RSTATE){ .count = c, .start = t });
  return c;
}

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
)
{
  uint8_t c = GlueRateRateStep(St, Now, W);
  GlueFrontSetIdentity(Frame, c, Role, Scope, Sl, Subj);
}

