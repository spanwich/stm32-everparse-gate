

#ifndef Gate_H
#define Gate_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

typedef struct GATE_SPEC_RULE_s
{
  uint32_t path;
  uint8_t mask;
  uint8_t min_role;
  uint16_t rscope;
}
GATE_SPEC_RULE;

typedef struct GATE_SPEC_REQUEST_s
{
  uint32_t rpath;
  uint8_t meth;
}
GATE_SPEC_REQUEST;

typedef struct GATE_SPEC_SESSION_s
{
  uint8_t role;
  uint16_t sscope;
  uint8_t count;
}
GATE_SPEC_SESSION;

void
GateLowWritePart(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  GATE_SPEC_REQUEST Q,
  GATE_SPEC_SESSION S,
  uint32_t J,
  uint8_t *Out
);

void GateLowWriteRate(uint8_t C, uint8_t *Out);

uint8_t
GateLowGateDecide(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  GATE_SPEC_REQUEST Q,
  GATE_SPEC_SESSION S,
  uint8_t *Ctxt
);

#if defined(__cplusplus)
}
#endif

#define Gate_H_DEFINED
#endif /* Gate_H */
