

#ifndef internal_Gate_H
#define internal_Gate_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "../Gate.h"
#include "EverParse.h"

uint8_t
GateLowScan(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  GATE_SPEC_REQUEST Q,
  GATE_SPEC_SESSION S,
  uint8_t *Ctxt,
  uint8_t *Bp,
  uint32_t J
);

#if defined(__cplusplus)
}
#endif

#define internal_Gate_H_DEFINED
#endif /* internal_Gate_H */
