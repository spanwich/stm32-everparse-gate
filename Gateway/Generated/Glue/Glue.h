

#ifndef Glue_H
#define Glue_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "Gate.h"
#include "EverParse.h"

uint8_t
GlueLowMediate(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  uint32_t J,
  uint8_t *W,
  uint32_t Len,
  uint8_t *Nr,
  uint8_t *App,
  uint32_t *AppLen,
  uint8_t *Ctxt
);

#if defined(__cplusplus)
}
#endif

#define Glue_H_DEFINED
#endif /* Glue_H */
