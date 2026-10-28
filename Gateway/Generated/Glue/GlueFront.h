

#ifndef GlueFront_H
#define GlueFront_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

uint32_t GlueFrontReadU32(uint8_t *W, uint32_t O);

uint16_t GlueFrontReadU16(uint8_t *W, uint32_t O);

BOOLEAN GlueFrontWireCheck(uint8_t *W, uint32_t Len);

uint8_t GlueFrontClassify(uint8_t *W, uint32_t Len);

uint32_t GlueFrontCredential(uint8_t *W, uint32_t Len, uint8_t *Dst);

void
GlueFrontSetIdentity(
  uint8_t *W,
  uint8_t Count,
  uint8_t Role,
  uint16_t Scope,
  uint8_t Sl,
  uint8_t *Subj
);

#if defined(__cplusplus)
}
#endif

#define GlueFront_H_DEFINED
#endif /* GlueFront_H */
