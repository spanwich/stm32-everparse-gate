

#ifndef Blob_H
#define Blob_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

typedef struct BLOB_SPEC_RULE_s
{
  uint32_t path;
  uint8_t mask;
  uint8_t min_role;
  uint16_t rscope;
}
BLOB_SPEC_RULE;

typedef struct BLOB_SPEC_SESSION_s
{
  uint8_t role;
  uint8_t count;
}
BLOB_SPEC_SESSION;

void BlobLowWriteBlob(BLOB_SPEC_SESSION S, uint8_t *Body, uint8_t *Out);

uint8_t
BlobLowUpdateDecide(
  BLOB_SPEC_SESSION S,
  uint8_t *Body,
  BLOB_SPEC_RULE *Pol,
  uint8_t *Nr,
  uint8_t *Ctxt
);

#if defined(__cplusplus)
}
#endif

#define Blob_H_DEFINED
#endif /* Blob_H */
