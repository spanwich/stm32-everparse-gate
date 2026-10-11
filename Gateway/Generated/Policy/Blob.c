

#include "Blob.h"

#include "RbacPolicy.h"

void BlobLowWriteBlob(BLOB_SPEC_SESSION S, uint8_t *Body, uint8_t *Out)
{
  memcpy(Out + 2U, Body, 65U * sizeof (uint8_t));
  Out[0U] = S.role;
  Out[1U] = S.count;
  Out[67U] = 0U;
  Out[68U] = 0U;
  Out[69U] = 0U;
}

static BLOB_SPEC_RULE ReadRule(uint8_t *Body, uint32_t O)
{
  uint8_t x0 = Body[O + 0U];
  uint8_t x1 = Body[O + 1U];
  uint8_t x2 = Body[O + 2U];
  uint8_t x3 = Body[O + 3U];
  uint8_t x4 = Body[O + 4U];
  uint8_t x5 = Body[O + 5U];
  uint8_t x6 = Body[O + 6U];
  uint8_t x7 = Body[O + 7U];
  uint32_t b0 = (uint32_t)x0;
  uint32_t b1 = (uint32_t)x1;
  uint32_t b2 = (uint32_t)x2;
  uint32_t b3 = (uint32_t)x3;
  uint8_t m = x4;
  uint8_t r = x5;
  uint16_t c0 = (uint16_t)x6;
  uint16_t c1 = (uint16_t)x7;
  uint32_t path = b0 + 256U * b1 + 65536U * b2 + 16777216U * b3;
  uint16_t sc = (uint32_t)c0 + 256U * (uint32_t)c1;
  return ((BLOB_SPEC_RULE){ .path = path, .mask = m, .min_role = r, .rscope = sc });
}

static void DecodeInto(uint8_t *Body, BLOB_SPEC_RULE *Pol)
{
  BLOB_SPEC_RULE r0 = ReadRule(Body, 1U);
  Pol[0U] = r0;
  BLOB_SPEC_RULE r1 = ReadRule(Body, 9U);
  Pol[1U] = r1;
  BLOB_SPEC_RULE r2 = ReadRule(Body, 17U);
  Pol[2U] = r2;
  BLOB_SPEC_RULE r3 = ReadRule(Body, 25U);
  Pol[3U] = r3;
  BLOB_SPEC_RULE r4 = ReadRule(Body, 33U);
  Pol[4U] = r4;
  BLOB_SPEC_RULE r5 = ReadRule(Body, 41U);
  Pol[5U] = r5;
  BLOB_SPEC_RULE r6 = ReadRule(Body, 49U);
  Pol[6U] = r6;
  BLOB_SPEC_RULE r7 = ReadRule(Body, 57U);
  Pol[7U] = r7;
}

static void
Quiet(
  EVERPARSE_STRING Uu,
  EVERPARSE_STRING Uu1,
  EVERPARSE_STRING Uu2,
  uint64_t Uu3,
  uint8_t *Uu4,
  uint8_t *Uu5,
  uint64_t Uu6
)
{
  KRML_MAYBE_UNUSED_VAR(Uu);
  KRML_MAYBE_UNUSED_VAR(Uu1);
  KRML_MAYBE_UNUSED_VAR(Uu2);
  KRML_MAYBE_UNUSED_VAR(Uu3);
  KRML_MAYBE_UNUSED_VAR(Uu4);
  KRML_MAYBE_UNUSED_VAR(Uu5);
  KRML_MAYBE_UNUSED_VAR(Uu6);
}

static uint8_t CodeOf(uint64_t Res)
{
  if (EverParseIsSuccess(Res))
  {
    return 1U;
  }
  if
  (
    EverParseGetValidatorErrorKind(Res) ==
      EverParseGetValidatorErrorKind(EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED)
  )
  {
    return 2U;
  }
  return 0U;
}

static uint8_t CheckBlob(uint8_t *B, uint8_t *Ctxt)
{
  uint8_t *sl = B;
  uint64_t res = RbacPolicyValidatePolicyBlob(Ctxt, Quiet, sl, 70ULL, 0ULL);
  uint8_t r = CodeOf(res);
  return r;
}

uint8_t
BlobLowUpdateDecide(
  BLOB_SPEC_SESSION S,
  uint8_t *Body,
  BLOB_SPEC_RULE *Pol,
  uint8_t *Nr,
  uint8_t *Ctxt
)
{
  uint8_t buf[70U] = { 0U };
  BlobLowWriteBlob(S, Body, buf);
  uint8_t v = CheckBlob(buf, Ctxt);
  if (v == 1U)
  {
    DecodeInto(Body, Pol);
    Nr[0U] = Body[0U];
  }
  return v;
}

