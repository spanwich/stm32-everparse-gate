

#include "internal/Gate.h"

#include "UniversalRate.h"
#include "Partition8.h"
#include "internal/EverParse.h"

static void Put8(uint8_t *B, uint32_t Pos, uint8_t X)
{
  B[Pos] = X;
  KRML_HOST_IGNORE(1U);
}

static void Put16(uint8_t *B, uint32_t Pos, uint16_t X)
{
  SLICE sl = { .base = B, .len = Pos + 2U };
  uint16_t x_ = (uint16_t)(uint32_t)X;
  Store16Le(sl.base + Pos, x_);
  uint32_t len = 2U;
  uint32_t pos_ = Pos + len;
  uint32_t pos_0 = pos_;
  KRML_MAYBE_UNUSED_VAR(pos_0);
}

static void Put32(uint8_t *B, uint32_t Pos, uint32_t X)
{
  SLICE sl = { .base = B, .len = Pos + 4U };
  Store32Le(sl.base + Pos, X);
  uint32_t len = 4U;
  uint32_t pos_ = Pos + len;
  uint32_t pos_0 = pos_;
  KRML_MAYBE_UNUSED_VAR(pos_0);
}

static void PutRule(uint8_t *B, uint32_t Pos, GATE_SPEC_RULE R)
{
  Put16(B, Pos + 6U, R.rscope);
  Put8(B, Pos + 5U, R.min_role);
  Put8(B, Pos + 4U, R.mask);
  Put32(B, Pos, R.path);
}

static void
PutPart8(
  uint8_t *Out,
  GATE_SPEC_SESSION S,
  GATE_SPEC_RULE R0,
  GATE_SPEC_RULE R1,
  GATE_SPEC_RULE R2,
  GATE_SPEC_RULE R3,
  GATE_SPEC_RULE R4,
  GATE_SPEC_RULE R5,
  GATE_SPEC_RULE R6,
  GATE_SPEC_RULE R7,
  GATE_SPEC_REQUEST Q
)
{
  Put8(Out, 72U, 0U);
  Put8(Out, 71U, Q.meth);
  Put32(Out, 67U, Q.rpath);
  PutRule(Out, 59U, R7);
  PutRule(Out, 51U, R6);
  PutRule(Out, 43U, R5);
  PutRule(Out, 35U, R4);
  PutRule(Out, 27U, R3);
  PutRule(Out, 19U, R2);
  PutRule(Out, 11U, R1);
  PutRule(Out, 3U, R0);
  Put16(Out, 1U, S.sscope);
  Put8(Out, 0U, S.role);
}

void
GateLowWritePart(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  GATE_SPEC_REQUEST Q,
  GATE_SPEC_SESSION S,
  uint32_t J,
  uint8_t *Out
)
{
  KRML_MAYBE_UNUSED_VAR(N);
  uint32_t base = 8U * (J - 1U);
  GATE_SPEC_RULE r0 = Pi[base];
  GATE_SPEC_RULE r1 = Pi[base + 1U];
  GATE_SPEC_RULE r2 = Pi[base + 2U];
  GATE_SPEC_RULE r3 = Pi[base + 3U];
  GATE_SPEC_RULE r4 = Pi[base + 4U];
  GATE_SPEC_RULE r5 = Pi[base + 5U];
  GATE_SPEC_RULE r6 = Pi[base + 6U];
  GATE_SPEC_RULE r7 = Pi[base + 7U];
  PutPart8(Out, S, r0, r1, r2, r3, r4, r5, r6, r7, Q);
}

void GateLowWriteRate(uint8_t C, uint8_t *Out)
{
  Put8(Out, 1U, 0U);
  Put8(Out, 0U, C);
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

static uint8_t CheckPart(uint8_t *B, uint8_t *Ctxt)
{
  uint8_t *sl = B;
  uint64_t res = Partition8ValidatePartition8(Ctxt, Quiet, sl, 73ULL, 0ULL);
  uint8_t r = CodeOf(res);
  return r;
}

static uint8_t CheckRate(uint8_t *B, uint8_t *Ctxt)
{
  uint8_t *sl = B;
  uint64_t res = UniversalRateValidateUniversalRate(Ctxt, Quiet, sl, 2ULL, 0ULL);
  uint8_t r = CodeOf(res);
  return r;
}

uint8_t
GateLowScan(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  GATE_SPEC_REQUEST Q,
  GATE_SPEC_SESSION S,
  uint8_t *Ctxt,
  uint8_t *Bp,
  uint32_t J
)
{
  if (J > N)
  {
    return 0U;
  }
  GateLowWritePart(N, Pi, Q, S, J, Bp);
  uint8_t v = CheckPart(Bp, Ctxt);
  if (v == 1U)
  {
    return 1U;
  }
  if (v == 2U)
  {
    return 2U;
  }
  return GateLowScan(N, Pi, Q, S, Ctxt, Bp, J + 1U);
}

uint8_t
GateLowGateDecide(
  uint32_t N,
  GATE_SPEC_RULE *Pi,
  GATE_SPEC_REQUEST Q,
  GATE_SPEC_SESSION S,
  uint8_t *Ctxt
)
{
  uint8_t br[2U] = { 0U };
  uint8_t bp[73U] = { 0U };
  GateLowWriteRate(S.count, br);
  uint8_t vr = CheckRate(br, Ctxt);
  if (vr == 1U)
  {
    return GateLowScan(N, Pi, Q, S, Ctxt, bp, 1U);
  }
  if (vr == 2U)
  {
    return 2U;
  }
  return 0U;
}

