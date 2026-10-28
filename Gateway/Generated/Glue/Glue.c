

#include "Glue.h"

#include "GlueFront.h"
#include "Gate.h"
#include "Blob.h"

static GATE_SPEC_RULE ToGate(BLOB_SPEC_RULE R)
{
  return
    (
      (GATE_SPEC_RULE){ .path = R.path, .mask = R.mask, .min_role = R.min_role, .rscope = R.rscope }
    );
}

static void BuildApp(uint8_t *W, uint8_t *App, uint32_t *AppLen)
{
  uint32_t bl = GlueFrontReadU32(W, 171U);
  App[0U] = 0U;
  memcpy(App + 1U, W + 1U, 41U * sizeof (uint8_t));
  memcpy(App + 42U, W + 171U, (4U + bl) * sizeof (uint8_t));
  AppLen[0U] = 46U + bl;
}

static BLOB_SPEC_RULE DummyRule = { .path = 0U, .mask = 0U, .min_role = 0U, .rscope = 0U };

static void CopyPart(GATE_SPEC_RULE *Pi, uint32_t J, BLOB_SPEC_RULE *Pol)
{
  uint32_t o = 8U * (J - 1U);
  BLOB_SPEC_RULE x0 = Pol[0U];
  Pi[o + 0U] = ToGate(x0);
  BLOB_SPEC_RULE x1 = Pol[1U];
  Pi[o + 1U] = ToGate(x1);
  BLOB_SPEC_RULE x2 = Pol[2U];
  Pi[o + 2U] = ToGate(x2);
  BLOB_SPEC_RULE x3 = Pol[3U];
  Pi[o + 3U] = ToGate(x3);
  BLOB_SPEC_RULE x4 = Pol[4U];
  Pi[o + 4U] = ToGate(x4);
  BLOB_SPEC_RULE x5 = Pol[5U];
  Pi[o + 5U] = ToGate(x5);
  BLOB_SPEC_RULE x6 = Pol[6U];
  Pi[o + 6U] = ToGate(x6);
  BLOB_SPEC_RULE x7 = Pol[7U];
  Pi[o + 7U] = ToGate(x7);
}

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
)
{
  if (!GlueFrontWireCheck(W, Len))
  {
    return 0U;
  }
  uint32_t path = GlueFrontReadU32(W, 1U);
  uint8_t m = W[5U];
  if (path == 0x44444444U && m == 4U)
  {
    if (Len == 240U && 1U <= J && J <= N)
    {
      uint8_t ro = W[6U];
      uint8_t co = W[0U];
      BLOB_SPEC_SESSION ss = { .role = ro, .count = co };
      KRML_CHECK_SIZE(sizeof (BLOB_SPEC_RULE), 8U);
      BLOB_SPEC_RULE pol[8U];
      for (uint32_t _i = 0U; _i < 8U; ++_i)
        pol[_i] = DummyRule;
      uint8_t *body = W + 175U;
      uint8_t v = BlobLowUpdateDecide(ss, body, pol, Nr, Ctxt);
      if (v == 1U)
      {
        CopyPart(Pi, J, pol);
      }
      if (v == 1U)
      {
        return 4U;
      }
      if (v == 0U)
      {
        return 5U;
      }
      return 6U;
    }
    return 5U;
  }
  uint8_t c = W[0U];
  if (c >= 50U)
  {
    return 3U;
  }
  GATE_SPEC_REQUEST q = { .rpath = path, .meth = m };
  uint8_t ro = W[6U];
  uint16_t sc = GlueFrontReadU16(W, 7U);
  GATE_SPEC_SESSION ss = { .role = ro, .sscope = sc, .count = c };
  uint8_t v = GateLowGateDecide(N, Pi, q, ss, Ctxt);
  if (v == 1U)
  {
    BuildApp(W, App, AppLen);
    return 1U;
  }
  if (v == 0U)
  {
    return 2U;
  }
  return 6U;
}

