

#include "GlueFront.h"

uint32_t GlueFrontReadU32(uint8_t *W, uint32_t O)
{
  uint8_t x0 = W[O];
  uint8_t x1 = W[O + 1U];
  uint8_t x2 = W[O + 2U];
  uint8_t x3 = W[O + 3U];
  uint32_t b0 = (uint32_t)x0;
  uint32_t b1 = (uint32_t)x1;
  uint32_t b2 = (uint32_t)x2;
  uint32_t b3 = (uint32_t)x3;
  return b0 + 256U * b1 + 65536U * b2 + 16777216U * b3;
}

uint16_t GlueFrontReadU16(uint8_t *W, uint32_t O)
{
  uint8_t x0 = W[O];
  uint8_t x1 = W[O + 1U];
  uint16_t c0 = (uint16_t)x0;
  uint16_t c1 = (uint16_t)x1;
  return (uint32_t)c0 + 256U * (uint32_t)c1;
}

static BOOLEAN MethodOkL(uint8_t M)
{
  return M == 1U || M == 2U || M == 4U || M == 8U || M == 16U || M == 32U;
}

BOOLEAN GlueFrontWireCheck(uint8_t *W, uint32_t Len)
{
  if (Len < 175U || Len > 1536U)
  {
    return FALSE;
  }
  uint32_t bl = GlueFrontReadU32(W, 171U);
  uint8_t sl = W[9U];
  uint8_t tl = W[42U];
  uint8_t ro = W[6U];
  uint8_t m = W[5U];
  return bl == Len - 175U && sl <= 32U && tl <= 128U && ro <= 2U && MethodOkL(m);
}

uint8_t GlueFrontClassify(uint8_t *W, uint32_t Len)
{
  if (!GlueFrontWireCheck(W, Len))
  {
    return 0U;
  }
  uint32_t path = GlueFrontReadU32(W, 1U);
  uint8_t m = W[5U];
  if (path == 0U && m == 1U)
  {
    return 1U;
  }
  if (path == 0x11111111U && m == 2U)
  {
    return 2U;
  }
  if (W[42U] == 0U)
  {
    return 3U;
  }
  return 4U;
}

uint32_t GlueFrontCredential(uint8_t *W, uint32_t Len, uint8_t *Dst)
{
  KRML_MAYBE_UNUSED_VAR(Len);
  uint32_t path = GlueFrontReadU32(W, 1U);
  uint8_t m = W[5U];
  if (path == 0x11111111U && m == 2U)
  {
    uint32_t bl = GlueFrontReadU32(W, 171U);
    memcpy(Dst, W + 175U, bl * sizeof (uint8_t));
    return bl;
  }
  uint8_t t8 = W[42U];
  uint32_t tl = (uint32_t)t8;
  memcpy(Dst, W + 43U, tl * sizeof (uint8_t));
  return tl;
}

void
GlueFrontSetIdentity(
  uint8_t *W,
  uint8_t Count,
  uint8_t Role,
  uint16_t Scope,
  uint8_t Sl,
  uint8_t *Subj
)
{
  uint8_t reg[32U] = { 0U };
  uint32_t sl32 = (uint32_t)Sl;
  memcpy(reg, Subj, sl32 * sizeof (uint8_t));
  memcpy(W + 10U, reg, 32U * sizeof (uint8_t));
  uint8_t lo = (uint8_t)Scope;
  uint8_t hi = (uint8_t)((uint32_t)Scope >> 8U);
  W[0U] = Count;
  W[6U] = Role;
  W[7U] = lo;
  W[8U] = hi;
  W[9U] = Sl;
}

