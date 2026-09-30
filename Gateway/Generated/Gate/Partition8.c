

#include "Partition8.h"

#include "internal/EverParse.h"

uint64_t
Partition8ValidatePartition8(
  uint8_t *Ctxt,
  void
  (*ErrorHandlerFn)(
    EVERPARSE_STRING x0,
    EVERPARSE_STRING x1,
    EVERPARSE_STRING x2,
    uint64_t x3,
    uint8_t *x4,
    uint8_t *x5,
    uint64_t x6
  ),
  uint8_t *Input,
  uint64_t InputLength,
  uint64_t StartPosition
)
{
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes0 = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterPartition8;
  if (hasBytes0)
  {
    positionAfterPartition8 = StartPosition + 1ULL;
  }
  else
  {
    positionAfterPartition8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterPartition8))
  {
    positionAfterauthState = positionAfterPartition8;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterPartition8),
      EverParseGetValidatorErrorKind(positionAfterPartition8),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterPartition8;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes1 = 2ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterPartition80;
  if (hasBytes1)
  {
    positionAfterPartition80 = positionAfterauthState + 2ULL;
  }
  else
  {
    positionAfterPartition80 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterauthScope;
  if (EverParseIsSuccess(positionAfterPartition80))
  {
    positionAfterauthScope = positionAfterPartition80;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "auth_scope",
      EverParseErrorReasonOfResult(positionAfterPartition80),
      EverParseGetValidatorErrorKind(positionAfterPartition80),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterauthScope = positionAfterPartition80;
  }
  if (EverParseIsError(positionAfterauthScope))
  {
    return positionAfterauthScope;
  }
  uint16_t r0 = Load16Le(Input + (uint32_t)positionAfterauthState);
  uint16_t authScope = (uint16_t)(uint32_t)r0;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterauthScope);
  uint64_t positionAfterPartition81;
  if (hasBytes2)
  {
    positionAfterPartition81 = positionAfterauthScope + 4ULL;
  }
  else
  {
    positionAfterPartition81 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthScope);
  }
  uint64_t positionAfterr0PathId;
  if (EverParseIsSuccess(positionAfterPartition81))
  {
    positionAfterr0PathId = positionAfterPartition81;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r0_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition81),
      EverParseGetValidatorErrorKind(positionAfterPartition81),
      Ctxt,
      Input,
      positionAfterauthScope);
    positionAfterr0PathId = positionAfterPartition81;
  }
  if (EverParseIsError(positionAfterr0PathId))
  {
    return positionAfterr0PathId;
  }
  uint32_t r0PathId = Load32Le(Input + (uint32_t)positionAfterauthScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterr0PathId);
  uint64_t positionAfterPartition82;
  if (hasBytes3)
  {
    positionAfterPartition82 = positionAfterr0PathId + 1ULL;
  }
  else
  {
    positionAfterPartition82 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathId);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterPartition82))
  {
    positionAfterr0Method = positionAfterPartition82;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterPartition82),
      EverParseGetValidatorErrorKind(positionAfterPartition82),
      Ctxt,
      Input,
      positionAfterr0PathId);
    positionAfterr0Method = positionAfterPartition82;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterPartition83;
  if (hasBytes4)
  {
    positionAfterPartition83 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterPartition83 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterPartition83))
  {
    positionAfterr0MinRole = positionAfterPartition83;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition83),
      EverParseGetValidatorErrorKind(positionAfterPartition83),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterPartition83;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes5 = 2ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterPartition84;
  if (hasBytes5)
  {
    positionAfterPartition84 = positionAfterr0MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition84 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr0ReqScope;
  if (EverParseIsSuccess(positionAfterPartition84))
  {
    positionAfterr0ReqScope = positionAfterPartition84;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r0_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition84),
      EverParseGetValidatorErrorKind(positionAfterPartition84),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr0ReqScope = positionAfterPartition84;
  }
  if (EverParseIsError(positionAfterr0ReqScope))
  {
    return positionAfterr0ReqScope;
  }
  uint16_t r1 = Load16Le(Input + (uint32_t)positionAfterr0MinRole);
  uint16_t r0ReqScope = (uint16_t)(uint32_t)r1;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes6 = 4ULL <= (InputLength - positionAfterr0ReqScope);
  uint64_t positionAfterPartition85;
  if (hasBytes6)
  {
    positionAfterPartition85 = positionAfterr0ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition85 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0ReqScope);
  }
  uint64_t positionAfterr1PathId;
  if (EverParseIsSuccess(positionAfterPartition85))
  {
    positionAfterr1PathId = positionAfterPartition85;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r1_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition85),
      EverParseGetValidatorErrorKind(positionAfterPartition85),
      Ctxt,
      Input,
      positionAfterr0ReqScope);
    positionAfterr1PathId = positionAfterPartition85;
  }
  if (EverParseIsError(positionAfterr1PathId))
  {
    return positionAfterr1PathId;
  }
  uint32_t r1PathId = Load32Le(Input + (uint32_t)positionAfterr0ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterr1PathId);
  uint64_t positionAfterPartition86;
  if (hasBytes7)
  {
    positionAfterPartition86 = positionAfterr1PathId + 1ULL;
  }
  else
  {
    positionAfterPartition86 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathId);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterPartition86))
  {
    positionAfterr1Method = positionAfterPartition86;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterPartition86),
      EverParseGetValidatorErrorKind(positionAfterPartition86),
      Ctxt,
      Input,
      positionAfterr1PathId);
    positionAfterr1Method = positionAfterPartition86;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterPartition87;
  if (hasBytes8)
  {
    positionAfterPartition87 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterPartition87 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterPartition87))
  {
    positionAfterr1MinRole = positionAfterPartition87;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition87),
      EverParseGetValidatorErrorKind(positionAfterPartition87),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterPartition87;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes9 = 2ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterPartition88;
  if (hasBytes9)
  {
    positionAfterPartition88 = positionAfterr1MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition88 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr1ReqScope;
  if (EverParseIsSuccess(positionAfterPartition88))
  {
    positionAfterr1ReqScope = positionAfterPartition88;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r1_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition88),
      EverParseGetValidatorErrorKind(positionAfterPartition88),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr1ReqScope = positionAfterPartition88;
  }
  if (EverParseIsError(positionAfterr1ReqScope))
  {
    return positionAfterr1ReqScope;
  }
  uint16_t r2 = Load16Le(Input + (uint32_t)positionAfterr1MinRole);
  uint16_t r1ReqScope = (uint16_t)(uint32_t)r2;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes10 = 4ULL <= (InputLength - positionAfterr1ReqScope);
  uint64_t positionAfterPartition89;
  if (hasBytes10)
  {
    positionAfterPartition89 = positionAfterr1ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition89 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1ReqScope);
  }
  uint64_t positionAfterr2PathId;
  if (EverParseIsSuccess(positionAfterPartition89))
  {
    positionAfterr2PathId = positionAfterPartition89;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r2_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition89),
      EverParseGetValidatorErrorKind(positionAfterPartition89),
      Ctxt,
      Input,
      positionAfterr1ReqScope);
    positionAfterr2PathId = positionAfterPartition89;
  }
  if (EverParseIsError(positionAfterr2PathId))
  {
    return positionAfterr2PathId;
  }
  uint32_t r2PathId = Load32Le(Input + (uint32_t)positionAfterr1ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterr2PathId);
  uint64_t positionAfterPartition810;
  if (hasBytes11)
  {
    positionAfterPartition810 = positionAfterr2PathId + 1ULL;
  }
  else
  {
    positionAfterPartition810 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathId);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterPartition810))
  {
    positionAfterr2Method = positionAfterPartition810;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterPartition810),
      EverParseGetValidatorErrorKind(positionAfterPartition810),
      Ctxt,
      Input,
      positionAfterr2PathId);
    positionAfterr2Method = positionAfterPartition810;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes12 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterPartition811;
  if (hasBytes12)
  {
    positionAfterPartition811 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterPartition811 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterPartition811))
  {
    positionAfterr2MinRole = positionAfterPartition811;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition811),
      EverParseGetValidatorErrorKind(positionAfterPartition811),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterPartition811;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes13 = 2ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterPartition812;
  if (hasBytes13)
  {
    positionAfterPartition812 = positionAfterr2MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition812 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr2ReqScope;
  if (EverParseIsSuccess(positionAfterPartition812))
  {
    positionAfterr2ReqScope = positionAfterPartition812;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r2_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition812),
      EverParseGetValidatorErrorKind(positionAfterPartition812),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr2ReqScope = positionAfterPartition812;
  }
  if (EverParseIsError(positionAfterr2ReqScope))
  {
    return positionAfterr2ReqScope;
  }
  uint16_t r3 = Load16Le(Input + (uint32_t)positionAfterr2MinRole);
  uint16_t r2ReqScope = (uint16_t)(uint32_t)r3;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes14 = 4ULL <= (InputLength - positionAfterr2ReqScope);
  uint64_t positionAfterPartition813;
  if (hasBytes14)
  {
    positionAfterPartition813 = positionAfterr2ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition813 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2ReqScope);
  }
  uint64_t positionAfterr3PathId;
  if (EverParseIsSuccess(positionAfterPartition813))
  {
    positionAfterr3PathId = positionAfterPartition813;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r3_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition813),
      EverParseGetValidatorErrorKind(positionAfterPartition813),
      Ctxt,
      Input,
      positionAfterr2ReqScope);
    positionAfterr3PathId = positionAfterPartition813;
  }
  if (EverParseIsError(positionAfterr3PathId))
  {
    return positionAfterr3PathId;
  }
  uint32_t r3PathId = Load32Le(Input + (uint32_t)positionAfterr2ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes15 = 1ULL <= (InputLength - positionAfterr3PathId);
  uint64_t positionAfterPartition814;
  if (hasBytes15)
  {
    positionAfterPartition814 = positionAfterr3PathId + 1ULL;
  }
  else
  {
    positionAfterPartition814 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathId);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterPartition814))
  {
    positionAfterr3Method = positionAfterPartition814;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterPartition814),
      EverParseGetValidatorErrorKind(positionAfterPartition814),
      Ctxt,
      Input,
      positionAfterr3PathId);
    positionAfterr3Method = positionAfterPartition814;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterPartition815;
  if (hasBytes16)
  {
    positionAfterPartition815 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterPartition815 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterPartition815))
  {
    positionAfterr3MinRole = positionAfterPartition815;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition815),
      EverParseGetValidatorErrorKind(positionAfterPartition815),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterPartition815;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes17 = 2ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterPartition816;
  if (hasBytes17)
  {
    positionAfterPartition816 = positionAfterr3MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition816 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr3ReqScope;
  if (EverParseIsSuccess(positionAfterPartition816))
  {
    positionAfterr3ReqScope = positionAfterPartition816;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r3_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition816),
      EverParseGetValidatorErrorKind(positionAfterPartition816),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr3ReqScope = positionAfterPartition816;
  }
  if (EverParseIsError(positionAfterr3ReqScope))
  {
    return positionAfterr3ReqScope;
  }
  uint16_t r4 = Load16Le(Input + (uint32_t)positionAfterr3MinRole);
  uint16_t r3ReqScope = (uint16_t)(uint32_t)r4;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterr3ReqScope);
  uint64_t positionAfterPartition817;
  if (hasBytes18)
  {
    positionAfterPartition817 = positionAfterr3ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition817 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3ReqScope);
  }
  uint64_t positionAfterr4PathId;
  if (EverParseIsSuccess(positionAfterPartition817))
  {
    positionAfterr4PathId = positionAfterPartition817;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r4_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition817),
      EverParseGetValidatorErrorKind(positionAfterPartition817),
      Ctxt,
      Input,
      positionAfterr3ReqScope);
    positionAfterr4PathId = positionAfterPartition817;
  }
  if (EverParseIsError(positionAfterr4PathId))
  {
    return positionAfterr4PathId;
  }
  uint32_t r4PathId = Load32Le(Input + (uint32_t)positionAfterr3ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterr4PathId);
  uint64_t positionAfterPartition818;
  if (hasBytes19)
  {
    positionAfterPartition818 = positionAfterr4PathId + 1ULL;
  }
  else
  {
    positionAfterPartition818 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathId);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterPartition818))
  {
    positionAfterr4Method = positionAfterPartition818;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterPartition818),
      EverParseGetValidatorErrorKind(positionAfterPartition818),
      Ctxt,
      Input,
      positionAfterr4PathId);
    positionAfterr4Method = positionAfterPartition818;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterPartition819;
  if (hasBytes20)
  {
    positionAfterPartition819 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterPartition819 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterPartition819))
  {
    positionAfterr4MinRole = positionAfterPartition819;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition819),
      EverParseGetValidatorErrorKind(positionAfterPartition819),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterPartition819;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes21 = 2ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterPartition820;
  if (hasBytes21)
  {
    positionAfterPartition820 = positionAfterr4MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition820 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr4ReqScope;
  if (EverParseIsSuccess(positionAfterPartition820))
  {
    positionAfterr4ReqScope = positionAfterPartition820;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r4_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition820),
      EverParseGetValidatorErrorKind(positionAfterPartition820),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr4ReqScope = positionAfterPartition820;
  }
  if (EverParseIsError(positionAfterr4ReqScope))
  {
    return positionAfterr4ReqScope;
  }
  uint16_t r5 = Load16Le(Input + (uint32_t)positionAfterr4MinRole);
  uint16_t r4ReqScope = (uint16_t)(uint32_t)r5;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes22 = 4ULL <= (InputLength - positionAfterr4ReqScope);
  uint64_t positionAfterPartition821;
  if (hasBytes22)
  {
    positionAfterPartition821 = positionAfterr4ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition821 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4ReqScope);
  }
  uint64_t positionAfterr5PathId;
  if (EverParseIsSuccess(positionAfterPartition821))
  {
    positionAfterr5PathId = positionAfterPartition821;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r5_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition821),
      EverParseGetValidatorErrorKind(positionAfterPartition821),
      Ctxt,
      Input,
      positionAfterr4ReqScope);
    positionAfterr5PathId = positionAfterPartition821;
  }
  if (EverParseIsError(positionAfterr5PathId))
  {
    return positionAfterr5PathId;
  }
  uint32_t r5PathId = Load32Le(Input + (uint32_t)positionAfterr4ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes23 = 1ULL <= (InputLength - positionAfterr5PathId);
  uint64_t positionAfterPartition822;
  if (hasBytes23)
  {
    positionAfterPartition822 = positionAfterr5PathId + 1ULL;
  }
  else
  {
    positionAfterPartition822 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathId);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterPartition822))
  {
    positionAfterr5Method = positionAfterPartition822;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterPartition822),
      EverParseGetValidatorErrorKind(positionAfterPartition822),
      Ctxt,
      Input,
      positionAfterr5PathId);
    positionAfterr5Method = positionAfterPartition822;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes24 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterPartition823;
  if (hasBytes24)
  {
    positionAfterPartition823 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterPartition823 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterPartition823))
  {
    positionAfterr5MinRole = positionAfterPartition823;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition823),
      EverParseGetValidatorErrorKind(positionAfterPartition823),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterPartition823;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes25 = 2ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterPartition824;
  if (hasBytes25)
  {
    positionAfterPartition824 = positionAfterr5MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition824 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr5ReqScope;
  if (EverParseIsSuccess(positionAfterPartition824))
  {
    positionAfterr5ReqScope = positionAfterPartition824;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r5_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition824),
      EverParseGetValidatorErrorKind(positionAfterPartition824),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr5ReqScope = positionAfterPartition824;
  }
  if (EverParseIsError(positionAfterr5ReqScope))
  {
    return positionAfterr5ReqScope;
  }
  uint16_t r6 = Load16Le(Input + (uint32_t)positionAfterr5MinRole);
  uint16_t r5ReqScope = (uint16_t)(uint32_t)r6;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes26 = 4ULL <= (InputLength - positionAfterr5ReqScope);
  uint64_t positionAfterPartition825;
  if (hasBytes26)
  {
    positionAfterPartition825 = positionAfterr5ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition825 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5ReqScope);
  }
  uint64_t positionAfterr6PathId;
  if (EverParseIsSuccess(positionAfterPartition825))
  {
    positionAfterr6PathId = positionAfterPartition825;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r6_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition825),
      EverParseGetValidatorErrorKind(positionAfterPartition825),
      Ctxt,
      Input,
      positionAfterr5ReqScope);
    positionAfterr6PathId = positionAfterPartition825;
  }
  if (EverParseIsError(positionAfterr6PathId))
  {
    return positionAfterr6PathId;
  }
  uint32_t r6PathId = Load32Le(Input + (uint32_t)positionAfterr5ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes27 = 1ULL <= (InputLength - positionAfterr6PathId);
  uint64_t positionAfterPartition826;
  if (hasBytes27)
  {
    positionAfterPartition826 = positionAfterr6PathId + 1ULL;
  }
  else
  {
    positionAfterPartition826 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathId);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterPartition826))
  {
    positionAfterr6Method = positionAfterPartition826;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterPartition826),
      EverParseGetValidatorErrorKind(positionAfterPartition826),
      Ctxt,
      Input,
      positionAfterr6PathId);
    positionAfterr6Method = positionAfterPartition826;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterPartition827;
  if (hasBytes28)
  {
    positionAfterPartition827 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterPartition827 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterPartition827))
  {
    positionAfterr6MinRole = positionAfterPartition827;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition827),
      EverParseGetValidatorErrorKind(positionAfterPartition827),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterPartition827;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes29 = 2ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterPartition828;
  if (hasBytes29)
  {
    positionAfterPartition828 = positionAfterr6MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition828 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr6ReqScope;
  if (EverParseIsSuccess(positionAfterPartition828))
  {
    positionAfterr6ReqScope = positionAfterPartition828;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r6_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition828),
      EverParseGetValidatorErrorKind(positionAfterPartition828),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr6ReqScope = positionAfterPartition828;
  }
  if (EverParseIsError(positionAfterr6ReqScope))
  {
    return positionAfterr6ReqScope;
  }
  uint16_t r7 = Load16Le(Input + (uint32_t)positionAfterr6MinRole);
  uint16_t r6ReqScope = (uint16_t)(uint32_t)r7;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes30 = 4ULL <= (InputLength - positionAfterr6ReqScope);
  uint64_t positionAfterPartition829;
  if (hasBytes30)
  {
    positionAfterPartition829 = positionAfterr6ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition829 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6ReqScope);
  }
  uint64_t positionAfterr7PathId;
  if (EverParseIsSuccess(positionAfterPartition829))
  {
    positionAfterr7PathId = positionAfterPartition829;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r7_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition829),
      EverParseGetValidatorErrorKind(positionAfterPartition829),
      Ctxt,
      Input,
      positionAfterr6ReqScope);
    positionAfterr7PathId = positionAfterPartition829;
  }
  if (EverParseIsError(positionAfterr7PathId))
  {
    return positionAfterr7PathId;
  }
  uint32_t r7PathId = Load32Le(Input + (uint32_t)positionAfterr6ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes31 = 1ULL <= (InputLength - positionAfterr7PathId);
  uint64_t positionAfterPartition830;
  if (hasBytes31)
  {
    positionAfterPartition830 = positionAfterr7PathId + 1ULL;
  }
  else
  {
    positionAfterPartition830 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathId);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterPartition830))
  {
    positionAfterr7Method = positionAfterPartition830;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterPartition830),
      EverParseGetValidatorErrorKind(positionAfterPartition830),
      Ctxt,
      Input,
      positionAfterr7PathId);
    positionAfterr7Method = positionAfterPartition830;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathId];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes32 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterPartition831;
  if (hasBytes32)
  {
    positionAfterPartition831 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterPartition831 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterPartition831))
  {
    positionAfterr7MinRole = positionAfterPartition831;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterPartition831),
      EverParseGetValidatorErrorKind(positionAfterPartition831),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterPartition831;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes33 = 2ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterPartition832;
  if (hasBytes33)
  {
    positionAfterPartition832 = positionAfterr7MinRole + 2ULL;
  }
  else
  {
    positionAfterPartition832 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterr7ReqScope;
  if (EverParseIsSuccess(positionAfterPartition832))
  {
    positionAfterr7ReqScope = positionAfterPartition832;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "r7_req_scope",
      EverParseErrorReasonOfResult(positionAfterPartition832),
      EverParseGetValidatorErrorKind(positionAfterPartition832),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterr7ReqScope = positionAfterPartition832;
  }
  if (EverParseIsError(positionAfterr7ReqScope))
  {
    return positionAfterr7ReqScope;
  }
  uint16_t r = Load16Le(Input + (uint32_t)positionAfterr7MinRole);
  uint16_t r7ReqScope = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes34 = 4ULL <= (InputLength - positionAfterr7ReqScope);
  uint64_t positionAfterPartition833;
  if (hasBytes34)
  {
    positionAfterPartition833 = positionAfterr7ReqScope + 4ULL;
  }
  else
  {
    positionAfterPartition833 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7ReqScope);
  }
  uint64_t positionAfterreqPathId;
  if (EverParseIsSuccess(positionAfterPartition833))
  {
    positionAfterreqPathId = positionAfterPartition833;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "req_path_id",
      EverParseErrorReasonOfResult(positionAfterPartition833),
      EverParseGetValidatorErrorKind(positionAfterPartition833),
      Ctxt,
      Input,
      positionAfterr7ReqScope);
    positionAfterreqPathId = positionAfterPartition833;
  }
  if (EverParseIsError(positionAfterreqPathId))
  {
    return positionAfterreqPathId;
  }
  uint32_t reqPathId = Load32Le(Input + (uint32_t)positionAfterr7ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes35 = 1ULL <= (InputLength - positionAfterreqPathId);
  uint64_t positionAfterPartition834;
  if (hasBytes35)
  {
    positionAfterPartition834 = positionAfterreqPathId + 1ULL;
  }
  else
  {
    positionAfterPartition834 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathId);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterPartition834))
  {
    positionAfterreqMethod = positionAfterPartition834;
  }
  else
  {
    ErrorHandlerFn("_Partition8",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterPartition834),
      EverParseGetValidatorErrorKind(positionAfterPartition834),
      Ctxt,
      Input,
      positionAfterreqPathId);
    positionAfterreqMethod = positionAfterPartition834;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathId];
  /* Validating field _access_ok */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterAccessOk_refinement;
  if (hasBytes)
  {
    positionAfterAccessOk_refinement = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterAccessOk_refinement =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterPartition835;
  if (EverParseIsError(positionAfterAccessOk_refinement))
  {
    positionAfterPartition835 = positionAfterAccessOk_refinement;
  }
  else
  {
    /* reading field_value */
    uint8_t accessOk_refinement = Input[(uint32_t)positionAfterreqMethod];
    KRML_MAYBE_UNUSED_VAR(accessOk_refinement);
    /* start: checking constraint */
    BOOLEAN
    accessOk_refinementConstraintIsOk =
      (r0PathId == reqPathId && ((uint32_t)r0Method & (uint32_t)reqMethod) == reqMethod &&
        authState >= r0MinRole
      && ((uint32_t)authScope & (uint32_t)r0ReqScope) == r0ReqScope)
      ||
        (r1PathId == reqPathId && ((uint32_t)r1Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r1MinRole
        && ((uint32_t)authScope & (uint32_t)r1ReqScope) == r1ReqScope)
      ||
        (r2PathId == reqPathId && ((uint32_t)r2Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r2MinRole
        && ((uint32_t)authScope & (uint32_t)r2ReqScope) == r2ReqScope)
      ||
        (r3PathId == reqPathId && ((uint32_t)r3Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r3MinRole
        && ((uint32_t)authScope & (uint32_t)r3ReqScope) == r3ReqScope)
      ||
        (r4PathId == reqPathId && ((uint32_t)r4Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r4MinRole
        && ((uint32_t)authScope & (uint32_t)r4ReqScope) == r4ReqScope)
      ||
        (r5PathId == reqPathId && ((uint32_t)r5Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r5MinRole
        && ((uint32_t)authScope & (uint32_t)r5ReqScope) == r5ReqScope)
      ||
        (r6PathId == reqPathId && ((uint32_t)r6Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r6MinRole
        && ((uint32_t)authScope & (uint32_t)r6ReqScope) == r6ReqScope)
      ||
        (r7PathId == reqPathId && ((uint32_t)r7Method & (uint32_t)reqMethod) == reqMethod &&
          authState >= r7MinRole
        && ((uint32_t)authScope & (uint32_t)r7ReqScope) == r7ReqScope);
    /* end: checking constraint */
    positionAfterPartition835 =
      EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
        positionAfterAccessOk_refinement);
  }
  if (EverParseIsSuccess(positionAfterPartition835))
  {
    return positionAfterPartition835;
  }
  ErrorHandlerFn("_Partition8",
    "_access_ok.refinement",
    EverParseErrorReasonOfResult(positionAfterPartition835),
    EverParseGetValidatorErrorKind(positionAfterPartition835),
    Ctxt,
    Input,
    positionAfterreqMethod);
  return positionAfterPartition835;
}

