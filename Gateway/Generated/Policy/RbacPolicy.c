

#include "RbacPolicy.h"

uint64_t
RbacPolicyValidateLoginRequest(
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
  /* Validating field auth_state */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes0 = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterLoginRequest;
  if (hasBytes0)
  {
    positionAfterLoginRequest = StartPosition + 1ULL;
  }
  else
  {
    positionAfterLoginRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterLoginRequest))
  {
    res0 = positionAfterLoginRequest;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterLoginRequest),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest),
      Ctxt,
      Input,
      StartPosition);
    res0 = positionAfterLoginRequest;
  }
  uint64_t positionAfterauthState = res0;
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterLoginRequest0;
  if (hasBytes1)
  {
    positionAfterLoginRequest0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterLoginRequest0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterLoginRequest0))
  {
    positionAfterrateCount = positionAfterLoginRequest0;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterLoginRequest0),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterLoginRequest0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterLoginRequest1;
  if (hasBytes2)
  {
    positionAfterLoginRequest1 = positionAfterrateCount + 4ULL;
  }
  else
  {
    positionAfterLoginRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterpathHash;
  if (EverParseIsSuccess(positionAfterLoginRequest1))
  {
    positionAfterpathHash = positionAfterLoginRequest1;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "path_hash",
      EverParseErrorReasonOfResult(positionAfterLoginRequest1),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfterpathHash = positionAfterLoginRequest1;
  }
  if (EverParseIsError(positionAfterpathHash))
  {
    return positionAfterpathHash;
  }
  uint32_t pathHash = Load32Le(Input + (uint32_t)positionAfterrateCount);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes3 = 1ULL <= (InputLength - positionAfterpathHash);
  uint64_t positionAfterLoginRequest2;
  if (hasBytes3)
  {
    positionAfterLoginRequest2 = positionAfterpathHash + 1ULL;
  }
  else
  {
    positionAfterLoginRequest2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterpathHash);
  }
  uint64_t positionAftermethod;
  if (EverParseIsSuccess(positionAfterLoginRequest2))
  {
    positionAftermethod = positionAfterLoginRequest2;
  }
  else
  {
    ErrorHandlerFn("_LoginRequest",
      "method",
      EverParseErrorReasonOfResult(positionAfterLoginRequest2),
      EverParseGetValidatorErrorKind(positionAfterLoginRequest2),
      Ctxt,
      Input,
      positionAfterpathHash);
    positionAftermethod = positionAfterLoginRequest2;
  }
  if (EverParseIsError(positionAftermethod))
  {
    return positionAftermethod;
  }
  uint8_t method = Input[(uint32_t)positionAfterpathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAftermethod);
  uint64_t positionAfterCheck;
  if (hasBytes4)
  {
    positionAfterCheck = positionAftermethod + 1ULL;
  }
  else
  {
    positionAfterCheck =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftermethod);
  }
  uint64_t positionAfterLoginRequest3;
  if (EverParseIsError(positionAfterCheck))
  {
    positionAfterLoginRequest3 = positionAfterCheck;
  }
  else
  {
    uint8_t check = Input[(uint32_t)positionAftermethod];
    KRML_MAYBE_UNUSED_VAR(check);
    BOOLEAN
    checkConstraintIsOk =
      pathHash == RBACPOLICY____PATH_LOGIN && method == RBACPOLICY____METHOD_POST &&
        rateCount < RBACPOLICY____MAX_RATE;
    uint64_t
    positionAfterCheck1 = EverParseCheckConstraintOk(checkConstraintIsOk, positionAfterCheck);
    if (EverParseIsError(positionAfterCheck1))
    {
      positionAfterLoginRequest3 = positionAfterCheck1;
    }
    else
    {
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterCheck1);
      uint64_t positionAfterusernameLen;
      if (hasBytes5)
      {
        positionAfterusernameLen = positionAfterCheck1 + 1ULL;
      }
      else
      {
        positionAfterusernameLen =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterCheck1);
      }
      uint64_t positionAfterLoginRequest4;
      if (EverParseIsError(positionAfterusernameLen))
      {
        positionAfterLoginRequest4 = positionAfterusernameLen;
      }
      else
      {
        uint8_t usernameLen = Input[(uint32_t)positionAfterCheck1];
        BOOLEAN usernameLenConstraintIsOk = usernameLen >= 1U && usernameLen <= 32U;
        uint64_t
        positionAfterusernameLen1 =
          EverParseCheckConstraintOk(usernameLenConstraintIsOk,
            positionAfterusernameLen);
        if (EverParseIsError(positionAfterusernameLen1))
        {
          positionAfterLoginRequest4 = positionAfterusernameLen1;
        }
        else
        {
          /* Validating field username */
          BOOLEAN
          hasBytes6 = (uint64_t)(uint32_t)usernameLen <= (InputLength - positionAfterusernameLen1);
          uint64_t res1;
          if (hasBytes6)
          {
            res1 = positionAfterusernameLen1 + (uint64_t)(uint32_t)usernameLen;
          }
          else
          {
            res1 =
              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterusernameLen1);
          }
          uint64_t positionAfterLoginRequest5 = res1;
          uint64_t positionAfterusername;
          if (EverParseIsSuccess(positionAfterLoginRequest5))
          {
            positionAfterusername = positionAfterLoginRequest5;
          }
          else
          {
            ErrorHandlerFn("_LoginRequest",
              "username",
              EverParseErrorReasonOfResult(positionAfterLoginRequest5),
              EverParseGetValidatorErrorKind(positionAfterLoginRequest5),
              Ctxt,
              Input,
              positionAfterusernameLen1);
            positionAfterusername = positionAfterLoginRequest5;
          }
          if (EverParseIsError(positionAfterusername))
          {
            positionAfterLoginRequest4 = positionAfterusername;
          }
          else
          {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterusername);
            uint64_t positionAfterpasswordLen;
            if (hasBytes7)
            {
              positionAfterpasswordLen = positionAfterusername + 1ULL;
            }
            else
            {
              positionAfterpasswordLen =
                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                  positionAfterusername);
            }
            uint64_t positionAfterLoginRequest6;
            if (EverParseIsError(positionAfterpasswordLen))
            {
              positionAfterLoginRequest6 = positionAfterpasswordLen;
            }
            else
            {
              uint8_t passwordLen = Input[(uint32_t)positionAfterusername];
              BOOLEAN passwordLenConstraintIsOk = passwordLen >= 1U && passwordLen <= 64U;
              uint64_t
              positionAfterpasswordLen1 =
                EverParseCheckConstraintOk(passwordLenConstraintIsOk,
                  positionAfterpasswordLen);
              if (EverParseIsError(positionAfterpasswordLen1))
              {
                positionAfterLoginRequest6 = positionAfterpasswordLen1;
              }
              else
              {
                /* Validating field password */
                BOOLEAN
                hasBytes =
                  (uint64_t)(uint32_t)passwordLen <= (InputLength - positionAfterpasswordLen1);
                uint64_t res;
                if (hasBytes)
                {
                  res = positionAfterpasswordLen1 + (uint64_t)(uint32_t)passwordLen;
                }
                else
                {
                  res =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                      positionAfterpasswordLen1);
                }
                uint64_t positionAfterLoginRequest7 = res;
                if (EverParseIsSuccess(positionAfterLoginRequest7))
                {
                  positionAfterLoginRequest6 = positionAfterLoginRequest7;
                }
                else
                {
                  ErrorHandlerFn("_LoginRequest",
                    "password",
                    EverParseErrorReasonOfResult(positionAfterLoginRequest7),
                    EverParseGetValidatorErrorKind(positionAfterLoginRequest7),
                    Ctxt,
                    Input,
                    positionAfterpasswordLen1);
                  positionAfterLoginRequest6 = positionAfterLoginRequest7;
                }
              }
            }
            if (EverParseIsSuccess(positionAfterLoginRequest6))
            {
              positionAfterLoginRequest4 = positionAfterLoginRequest6;
            }
            else
            {
              ErrorHandlerFn("_LoginRequest",
                "password_len",
                EverParseErrorReasonOfResult(positionAfterLoginRequest6),
                EverParseGetValidatorErrorKind(positionAfterLoginRequest6),
                Ctxt,
                Input,
                positionAfterusername);
              positionAfterLoginRequest4 = positionAfterLoginRequest6;
            }
          }
        }
      }
      if (EverParseIsSuccess(positionAfterLoginRequest4))
      {
        positionAfterLoginRequest3 = positionAfterLoginRequest4;
      }
      else
      {
        ErrorHandlerFn("_LoginRequest",
          "username_len",
          EverParseErrorReasonOfResult(positionAfterLoginRequest4),
          EverParseGetValidatorErrorKind(positionAfterLoginRequest4),
          Ctxt,
          Input,
          positionAfterCheck1);
        positionAfterLoginRequest3 = positionAfterLoginRequest4;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterLoginRequest3))
  {
    return positionAfterLoginRequest3;
  }
  ErrorHandlerFn("_LoginRequest",
    "_check",
    EverParseErrorReasonOfResult(positionAfterLoginRequest3),
    EverParseGetValidatorErrorKind(positionAfterLoginRequest3),
    Ctxt,
    Input,
    positionAftermethod);
  return positionAfterLoginRequest3;
}

uint64_t
RbacPolicyValidatePolicyBlob(
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
  uint64_t positionAfterPolicyBlob;
  if (hasBytes0)
  {
    positionAfterPolicyBlob = StartPosition + 1ULL;
  }
  else
  {
    positionAfterPolicyBlob =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterPolicyBlob))
  {
    positionAfterauthState = positionAfterPolicyBlob;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterPolicyBlob;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterPolicyBlob0;
  if (hasBytes1)
  {
    positionAfterPolicyBlob0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterPolicyBlob0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterPolicyBlob0))
  {
    positionAfterrateCount = positionAfterPolicyBlob0;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob0),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterPolicyBlob0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterPolicyBlob1;
  if (hasBytes2)
  {
    positionAfterPolicyBlob1 = positionAfterrateCount + 1ULL;
  }
  else
  {
    positionAfterPolicyBlob1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfternumRules;
  if (EverParseIsSuccess(positionAfterPolicyBlob1))
  {
    positionAfternumRules = positionAfterPolicyBlob1;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "num_rules",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob1),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfternumRules = positionAfterPolicyBlob1;
  }
  if (EverParseIsError(positionAfternumRules))
  {
    return positionAfternumRules;
  }
  uint8_t numRules = Input[(uint32_t)positionAfterrateCount];
  /* Validating field r0_path_hash */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfternumRules);
  uint64_t positionAfterPolicyBlob2;
  if (hasBytes3)
  {
    positionAfterPolicyBlob2 = positionAfternumRules + 4ULL;
  }
  else
  {
    positionAfterPolicyBlob2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfternumRules);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterPolicyBlob2))
  {
    res0 = positionAfterPolicyBlob2;
  }
  else
  {
    ErrorHandlerFn("_PolicyBlob",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterPolicyBlob2),
      EverParseGetValidatorErrorKind(positionAfterPolicyBlob2),
      Ctxt,
      Input,
      positionAfternumRules);
    res0 = positionAfterPolicyBlob2;
  }
  uint64_t positionAfterr0PathHash = res0;
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterr0Method;
  if (hasBytes4)
  {
    positionAfterr0Method = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterr0Method =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterPolicyBlob3;
  if (EverParseIsError(positionAfterr0Method))
  {
    positionAfterPolicyBlob3 = positionAfterr0Method;
  }
  else
  {
    uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
    BOOLEAN r0MethodConstraintIsOk = r0Method <= 3U;
    uint64_t
    positionAfterr0Method1 =
      EverParseCheckConstraintOk(r0MethodConstraintIsOk,
        positionAfterr0Method);
    if (EverParseIsError(positionAfterr0Method1))
    {
      positionAfterPolicyBlob3 = positionAfterr0Method1;
    }
    else
    {
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr0Method1);
      uint64_t positionAfterr0MinRole;
      if (hasBytes5)
      {
        positionAfterr0MinRole = positionAfterr0Method1 + 1ULL;
      }
      else
      {
        positionAfterr0MinRole =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterr0Method1);
      }
      uint64_t positionAfterPolicyBlob4;
      if (EverParseIsError(positionAfterr0MinRole))
      {
        positionAfterPolicyBlob4 = positionAfterr0MinRole;
      }
      else
      {
        uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method1];
        BOOLEAN r0MinRoleConstraintIsOk = r0MinRole <= 2U;
        uint64_t
        positionAfterr0MinRole1 =
          EverParseCheckConstraintOk(r0MinRoleConstraintIsOk,
            positionAfterr0MinRole);
        if (EverParseIsError(positionAfterr0MinRole1))
        {
          positionAfterPolicyBlob4 = positionAfterr0MinRole1;
        }
        else
        {
          /* Validating field r0_req_scope */
          /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
          BOOLEAN hasBytes6 = 2ULL <= (InputLength - positionAfterr0MinRole1);
          uint64_t positionAfterPolicyBlob5;
          if (hasBytes6)
          {
            positionAfterPolicyBlob5 = positionAfterr0MinRole1 + 2ULL;
          }
          else
          {
            positionAfterPolicyBlob5 =
              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterr0MinRole1);
          }
          uint64_t res1;
          if (EverParseIsSuccess(positionAfterPolicyBlob5))
          {
            res1 = positionAfterPolicyBlob5;
          }
          else
          {
            ErrorHandlerFn("_PolicyBlob",
              "r0_req_scope",
              EverParseErrorReasonOfResult(positionAfterPolicyBlob5),
              EverParseGetValidatorErrorKind(positionAfterPolicyBlob5),
              Ctxt,
              Input,
              positionAfterr0MinRole1);
            res1 = positionAfterPolicyBlob5;
          }
          uint64_t positionAfterr0ReqScope = res1;
          if (EverParseIsError(positionAfterr0ReqScope))
          {
            positionAfterPolicyBlob4 = positionAfterr0ReqScope;
          }
          else
          {
            /* Validating field r1_path_hash */
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes7 = 4ULL <= (InputLength - positionAfterr0ReqScope);
            uint64_t positionAfterPolicyBlob6;
            if (hasBytes7)
            {
              positionAfterPolicyBlob6 = positionAfterr0ReqScope + 4ULL;
            }
            else
            {
              positionAfterPolicyBlob6 =
                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                  positionAfterr0ReqScope);
            }
            uint64_t res2;
            if (EverParseIsSuccess(positionAfterPolicyBlob6))
            {
              res2 = positionAfterPolicyBlob6;
            }
            else
            {
              ErrorHandlerFn("_PolicyBlob",
                "r1_path_hash",
                EverParseErrorReasonOfResult(positionAfterPolicyBlob6),
                EverParseGetValidatorErrorKind(positionAfterPolicyBlob6),
                Ctxt,
                Input,
                positionAfterr0ReqScope);
              res2 = positionAfterPolicyBlob6;
            }
            uint64_t positionAfterr1PathHash = res2;
            if (EverParseIsError(positionAfterr1PathHash))
            {
              positionAfterPolicyBlob4 = positionAfterr1PathHash;
            }
            else
            {
              /* Checking that we have enough space for a UINT8, i.e., 1 byte */
              BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr1PathHash);
              uint64_t positionAfterr1Method;
              if (hasBytes8)
              {
                positionAfterr1Method = positionAfterr1PathHash + 1ULL;
              }
              else
              {
                positionAfterr1Method =
                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfterr1PathHash);
              }
              uint64_t positionAfterPolicyBlob7;
              if (EverParseIsError(positionAfterr1Method))
              {
                positionAfterPolicyBlob7 = positionAfterr1Method;
              }
              else
              {
                uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
                BOOLEAN r1MethodConstraintIsOk = r1Method <= 3U;
                uint64_t
                positionAfterr1Method1 =
                  EverParseCheckConstraintOk(r1MethodConstraintIsOk,
                    positionAfterr1Method);
                if (EverParseIsError(positionAfterr1Method1))
                {
                  positionAfterPolicyBlob7 = positionAfterr1Method1;
                }
                else
                {
                  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                  BOOLEAN hasBytes9 = 1ULL <= (InputLength - positionAfterr1Method1);
                  uint64_t positionAfterr1MinRole;
                  if (hasBytes9)
                  {
                    positionAfterr1MinRole = positionAfterr1Method1 + 1ULL;
                  }
                  else
                  {
                    positionAfterr1MinRole =
                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterr1Method1);
                  }
                  uint64_t positionAfterPolicyBlob8;
                  if (EverParseIsError(positionAfterr1MinRole))
                  {
                    positionAfterPolicyBlob8 = positionAfterr1MinRole;
                  }
                  else
                  {
                    uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method1];
                    BOOLEAN r1MinRoleConstraintIsOk = r1MinRole <= 2U;
                    uint64_t
                    positionAfterr1MinRole1 =
                      EverParseCheckConstraintOk(r1MinRoleConstraintIsOk,
                        positionAfterr1MinRole);
                    if (EverParseIsError(positionAfterr1MinRole1))
                    {
                      positionAfterPolicyBlob8 = positionAfterr1MinRole1;
                    }
                    else
                    {
                      /* Validating field r1_req_scope */
                      /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                      BOOLEAN hasBytes10 = 2ULL <= (InputLength - positionAfterr1MinRole1);
                      uint64_t positionAfterPolicyBlob9;
                      if (hasBytes10)
                      {
                        positionAfterPolicyBlob9 = positionAfterr1MinRole1 + 2ULL;
                      }
                      else
                      {
                        positionAfterPolicyBlob9 =
                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterr1MinRole1);
                      }
                      uint64_t res3;
                      if (EverParseIsSuccess(positionAfterPolicyBlob9))
                      {
                        res3 = positionAfterPolicyBlob9;
                      }
                      else
                      {
                        ErrorHandlerFn("_PolicyBlob",
                          "r1_req_scope",
                          EverParseErrorReasonOfResult(positionAfterPolicyBlob9),
                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob9),
                          Ctxt,
                          Input,
                          positionAfterr1MinRole1);
                        res3 = positionAfterPolicyBlob9;
                      }
                      uint64_t positionAfterr1ReqScope = res3;
                      if (EverParseIsError(positionAfterr1ReqScope))
                      {
                        positionAfterPolicyBlob8 = positionAfterr1ReqScope;
                      }
                      else
                      {
                        /* Validating field r2_path_hash */
                        /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                        BOOLEAN hasBytes11 = 4ULL <= (InputLength - positionAfterr1ReqScope);
                        uint64_t positionAfterPolicyBlob10;
                        if (hasBytes11)
                        {
                          positionAfterPolicyBlob10 = positionAfterr1ReqScope + 4ULL;
                        }
                        else
                        {
                          positionAfterPolicyBlob10 =
                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                              positionAfterr1ReqScope);
                        }
                        uint64_t res4;
                        if (EverParseIsSuccess(positionAfterPolicyBlob10))
                        {
                          res4 = positionAfterPolicyBlob10;
                        }
                        else
                        {
                          ErrorHandlerFn("_PolicyBlob",
                            "r2_path_hash",
                            EverParseErrorReasonOfResult(positionAfterPolicyBlob10),
                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob10),
                            Ctxt,
                            Input,
                            positionAfterr1ReqScope);
                          res4 = positionAfterPolicyBlob10;
                        }
                        uint64_t positionAfterr2PathHash = res4;
                        if (EverParseIsError(positionAfterr2PathHash))
                        {
                          positionAfterPolicyBlob8 = positionAfterr2PathHash;
                        }
                        else
                        {
                          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                          BOOLEAN hasBytes12 = 1ULL <= (InputLength - positionAfterr2PathHash);
                          uint64_t positionAfterr2Method;
                          if (hasBytes12)
                          {
                            positionAfterr2Method = positionAfterr2PathHash + 1ULL;
                          }
                          else
                          {
                            positionAfterr2Method =
                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterr2PathHash);
                          }
                          uint64_t positionAfterPolicyBlob11;
                          if (EverParseIsError(positionAfterr2Method))
                          {
                            positionAfterPolicyBlob11 = positionAfterr2Method;
                          }
                          else
                          {
                            uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
                            BOOLEAN r2MethodConstraintIsOk = r2Method <= 3U;
                            uint64_t
                            positionAfterr2Method1 =
                              EverParseCheckConstraintOk(r2MethodConstraintIsOk,
                                positionAfterr2Method);
                            if (EverParseIsError(positionAfterr2Method1))
                            {
                              positionAfterPolicyBlob11 = positionAfterr2Method1;
                            }
                            else
                            {
                              /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                              BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr2Method1);
                              uint64_t positionAfterr2MinRole;
                              if (hasBytes13)
                              {
                                positionAfterr2MinRole = positionAfterr2Method1 + 1ULL;
                              }
                              else
                              {
                                positionAfterr2MinRole =
                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterr2Method1);
                              }
                              uint64_t positionAfterPolicyBlob12;
                              if (EverParseIsError(positionAfterr2MinRole))
                              {
                                positionAfterPolicyBlob12 = positionAfterr2MinRole;
                              }
                              else
                              {
                                uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method1];
                                BOOLEAN r2MinRoleConstraintIsOk = r2MinRole <= 2U;
                                uint64_t
                                positionAfterr2MinRole1 =
                                  EverParseCheckConstraintOk(r2MinRoleConstraintIsOk,
                                    positionAfterr2MinRole);
                                if (EverParseIsError(positionAfterr2MinRole1))
                                {
                                  positionAfterPolicyBlob12 = positionAfterr2MinRole1;
                                }
                                else
                                {
                                  /* Validating field r2_req_scope */
                                  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                                  BOOLEAN
                                  hasBytes14 = 2ULL <= (InputLength - positionAfterr2MinRole1);
                                  uint64_t positionAfterPolicyBlob13;
                                  if (hasBytes14)
                                  {
                                    positionAfterPolicyBlob13 = positionAfterr2MinRole1 + 2ULL;
                                  }
                                  else
                                  {
                                    positionAfterPolicyBlob13 =
                                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfterr2MinRole1);
                                  }
                                  uint64_t res5;
                                  if (EverParseIsSuccess(positionAfterPolicyBlob13))
                                  {
                                    res5 = positionAfterPolicyBlob13;
                                  }
                                  else
                                  {
                                    ErrorHandlerFn("_PolicyBlob",
                                      "r2_req_scope",
                                      EverParseErrorReasonOfResult(positionAfterPolicyBlob13),
                                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob13),
                                      Ctxt,
                                      Input,
                                      positionAfterr2MinRole1);
                                    res5 = positionAfterPolicyBlob13;
                                  }
                                  uint64_t positionAfterr2ReqScope = res5;
                                  if (EverParseIsError(positionAfterr2ReqScope))
                                  {
                                    positionAfterPolicyBlob12 = positionAfterr2ReqScope;
                                  }
                                  else
                                  {
                                    /* Validating field r3_path_hash */
                                    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                    BOOLEAN
                                    hasBytes15 = 4ULL <= (InputLength - positionAfterr2ReqScope);
                                    uint64_t positionAfterPolicyBlob14;
                                    if (hasBytes15)
                                    {
                                      positionAfterPolicyBlob14 = positionAfterr2ReqScope + 4ULL;
                                    }
                                    else
                                    {
                                      positionAfterPolicyBlob14 =
                                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                          positionAfterr2ReqScope);
                                    }
                                    uint64_t res6;
                                    if (EverParseIsSuccess(positionAfterPolicyBlob14))
                                    {
                                      res6 = positionAfterPolicyBlob14;
                                    }
                                    else
                                    {
                                      ErrorHandlerFn("_PolicyBlob",
                                        "r3_path_hash",
                                        EverParseErrorReasonOfResult(positionAfterPolicyBlob14),
                                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob14),
                                        Ctxt,
                                        Input,
                                        positionAfterr2ReqScope);
                                      res6 = positionAfterPolicyBlob14;
                                    }
                                    uint64_t positionAfterr3PathHash = res6;
                                    if (EverParseIsError(positionAfterr3PathHash))
                                    {
                                      positionAfterPolicyBlob12 = positionAfterr3PathHash;
                                    }
                                    else
                                    {
                                      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                      BOOLEAN
                                      hasBytes16 = 1ULL <= (InputLength - positionAfterr3PathHash);
                                      uint64_t positionAfterr3Method;
                                      if (hasBytes16)
                                      {
                                        positionAfterr3Method = positionAfterr3PathHash + 1ULL;
                                      }
                                      else
                                      {
                                        positionAfterr3Method =
                                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            positionAfterr3PathHash);
                                      }
                                      uint64_t positionAfterPolicyBlob15;
                                      if (EverParseIsError(positionAfterr3Method))
                                      {
                                        positionAfterPolicyBlob15 = positionAfterr3Method;
                                      }
                                      else
                                      {
                                        uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
                                        BOOLEAN r3MethodConstraintIsOk = r3Method <= 3U;
                                        uint64_t
                                        positionAfterr3Method1 =
                                          EverParseCheckConstraintOk(r3MethodConstraintIsOk,
                                            positionAfterr3Method);
                                        if (EverParseIsError(positionAfterr3Method1))
                                        {
                                          positionAfterPolicyBlob15 = positionAfterr3Method1;
                                        }
                                        else
                                        {
                                          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                          BOOLEAN
                                          hasBytes17 =
                                            1ULL <= (InputLength - positionAfterr3Method1);
                                          uint64_t positionAfterr3MinRole;
                                          if (hasBytes17)
                                          {
                                            positionAfterr3MinRole = positionAfterr3Method1 + 1ULL;
                                          }
                                          else
                                          {
                                            positionAfterr3MinRole =
                                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                positionAfterr3Method1);
                                          }
                                          uint64_t positionAfterPolicyBlob16;
                                          if (EverParseIsError(positionAfterr3MinRole))
                                          {
                                            positionAfterPolicyBlob16 = positionAfterr3MinRole;
                                          }
                                          else
                                          {
                                            uint8_t
                                            r3MinRole = Input[(uint32_t)positionAfterr3Method1];
                                            BOOLEAN r3MinRoleConstraintIsOk = r3MinRole <= 2U;
                                            uint64_t
                                            positionAfterr3MinRole1 =
                                              EverParseCheckConstraintOk(r3MinRoleConstraintIsOk,
                                                positionAfterr3MinRole);
                                            if (EverParseIsError(positionAfterr3MinRole1))
                                            {
                                              positionAfterPolicyBlob16 = positionAfterr3MinRole1;
                                            }
                                            else
                                            {
                                              /* Validating field r3_req_scope */
                                              /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                                              BOOLEAN
                                              hasBytes18 =
                                                2ULL <= (InputLength - positionAfterr3MinRole1);
                                              uint64_t positionAfterPolicyBlob17;
                                              if (hasBytes18)
                                              {
                                                positionAfterPolicyBlob17 =
                                                  positionAfterr3MinRole1 + 2ULL;
                                              }
                                              else
                                              {
                                                positionAfterPolicyBlob17 =
                                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    positionAfterr3MinRole1);
                                              }
                                              uint64_t res7;
                                              if (EverParseIsSuccess(positionAfterPolicyBlob17))
                                              {
                                                res7 = positionAfterPolicyBlob17;
                                              }
                                              else
                                              {
                                                ErrorHandlerFn("_PolicyBlob",
                                                  "r3_req_scope",
                                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob17),
                                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob17),
                                                  Ctxt,
                                                  Input,
                                                  positionAfterr3MinRole1);
                                                res7 = positionAfterPolicyBlob17;
                                              }
                                              uint64_t positionAfterr3ReqScope = res7;
                                              if (EverParseIsError(positionAfterr3ReqScope))
                                              {
                                                positionAfterPolicyBlob16 = positionAfterr3ReqScope;
                                              }
                                              else
                                              {
                                                /* Validating field r4_path_hash */
                                                /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                BOOLEAN
                                                hasBytes19 =
                                                  4ULL <= (InputLength - positionAfterr3ReqScope);
                                                uint64_t positionAfterPolicyBlob18;
                                                if (hasBytes19)
                                                {
                                                  positionAfterPolicyBlob18 =
                                                    positionAfterr3ReqScope + 4ULL;
                                                }
                                                else
                                                {
                                                  positionAfterPolicyBlob18 =
                                                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                      positionAfterr3ReqScope);
                                                }
                                                uint64_t res8;
                                                if (EverParseIsSuccess(positionAfterPolicyBlob18))
                                                {
                                                  res8 = positionAfterPolicyBlob18;
                                                }
                                                else
                                                {
                                                  ErrorHandlerFn("_PolicyBlob",
                                                    "r4_path_hash",
                                                    EverParseErrorReasonOfResult(positionAfterPolicyBlob18),
                                                    EverParseGetValidatorErrorKind(positionAfterPolicyBlob18),
                                                    Ctxt,
                                                    Input,
                                                    positionAfterr3ReqScope);
                                                  res8 = positionAfterPolicyBlob18;
                                                }
                                                uint64_t positionAfterr4PathHash = res8;
                                                if (EverParseIsError(positionAfterr4PathHash))
                                                {
                                                  positionAfterPolicyBlob16 =
                                                    positionAfterr4PathHash;
                                                }
                                                else
                                                {
                                                  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                  BOOLEAN
                                                  hasBytes20 =
                                                    1ULL <= (InputLength - positionAfterr4PathHash);
                                                  uint64_t positionAfterr4Method;
                                                  if (hasBytes20)
                                                  {
                                                    positionAfterr4Method =
                                                      positionAfterr4PathHash + 1ULL;
                                                  }
                                                  else
                                                  {
                                                    positionAfterr4Method =
                                                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                        positionAfterr4PathHash);
                                                  }
                                                  uint64_t positionAfterPolicyBlob19;
                                                  if (EverParseIsError(positionAfterr4Method))
                                                  {
                                                    positionAfterPolicyBlob19 =
                                                      positionAfterr4Method;
                                                  }
                                                  else
                                                  {
                                                    uint8_t
                                                    r4Method =
                                                      Input[(uint32_t)positionAfterr4PathHash];
                                                    BOOLEAN r4MethodConstraintIsOk = r4Method <= 3U;
                                                    uint64_t
                                                    positionAfterr4Method1 =
                                                      EverParseCheckConstraintOk(r4MethodConstraintIsOk,
                                                        positionAfterr4Method);
                                                    if (EverParseIsError(positionAfterr4Method1))
                                                    {
                                                      positionAfterPolicyBlob19 =
                                                        positionAfterr4Method1;
                                                    }
                                                    else
                                                    {
                                                      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                      BOOLEAN
                                                      hasBytes21 =
                                                        1ULL <=
                                                          (InputLength - positionAfterr4Method1);
                                                      uint64_t positionAfterr4MinRole;
                                                      if (hasBytes21)
                                                      {
                                                        positionAfterr4MinRole =
                                                          positionAfterr4Method1 + 1ULL;
                                                      }
                                                      else
                                                      {
                                                        positionAfterr4MinRole =
                                                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                            positionAfterr4Method1);
                                                      }
                                                      uint64_t positionAfterPolicyBlob20;
                                                      if (EverParseIsError(positionAfterr4MinRole))
                                                      {
                                                        positionAfterPolicyBlob20 =
                                                          positionAfterr4MinRole;
                                                      }
                                                      else
                                                      {
                                                        uint8_t
                                                        r4MinRole =
                                                          Input[(uint32_t)positionAfterr4Method1];
                                                        BOOLEAN
                                                        r4MinRoleConstraintIsOk = r4MinRole <= 2U;
                                                        uint64_t
                                                        positionAfterr4MinRole1 =
                                                          EverParseCheckConstraintOk(r4MinRoleConstraintIsOk,
                                                            positionAfterr4MinRole);
                                                        if
                                                        (EverParseIsError(positionAfterr4MinRole1))
                                                        {
                                                          positionAfterPolicyBlob20 =
                                                            positionAfterr4MinRole1;
                                                        }
                                                        else
                                                        {
                                                          /* Validating field r4_req_scope */
                                                          /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                                                          BOOLEAN
                                                          hasBytes22 =
                                                            2ULL <=
                                                              (InputLength - positionAfterr4MinRole1);
                                                          uint64_t positionAfterPolicyBlob21;
                                                          if (hasBytes22)
                                                          {
                                                            positionAfterPolicyBlob21 =
                                                              positionAfterr4MinRole1 + 2ULL;
                                                          }
                                                          else
                                                          {
                                                            positionAfterPolicyBlob21 =
                                                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                positionAfterr4MinRole1);
                                                          }
                                                          uint64_t res9;
                                                          if
                                                          (
                                                            EverParseIsSuccess(positionAfterPolicyBlob21)
                                                          )
                                                          {
                                                            res9 = positionAfterPolicyBlob21;
                                                          }
                                                          else
                                                          {
                                                            ErrorHandlerFn("_PolicyBlob",
                                                              "r4_req_scope",
                                                              EverParseErrorReasonOfResult(positionAfterPolicyBlob21),
                                                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob21),
                                                              Ctxt,
                                                              Input,
                                                              positionAfterr4MinRole1);
                                                            res9 = positionAfterPolicyBlob21;
                                                          }
                                                          uint64_t positionAfterr4ReqScope = res9;
                                                          if
                                                          (
                                                            EverParseIsError(positionAfterr4ReqScope)
                                                          )
                                                          {
                                                            positionAfterPolicyBlob20 =
                                                              positionAfterr4ReqScope;
                                                          }
                                                          else
                                                          {
                                                            /* Validating field r5_path_hash */
                                                            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                            BOOLEAN
                                                            hasBytes23 =
                                                              4ULL <=
                                                                (InputLength -
                                                                  positionAfterr4ReqScope);
                                                            uint64_t positionAfterPolicyBlob22;
                                                            if (hasBytes23)
                                                            {
                                                              positionAfterPolicyBlob22 =
                                                                positionAfterr4ReqScope + 4ULL;
                                                            }
                                                            else
                                                            {
                                                              positionAfterPolicyBlob22 =
                                                                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                  positionAfterr4ReqScope);
                                                            }
                                                            uint64_t res10;
                                                            if
                                                            (
                                                              EverParseIsSuccess(positionAfterPolicyBlob22)
                                                            )
                                                            {
                                                              res10 = positionAfterPolicyBlob22;
                                                            }
                                                            else
                                                            {
                                                              ErrorHandlerFn("_PolicyBlob",
                                                                "r5_path_hash",
                                                                EverParseErrorReasonOfResult(positionAfterPolicyBlob22),
                                                                EverParseGetValidatorErrorKind(positionAfterPolicyBlob22),
                                                                Ctxt,
                                                                Input,
                                                                positionAfterr4ReqScope);
                                                              res10 = positionAfterPolicyBlob22;
                                                            }
                                                            uint64_t
                                                            positionAfterr5PathHash = res10;
                                                            if
                                                            (
                                                              EverParseIsError(positionAfterr5PathHash)
                                                            )
                                                            {
                                                              positionAfterPolicyBlob20 =
                                                                positionAfterr5PathHash;
                                                            }
                                                            else
                                                            {
                                                              /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                              BOOLEAN
                                                              hasBytes24 =
                                                                1ULL <=
                                                                  (InputLength -
                                                                    positionAfterr5PathHash);
                                                              uint64_t positionAfterr5Method;
                                                              if (hasBytes24)
                                                              {
                                                                positionAfterr5Method =
                                                                  positionAfterr5PathHash + 1ULL;
                                                              }
                                                              else
                                                              {
                                                                positionAfterr5Method =
                                                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    positionAfterr5PathHash);
                                                              }
                                                              uint64_t positionAfterPolicyBlob23;
                                                              if
                                                              (
                                                                EverParseIsError(positionAfterr5Method)
                                                              )
                                                              {
                                                                positionAfterPolicyBlob23 =
                                                                  positionAfterr5Method;
                                                              }
                                                              else
                                                              {
                                                                uint8_t
                                                                r5Method =
                                                                  Input[(uint32_t)positionAfterr5PathHash];
                                                                BOOLEAN
                                                                r5MethodConstraintIsOk =
                                                                  r5Method <= 3U;
                                                                uint64_t
                                                                positionAfterr5Method1 =
                                                                  EverParseCheckConstraintOk(r5MethodConstraintIsOk,
                                                                    positionAfterr5Method);
                                                                if
                                                                (
                                                                  EverParseIsError(positionAfterr5Method1)
                                                                )
                                                                {
                                                                  positionAfterPolicyBlob23 =
                                                                    positionAfterr5Method1;
                                                                }
                                                                else
                                                                {
                                                                  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                  BOOLEAN
                                                                  hasBytes25 =
                                                                    1ULL <=
                                                                      (InputLength -
                                                                        positionAfterr5Method1);
                                                                  uint64_t positionAfterr5MinRole;
                                                                  if (hasBytes25)
                                                                  {
                                                                    positionAfterr5MinRole =
                                                                      positionAfterr5Method1 + 1ULL;
                                                                  }
                                                                  else
                                                                  {
                                                                    positionAfterr5MinRole =
                                                                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                        positionAfterr5Method1);
                                                                  }
                                                                  uint64_t
                                                                  positionAfterPolicyBlob24;
                                                                  if
                                                                  (
                                                                    EverParseIsError(positionAfterr5MinRole)
                                                                  )
                                                                  {
                                                                    positionAfterPolicyBlob24 =
                                                                      positionAfterr5MinRole;
                                                                  }
                                                                  else
                                                                  {
                                                                    uint8_t
                                                                    r5MinRole =
                                                                      Input[(uint32_t)positionAfterr5Method1];
                                                                    BOOLEAN
                                                                    r5MinRoleConstraintIsOk =
                                                                      r5MinRole <= 2U;
                                                                    uint64_t
                                                                    positionAfterr5MinRole1 =
                                                                      EverParseCheckConstraintOk(r5MinRoleConstraintIsOk,
                                                                        positionAfterr5MinRole);
                                                                    if
                                                                    (
                                                                      EverParseIsError(positionAfterr5MinRole1)
                                                                    )
                                                                    {
                                                                      positionAfterPolicyBlob24 =
                                                                        positionAfterr5MinRole1;
                                                                    }
                                                                    else
                                                                    {
                                                                      /* Validating field r5_req_scope */
                                                                      /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                                                                      BOOLEAN
                                                                      hasBytes26 =
                                                                        2ULL <=
                                                                          (InputLength -
                                                                            positionAfterr5MinRole1);
                                                                      uint64_t
                                                                      positionAfterPolicyBlob25;
                                                                      if (hasBytes26)
                                                                      {
                                                                        positionAfterPolicyBlob25 =
                                                                          positionAfterr5MinRole1 +
                                                                            2ULL;
                                                                      }
                                                                      else
                                                                      {
                                                                        positionAfterPolicyBlob25 =
                                                                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                            positionAfterr5MinRole1);
                                                                      }
                                                                      uint64_t res11;
                                                                      if
                                                                      (
                                                                        EverParseIsSuccess(positionAfterPolicyBlob25)
                                                                      )
                                                                      {
                                                                        res11 =
                                                                          positionAfterPolicyBlob25;
                                                                      }
                                                                      else
                                                                      {
                                                                        ErrorHandlerFn("_PolicyBlob",
                                                                          "r5_req_scope",
                                                                          EverParseErrorReasonOfResult(positionAfterPolicyBlob25),
                                                                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob25),
                                                                          Ctxt,
                                                                          Input,
                                                                          positionAfterr5MinRole1);
                                                                        res11 =
                                                                          positionAfterPolicyBlob25;
                                                                      }
                                                                      uint64_t
                                                                      positionAfterr5ReqScope =
                                                                        res11;
                                                                      if
                                                                      (
                                                                        EverParseIsError(positionAfterr5ReqScope)
                                                                      )
                                                                      {
                                                                        positionAfterPolicyBlob24 =
                                                                          positionAfterr5ReqScope;
                                                                      }
                                                                      else
                                                                      {
                                                                        /* Validating field r6_path_hash */
                                                                        /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                                        BOOLEAN
                                                                        hasBytes27 =
                                                                          4ULL <=
                                                                            (InputLength -
                                                                              positionAfterr5ReqScope);
                                                                        uint64_t
                                                                        positionAfterPolicyBlob26;
                                                                        if (hasBytes27)
                                                                        {
                                                                          positionAfterPolicyBlob26
                                                                          =
                                                                            positionAfterr5ReqScope
                                                                            + 4ULL;
                                                                        }
                                                                        else
                                                                        {
                                                                          positionAfterPolicyBlob26
                                                                          =
                                                                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                              positionAfterr5ReqScope);
                                                                        }
                                                                        uint64_t res12;
                                                                        if
                                                                        (
                                                                          EverParseIsSuccess(positionAfterPolicyBlob26)
                                                                        )
                                                                        {
                                                                          res12 =
                                                                            positionAfterPolicyBlob26;
                                                                        }
                                                                        else
                                                                        {
                                                                          ErrorHandlerFn("_PolicyBlob",
                                                                            "r6_path_hash",
                                                                            EverParseErrorReasonOfResult(positionAfterPolicyBlob26),
                                                                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob26),
                                                                            Ctxt,
                                                                            Input,
                                                                            positionAfterr5ReqScope);
                                                                          res12 =
                                                                            positionAfterPolicyBlob26;
                                                                        }
                                                                        uint64_t
                                                                        positionAfterr6PathHash =
                                                                          res12;
                                                                        if
                                                                        (
                                                                          EverParseIsError(positionAfterr6PathHash)
                                                                        )
                                                                        {
                                                                          positionAfterPolicyBlob24
                                                                          = positionAfterr6PathHash;
                                                                        }
                                                                        else
                                                                        {
                                                                          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                          BOOLEAN
                                                                          hasBytes28 =
                                                                            1ULL <=
                                                                              (InputLength -
                                                                                positionAfterr6PathHash);
                                                                          uint64_t
                                                                          positionAfterr6Method;
                                                                          if (hasBytes28)
                                                                          {
                                                                            positionAfterr6Method =
                                                                              positionAfterr6PathHash
                                                                              + 1ULL;
                                                                          }
                                                                          else
                                                                          {
                                                                            positionAfterr6Method =
                                                                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                positionAfterr6PathHash);
                                                                          }
                                                                          uint64_t
                                                                          positionAfterPolicyBlob27;
                                                                          if
                                                                          (
                                                                            EverParseIsError(positionAfterr6Method)
                                                                          )
                                                                          {
                                                                            positionAfterPolicyBlob27
                                                                            = positionAfterr6Method;
                                                                          }
                                                                          else
                                                                          {
                                                                            uint8_t
                                                                            r6Method =
                                                                              Input[(uint32_t)positionAfterr6PathHash];
                                                                            BOOLEAN
                                                                            r6MethodConstraintIsOk =
                                                                              r6Method <= 3U;
                                                                            uint64_t
                                                                            positionAfterr6Method1 =
                                                                              EverParseCheckConstraintOk(r6MethodConstraintIsOk,
                                                                                positionAfterr6Method);
                                                                            if
                                                                            (
                                                                              EverParseIsError(positionAfterr6Method1)
                                                                            )
                                                                            {
                                                                              positionAfterPolicyBlob27
                                                                              =
                                                                                positionAfterr6Method1;
                                                                            }
                                                                            else
                                                                            {
                                                                              /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                              BOOLEAN
                                                                              hasBytes29 =
                                                                                1ULL <=
                                                                                  (InputLength -
                                                                                    positionAfterr6Method1);
                                                                              uint64_t
                                                                              positionAfterr6MinRole;
                                                                              if (hasBytes29)
                                                                              {
                                                                                positionAfterr6MinRole
                                                                                =
                                                                                  positionAfterr6Method1
                                                                                  + 1ULL;
                                                                              }
                                                                              else
                                                                              {
                                                                                positionAfterr6MinRole
                                                                                =
                                                                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                    positionAfterr6Method1);
                                                                              }
                                                                              uint64_t
                                                                              positionAfterPolicyBlob28;
                                                                              if
                                                                              (
                                                                                EverParseIsError(positionAfterr6MinRole)
                                                                              )
                                                                              {
                                                                                positionAfterPolicyBlob28
                                                                                =
                                                                                  positionAfterr6MinRole;
                                                                              }
                                                                              else
                                                                              {
                                                                                uint8_t
                                                                                r6MinRole =
                                                                                  Input[(uint32_t)positionAfterr6Method1];
                                                                                BOOLEAN
                                                                                r6MinRoleConstraintIsOk =
                                                                                  r6MinRole <= 2U;
                                                                                uint64_t
                                                                                positionAfterr6MinRole1 =
                                                                                  EverParseCheckConstraintOk(r6MinRoleConstraintIsOk,
                                                                                    positionAfterr6MinRole);
                                                                                if
                                                                                (
                                                                                  EverParseIsError(positionAfterr6MinRole1)
                                                                                )
                                                                                {
                                                                                  positionAfterPolicyBlob28
                                                                                  =
                                                                                    positionAfterr6MinRole1;
                                                                                }
                                                                                else
                                                                                {
                                                                                  /* Validating field r6_req_scope */
                                                                                  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                                                                                  BOOLEAN
                                                                                  hasBytes30 =
                                                                                    2ULL <=
                                                                                      (InputLength -
                                                                                        positionAfterr6MinRole1);
                                                                                  uint64_t
                                                                                  positionAfterPolicyBlob29;
                                                                                  if (hasBytes30)
                                                                                  {
                                                                                    positionAfterPolicyBlob29
                                                                                    =
                                                                                      positionAfterr6MinRole1
                                                                                      + 2ULL;
                                                                                  }
                                                                                  else
                                                                                  {
                                                                                    positionAfterPolicyBlob29
                                                                                    =
                                                                                      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                        positionAfterr6MinRole1);
                                                                                  }
                                                                                  uint64_t res13;
                                                                                  if
                                                                                  (
                                                                                    EverParseIsSuccess(positionAfterPolicyBlob29)
                                                                                  )
                                                                                  {
                                                                                    res13 =
                                                                                      positionAfterPolicyBlob29;
                                                                                  }
                                                                                  else
                                                                                  {
                                                                                    ErrorHandlerFn("_PolicyBlob",
                                                                                      "r6_req_scope",
                                                                                      EverParseErrorReasonOfResult(positionAfterPolicyBlob29),
                                                                                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob29),
                                                                                      Ctxt,
                                                                                      Input,
                                                                                      positionAfterr6MinRole1);
                                                                                    res13 =
                                                                                      positionAfterPolicyBlob29;
                                                                                  }
                                                                                  uint64_t
                                                                                  positionAfterr6ReqScope =
                                                                                    res13;
                                                                                  if
                                                                                  (
                                                                                    EverParseIsError(positionAfterr6ReqScope)
                                                                                  )
                                                                                  {
                                                                                    positionAfterPolicyBlob28
                                                                                    =
                                                                                      positionAfterr6ReqScope;
                                                                                  }
                                                                                  else
                                                                                  {
                                                                                    /* Validating field r7_path_hash */
                                                                                    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
                                                                                    BOOLEAN
                                                                                    hasBytes31 =
                                                                                      4ULL <=
                                                                                        (InputLength
                                                                                        -
                                                                                          positionAfterr6ReqScope);
                                                                                    uint64_t
                                                                                    positionAfterPolicyBlob30;
                                                                                    if (hasBytes31)
                                                                                    {
                                                                                      positionAfterPolicyBlob30
                                                                                      =
                                                                                        positionAfterr6ReqScope
                                                                                        + 4ULL;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      positionAfterPolicyBlob30
                                                                                      =
                                                                                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                          positionAfterr6ReqScope);
                                                                                    }
                                                                                    uint64_t res14;
                                                                                    if
                                                                                    (
                                                                                      EverParseIsSuccess(positionAfterPolicyBlob30)
                                                                                    )
                                                                                    {
                                                                                      res14 =
                                                                                        positionAfterPolicyBlob30;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      ErrorHandlerFn("_PolicyBlob",
                                                                                        "r7_path_hash",
                                                                                        EverParseErrorReasonOfResult(positionAfterPolicyBlob30),
                                                                                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob30),
                                                                                        Ctxt,
                                                                                        Input,
                                                                                        positionAfterr6ReqScope);
                                                                                      res14 =
                                                                                        positionAfterPolicyBlob30;
                                                                                    }
                                                                                    uint64_t
                                                                                    positionAfterr7PathHash =
                                                                                      res14;
                                                                                    if
                                                                                    (
                                                                                      EverParseIsError(positionAfterr7PathHash)
                                                                                    )
                                                                                    {
                                                                                      positionAfterPolicyBlob28
                                                                                      =
                                                                                        positionAfterr7PathHash;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                      BOOLEAN
                                                                                      hasBytes32 =
                                                                                        1ULL <=
                                                                                          (InputLength
                                                                                          -
                                                                                            positionAfterr7PathHash);
                                                                                      uint64_t
                                                                                      positionAfterr7Method;
                                                                                      if
                                                                                      (hasBytes32)
                                                                                      {
                                                                                        positionAfterr7Method
                                                                                        =
                                                                                          positionAfterr7PathHash
                                                                                          + 1ULL;
                                                                                      }
                                                                                      else
                                                                                      {
                                                                                        positionAfterr7Method
                                                                                        =
                                                                                          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                            positionAfterr7PathHash);
                                                                                      }
                                                                                      uint64_t
                                                                                      positionAfterPolicyBlob31;
                                                                                      if
                                                                                      (
                                                                                        EverParseIsError(positionAfterr7Method)
                                                                                      )
                                                                                      {
                                                                                        positionAfterPolicyBlob31
                                                                                        =
                                                                                          positionAfterr7Method;
                                                                                      }
                                                                                      else
                                                                                      {
                                                                                        uint8_t
                                                                                        r7Method =
                                                                                          Input[(uint32_t)positionAfterr7PathHash];
                                                                                        BOOLEAN
                                                                                        r7MethodConstraintIsOk =
                                                                                          r7Method
                                                                                          <= 3U;
                                                                                        uint64_t
                                                                                        positionAfterr7Method1 =
                                                                                          EverParseCheckConstraintOk(r7MethodConstraintIsOk,
                                                                                            positionAfterr7Method);
                                                                                        if
                                                                                        (
                                                                                          EverParseIsError(positionAfterr7Method1)
                                                                                        )
                                                                                        {
                                                                                          positionAfterPolicyBlob31
                                                                                          =
                                                                                            positionAfterr7Method1;
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                          /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                          BOOLEAN
                                                                                          hasBytes33 =
                                                                                            1ULL <=
                                                                                              (InputLength
                                                                                              -
                                                                                                positionAfterr7Method1);
                                                                                          uint64_t
                                                                                          positionAfterr7MinRole;
                                                                                          if
                                                                                          (
                                                                                            hasBytes33
                                                                                          )
                                                                                          {
                                                                                            positionAfterr7MinRole
                                                                                            =
                                                                                              positionAfterr7Method1
                                                                                              + 1ULL;
                                                                                          }
                                                                                          else
                                                                                          {
                                                                                            positionAfterr7MinRole
                                                                                            =
                                                                                              EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                                positionAfterr7Method1);
                                                                                          }
                                                                                          uint64_t
                                                                                          positionAfterPolicyBlob32;
                                                                                          if
                                                                                          (
                                                                                            EverParseIsError(positionAfterr7MinRole)
                                                                                          )
                                                                                          {
                                                                                            positionAfterPolicyBlob32
                                                                                            =
                                                                                              positionAfterr7MinRole;
                                                                                          }
                                                                                          else
                                                                                          {
                                                                                            uint8_t
                                                                                            r7MinRole =
                                                                                              Input[(uint32_t)positionAfterr7Method1];
                                                                                            BOOLEAN
                                                                                            r7MinRoleConstraintIsOk =
                                                                                              r7MinRole
                                                                                              <= 2U;
                                                                                            uint64_t
                                                                                            positionAfterr7MinRole1 =
                                                                                              EverParseCheckConstraintOk(r7MinRoleConstraintIsOk,
                                                                                                positionAfterr7MinRole);
                                                                                            if
                                                                                            (
                                                                                              EverParseIsError(positionAfterr7MinRole1)
                                                                                            )
                                                                                            {
                                                                                              positionAfterPolicyBlob32
                                                                                              =
                                                                                                positionAfterr7MinRole1;
                                                                                            }
                                                                                            else
                                                                                            {
                                                                                              /* Validating field r7_req_scope */
                                                                                              /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
                                                                                              BOOLEAN
                                                                                              hasBytes34 =
                                                                                                2ULL
                                                                                                <=
                                                                                                  (InputLength
                                                                                                  -
                                                                                                    positionAfterr7MinRole1);
                                                                                              uint64_t
                                                                                              positionAfterPolicyBlob33;
                                                                                              if
                                                                                              (
                                                                                                hasBytes34
                                                                                              )
                                                                                              {
                                                                                                positionAfterPolicyBlob33
                                                                                                =
                                                                                                  positionAfterr7MinRole1
                                                                                                  +
                                                                                                    2ULL;
                                                                                              }
                                                                                              else
                                                                                              {
                                                                                                positionAfterPolicyBlob33
                                                                                                =
                                                                                                  EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                                    positionAfterr7MinRole1);
                                                                                              }
                                                                                              uint64_t
                                                                                              res;
                                                                                              if
                                                                                              (
                                                                                                EverParseIsSuccess(positionAfterPolicyBlob33)
                                                                                              )
                                                                                              {
                                                                                                res
                                                                                                =
                                                                                                  positionAfterPolicyBlob33;
                                                                                              }
                                                                                              else
                                                                                              {
                                                                                                ErrorHandlerFn("_PolicyBlob",
                                                                                                  "r7_req_scope",
                                                                                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob33),
                                                                                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob33),
                                                                                                  Ctxt,
                                                                                                  Input,
                                                                                                  positionAfterr7MinRole1);
                                                                                                res
                                                                                                =
                                                                                                  positionAfterPolicyBlob33;
                                                                                              }
                                                                                              uint64_t
                                                                                              positionAfterr7ReqScope =
                                                                                                res;
                                                                                              if
                                                                                              (
                                                                                                EverParseIsError(positionAfterr7ReqScope)
                                                                                              )
                                                                                              {
                                                                                                positionAfterPolicyBlob32
                                                                                                =
                                                                                                  positionAfterr7ReqScope;
                                                                                              }
                                                                                              else
                                                                                              {
                                                                                                /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                                BOOLEAN
                                                                                                hasBytes35 =
                                                                                                  1ULL
                                                                                                  <=
                                                                                                    (InputLength
                                                                                                    -
                                                                                                      positionAfterr7ReqScope);
                                                                                                uint64_t
                                                                                                positionAfterAuthOk;
                                                                                                if
                                                                                                (
                                                                                                  hasBytes35
                                                                                                )
                                                                                                {
                                                                                                  positionAfterAuthOk
                                                                                                  =
                                                                                                    positionAfterr7ReqScope
                                                                                                    +
                                                                                                      1ULL;
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                  positionAfterAuthOk
                                                                                                  =
                                                                                                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                                      positionAfterr7ReqScope);
                                                                                                }
                                                                                                uint64_t
                                                                                                positionAfterPolicyBlob34;
                                                                                                if
                                                                                                (
                                                                                                  EverParseIsError(positionAfterAuthOk)
                                                                                                )
                                                                                                {
                                                                                                  positionAfterPolicyBlob34
                                                                                                  =
                                                                                                    positionAfterAuthOk;
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                  uint8_t
                                                                                                  authOk =
                                                                                                    Input[(uint32_t)positionAfterr7ReqScope];
                                                                                                  KRML_MAYBE_UNUSED_VAR(authOk);
                                                                                                  BOOLEAN
                                                                                                  authOkConstraintIsOk =
                                                                                                    authState
                                                                                                    >=
                                                                                                      RBACPOLICY____ROLE_ADMIN;
                                                                                                  uint64_t
                                                                                                  positionAfterAuthOk1 =
                                                                                                    EverParseCheckConstraintOk(authOkConstraintIsOk,
                                                                                                      positionAfterAuthOk);
                                                                                                  if
                                                                                                  (
                                                                                                    EverParseIsError(positionAfterAuthOk1)
                                                                                                  )
                                                                                                  {
                                                                                                    positionAfterPolicyBlob34
                                                                                                    =
                                                                                                      positionAfterAuthOk1;
                                                                                                  }
                                                                                                  else
                                                                                                  {
                                                                                                    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                                    BOOLEAN
                                                                                                    hasBytes36 =
                                                                                                      1ULL
                                                                                                      <=
                                                                                                        (InputLength
                                                                                                        -
                                                                                                          positionAfterAuthOk1);
                                                                                                    uint64_t
                                                                                                    positionAfterRateOk;
                                                                                                    if
                                                                                                    (
                                                                                                      hasBytes36
                                                                                                    )
                                                                                                    {
                                                                                                      positionAfterRateOk
                                                                                                      =
                                                                                                        positionAfterAuthOk1
                                                                                                        +
                                                                                                          1ULL;
                                                                                                    }
                                                                                                    else
                                                                                                    {
                                                                                                      positionAfterRateOk
                                                                                                      =
                                                                                                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                                          positionAfterAuthOk1);
                                                                                                    }
                                                                                                    uint64_t
                                                                                                    positionAfterPolicyBlob35;
                                                                                                    if
                                                                                                    (
                                                                                                      EverParseIsError(positionAfterRateOk)
                                                                                                    )
                                                                                                    {
                                                                                                      positionAfterPolicyBlob35
                                                                                                      =
                                                                                                        positionAfterRateOk;
                                                                                                    }
                                                                                                    else
                                                                                                    {
                                                                                                      uint8_t
                                                                                                      rateOk =
                                                                                                        Input[(uint32_t)positionAfterAuthOk1];
                                                                                                      KRML_MAYBE_UNUSED_VAR(rateOk);
                                                                                                      BOOLEAN
                                                                                                      rateOkConstraintIsOk =
                                                                                                        rateCount
                                                                                                        <
                                                                                                          RBACPOLICY____MAX_RATE;
                                                                                                      uint64_t
                                                                                                      positionAfterRateOk1 =
                                                                                                        EverParseCheckConstraintOk(rateOkConstraintIsOk,
                                                                                                          positionAfterRateOk);
                                                                                                      if
                                                                                                      (
                                                                                                        EverParseIsError(positionAfterRateOk1)
                                                                                                      )
                                                                                                      {
                                                                                                        positionAfterPolicyBlob35
                                                                                                        =
                                                                                                          positionAfterRateOk1;
                                                                                                      }
                                                                                                      else
                                                                                                      {
                                                                                                        /* Validating field _rules_ok */
                                                                                                        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
                                                                                                        BOOLEAN
                                                                                                        hasBytes =
                                                                                                          1ULL
                                                                                                          <=
                                                                                                            (InputLength
                                                                                                            -
                                                                                                              positionAfterRateOk1);
                                                                                                        uint64_t
                                                                                                        positionAfterRulesOk_refinement;
                                                                                                        if
                                                                                                        (
                                                                                                          hasBytes
                                                                                                        )
                                                                                                        {
                                                                                                          positionAfterRulesOk_refinement
                                                                                                          =
                                                                                                            positionAfterRateOk1
                                                                                                            +
                                                                                                              1ULL;
                                                                                                        }
                                                                                                        else
                                                                                                        {
                                                                                                          positionAfterRulesOk_refinement
                                                                                                          =
                                                                                                            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                                              positionAfterRateOk1);
                                                                                                        }
                                                                                                        uint64_t
                                                                                                        positionAfterPolicyBlob36;
                                                                                                        if
                                                                                                        (
                                                                                                          EverParseIsError(positionAfterRulesOk_refinement)
                                                                                                        )
                                                                                                        {
                                                                                                          positionAfterPolicyBlob36
                                                                                                          =
                                                                                                            positionAfterRulesOk_refinement;
                                                                                                        }
                                                                                                        else
                                                                                                        {
                                                                                                          /* reading field_value */
                                                                                                          uint8_t
                                                                                                          rulesOk_refinement =
                                                                                                            Input[(uint32_t)positionAfterRateOk1];
                                                                                                          KRML_MAYBE_UNUSED_VAR(rulesOk_refinement);
                                                                                                          /* start: checking constraint */
                                                                                                          BOOLEAN
                                                                                                          rulesOk_refinementConstraintIsOk =
                                                                                                            numRules
                                                                                                            >=
                                                                                                              1U
                                                                                                            &&
                                                                                                              numRules
                                                                                                              <=
                                                                                                                RBACPOLICY____MAX_RULES;
                                                                                                          /* end: checking constraint */
                                                                                                          positionAfterPolicyBlob36
                                                                                                          =
                                                                                                            EverParseCheckConstraintOk(rulesOk_refinementConstraintIsOk,
                                                                                                              positionAfterRulesOk_refinement);
                                                                                                        }
                                                                                                        if
                                                                                                        (
                                                                                                          EverParseIsSuccess(positionAfterPolicyBlob36)
                                                                                                        )
                                                                                                        {
                                                                                                          positionAfterPolicyBlob35
                                                                                                          =
                                                                                                            positionAfterPolicyBlob36;
                                                                                                        }
                                                                                                        else
                                                                                                        {
                                                                                                          ErrorHandlerFn("_PolicyBlob",
                                                                                                            "_rules_ok.refinement",
                                                                                                            EverParseErrorReasonOfResult(positionAfterPolicyBlob36),
                                                                                                            EverParseGetValidatorErrorKind(positionAfterPolicyBlob36),
                                                                                                            Ctxt,
                                                                                                            Input,
                                                                                                            positionAfterRateOk1);
                                                                                                          positionAfterPolicyBlob35
                                                                                                          =
                                                                                                            positionAfterPolicyBlob36;
                                                                                                        }
                                                                                                      }
                                                                                                    }
                                                                                                    if
                                                                                                    (
                                                                                                      EverParseIsSuccess(positionAfterPolicyBlob35)
                                                                                                    )
                                                                                                    {
                                                                                                      positionAfterPolicyBlob34
                                                                                                      =
                                                                                                        positionAfterPolicyBlob35;
                                                                                                    }
                                                                                                    else
                                                                                                    {
                                                                                                      ErrorHandlerFn("_PolicyBlob",
                                                                                                        "_rate_ok",
                                                                                                        EverParseErrorReasonOfResult(positionAfterPolicyBlob35),
                                                                                                        EverParseGetValidatorErrorKind(positionAfterPolicyBlob35),
                                                                                                        Ctxt,
                                                                                                        Input,
                                                                                                        positionAfterAuthOk1);
                                                                                                      positionAfterPolicyBlob34
                                                                                                      =
                                                                                                        positionAfterPolicyBlob35;
                                                                                                    }
                                                                                                  }
                                                                                                }
                                                                                                if
                                                                                                (
                                                                                                  EverParseIsSuccess(positionAfterPolicyBlob34)
                                                                                                )
                                                                                                {
                                                                                                  positionAfterPolicyBlob32
                                                                                                  =
                                                                                                    positionAfterPolicyBlob34;
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                  ErrorHandlerFn("_PolicyBlob",
                                                                                                    "_auth_ok",
                                                                                                    EverParseErrorReasonOfResult(positionAfterPolicyBlob34),
                                                                                                    EverParseGetValidatorErrorKind(positionAfterPolicyBlob34),
                                                                                                    Ctxt,
                                                                                                    Input,
                                                                                                    positionAfterr7ReqScope);
                                                                                                  positionAfterPolicyBlob32
                                                                                                  =
                                                                                                    positionAfterPolicyBlob34;
                                                                                                }
                                                                                              }
                                                                                            }
                                                                                          }
                                                                                          if
                                                                                          (
                                                                                            EverParseIsSuccess(positionAfterPolicyBlob32)
                                                                                          )
                                                                                          {
                                                                                            positionAfterPolicyBlob31
                                                                                            =
                                                                                              positionAfterPolicyBlob32;
                                                                                          }
                                                                                          else
                                                                                          {
                                                                                            ErrorHandlerFn("_PolicyBlob",
                                                                                              "r7_min_role",
                                                                                              EverParseErrorReasonOfResult(positionAfterPolicyBlob32),
                                                                                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob32),
                                                                                              Ctxt,
                                                                                              Input,
                                                                                              positionAfterr7Method1);
                                                                                            positionAfterPolicyBlob31
                                                                                            =
                                                                                              positionAfterPolicyBlob32;
                                                                                          }
                                                                                        }
                                                                                      }
                                                                                      if
                                                                                      (
                                                                                        EverParseIsSuccess(positionAfterPolicyBlob31)
                                                                                      )
                                                                                      {
                                                                                        positionAfterPolicyBlob28
                                                                                        =
                                                                                          positionAfterPolicyBlob31;
                                                                                      }
                                                                                      else
                                                                                      {
                                                                                        ErrorHandlerFn("_PolicyBlob",
                                                                                          "r7_method",
                                                                                          EverParseErrorReasonOfResult(positionAfterPolicyBlob31),
                                                                                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob31),
                                                                                          Ctxt,
                                                                                          Input,
                                                                                          positionAfterr7PathHash);
                                                                                        positionAfterPolicyBlob28
                                                                                        =
                                                                                          positionAfterPolicyBlob31;
                                                                                      }
                                                                                    }
                                                                                  }
                                                                                }
                                                                              }
                                                                              if
                                                                              (
                                                                                EverParseIsSuccess(positionAfterPolicyBlob28)
                                                                              )
                                                                              {
                                                                                positionAfterPolicyBlob27
                                                                                =
                                                                                  positionAfterPolicyBlob28;
                                                                              }
                                                                              else
                                                                              {
                                                                                ErrorHandlerFn("_PolicyBlob",
                                                                                  "r6_min_role",
                                                                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob28),
                                                                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob28),
                                                                                  Ctxt,
                                                                                  Input,
                                                                                  positionAfterr6Method1);
                                                                                positionAfterPolicyBlob27
                                                                                =
                                                                                  positionAfterPolicyBlob28;
                                                                              }
                                                                            }
                                                                          }
                                                                          if
                                                                          (
                                                                            EverParseIsSuccess(positionAfterPolicyBlob27)
                                                                          )
                                                                          {
                                                                            positionAfterPolicyBlob24
                                                                            =
                                                                              positionAfterPolicyBlob27;
                                                                          }
                                                                          else
                                                                          {
                                                                            ErrorHandlerFn("_PolicyBlob",
                                                                              "r6_method",
                                                                              EverParseErrorReasonOfResult(positionAfterPolicyBlob27),
                                                                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob27),
                                                                              Ctxt,
                                                                              Input,
                                                                              positionAfterr6PathHash);
                                                                            positionAfterPolicyBlob24
                                                                            =
                                                                              positionAfterPolicyBlob27;
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                  if
                                                                  (
                                                                    EverParseIsSuccess(positionAfterPolicyBlob24)
                                                                  )
                                                                  {
                                                                    positionAfterPolicyBlob23 =
                                                                      positionAfterPolicyBlob24;
                                                                  }
                                                                  else
                                                                  {
                                                                    ErrorHandlerFn("_PolicyBlob",
                                                                      "r5_min_role",
                                                                      EverParseErrorReasonOfResult(positionAfterPolicyBlob24),
                                                                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob24),
                                                                      Ctxt,
                                                                      Input,
                                                                      positionAfterr5Method1);
                                                                    positionAfterPolicyBlob23 =
                                                                      positionAfterPolicyBlob24;
                                                                  }
                                                                }
                                                              }
                                                              if
                                                              (
                                                                EverParseIsSuccess(positionAfterPolicyBlob23)
                                                              )
                                                              {
                                                                positionAfterPolicyBlob20 =
                                                                  positionAfterPolicyBlob23;
                                                              }
                                                              else
                                                              {
                                                                ErrorHandlerFn("_PolicyBlob",
                                                                  "r5_method",
                                                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob23),
                                                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob23),
                                                                  Ctxt,
                                                                  Input,
                                                                  positionAfterr5PathHash);
                                                                positionAfterPolicyBlob20 =
                                                                  positionAfterPolicyBlob23;
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                      if
                                                      (
                                                        EverParseIsSuccess(positionAfterPolicyBlob20)
                                                      )
                                                      {
                                                        positionAfterPolicyBlob19 =
                                                          positionAfterPolicyBlob20;
                                                      }
                                                      else
                                                      {
                                                        ErrorHandlerFn("_PolicyBlob",
                                                          "r4_min_role",
                                                          EverParseErrorReasonOfResult(positionAfterPolicyBlob20),
                                                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob20),
                                                          Ctxt,
                                                          Input,
                                                          positionAfterr4Method1);
                                                        positionAfterPolicyBlob19 =
                                                          positionAfterPolicyBlob20;
                                                      }
                                                    }
                                                  }
                                                  if (EverParseIsSuccess(positionAfterPolicyBlob19))
                                                  {
                                                    positionAfterPolicyBlob16 =
                                                      positionAfterPolicyBlob19;
                                                  }
                                                  else
                                                  {
                                                    ErrorHandlerFn("_PolicyBlob",
                                                      "r4_method",
                                                      EverParseErrorReasonOfResult(positionAfterPolicyBlob19),
                                                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob19),
                                                      Ctxt,
                                                      Input,
                                                      positionAfterr4PathHash);
                                                    positionAfterPolicyBlob16 =
                                                      positionAfterPolicyBlob19;
                                                  }
                                                }
                                              }
                                            }
                                          }
                                          if (EverParseIsSuccess(positionAfterPolicyBlob16))
                                          {
                                            positionAfterPolicyBlob15 = positionAfterPolicyBlob16;
                                          }
                                          else
                                          {
                                            ErrorHandlerFn("_PolicyBlob",
                                              "r3_min_role",
                                              EverParseErrorReasonOfResult(positionAfterPolicyBlob16),
                                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob16),
                                              Ctxt,
                                              Input,
                                              positionAfterr3Method1);
                                            positionAfterPolicyBlob15 = positionAfterPolicyBlob16;
                                          }
                                        }
                                      }
                                      if (EverParseIsSuccess(positionAfterPolicyBlob15))
                                      {
                                        positionAfterPolicyBlob12 = positionAfterPolicyBlob15;
                                      }
                                      else
                                      {
                                        ErrorHandlerFn("_PolicyBlob",
                                          "r3_method",
                                          EverParseErrorReasonOfResult(positionAfterPolicyBlob15),
                                          EverParseGetValidatorErrorKind(positionAfterPolicyBlob15),
                                          Ctxt,
                                          Input,
                                          positionAfterr3PathHash);
                                        positionAfterPolicyBlob12 = positionAfterPolicyBlob15;
                                      }
                                    }
                                  }
                                }
                              }
                              if (EverParseIsSuccess(positionAfterPolicyBlob12))
                              {
                                positionAfterPolicyBlob11 = positionAfterPolicyBlob12;
                              }
                              else
                              {
                                ErrorHandlerFn("_PolicyBlob",
                                  "r2_min_role",
                                  EverParseErrorReasonOfResult(positionAfterPolicyBlob12),
                                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob12),
                                  Ctxt,
                                  Input,
                                  positionAfterr2Method1);
                                positionAfterPolicyBlob11 = positionAfterPolicyBlob12;
                              }
                            }
                          }
                          if (EverParseIsSuccess(positionAfterPolicyBlob11))
                          {
                            positionAfterPolicyBlob8 = positionAfterPolicyBlob11;
                          }
                          else
                          {
                            ErrorHandlerFn("_PolicyBlob",
                              "r2_method",
                              EverParseErrorReasonOfResult(positionAfterPolicyBlob11),
                              EverParseGetValidatorErrorKind(positionAfterPolicyBlob11),
                              Ctxt,
                              Input,
                              positionAfterr2PathHash);
                            positionAfterPolicyBlob8 = positionAfterPolicyBlob11;
                          }
                        }
                      }
                    }
                  }
                  if (EverParseIsSuccess(positionAfterPolicyBlob8))
                  {
                    positionAfterPolicyBlob7 = positionAfterPolicyBlob8;
                  }
                  else
                  {
                    ErrorHandlerFn("_PolicyBlob",
                      "r1_min_role",
                      EverParseErrorReasonOfResult(positionAfterPolicyBlob8),
                      EverParseGetValidatorErrorKind(positionAfterPolicyBlob8),
                      Ctxt,
                      Input,
                      positionAfterr1Method1);
                    positionAfterPolicyBlob7 = positionAfterPolicyBlob8;
                  }
                }
              }
              if (EverParseIsSuccess(positionAfterPolicyBlob7))
              {
                positionAfterPolicyBlob4 = positionAfterPolicyBlob7;
              }
              else
              {
                ErrorHandlerFn("_PolicyBlob",
                  "r1_method",
                  EverParseErrorReasonOfResult(positionAfterPolicyBlob7),
                  EverParseGetValidatorErrorKind(positionAfterPolicyBlob7),
                  Ctxt,
                  Input,
                  positionAfterr1PathHash);
                positionAfterPolicyBlob4 = positionAfterPolicyBlob7;
              }
            }
          }
        }
      }
      if (EverParseIsSuccess(positionAfterPolicyBlob4))
      {
        positionAfterPolicyBlob3 = positionAfterPolicyBlob4;
      }
      else
      {
        ErrorHandlerFn("_PolicyBlob",
          "r0_min_role",
          EverParseErrorReasonOfResult(positionAfterPolicyBlob4),
          EverParseGetValidatorErrorKind(positionAfterPolicyBlob4),
          Ctxt,
          Input,
          positionAfterr0Method1);
        positionAfterPolicyBlob3 = positionAfterPolicyBlob4;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterPolicyBlob3))
  {
    return positionAfterPolicyBlob3;
  }
  ErrorHandlerFn("_PolicyBlob",
    "r0_method",
    EverParseErrorReasonOfResult(positionAfterPolicyBlob3),
    EverParseGetValidatorErrorKind(positionAfterPolicyBlob3),
    Ctxt,
    Input,
    positionAfterr0PathHash);
  return positionAfterPolicyBlob3;
}

uint64_t
RbacPolicyValidateAccessRequest(
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
  uint64_t positionAfterAccessRequest;
  if (hasBytes0)
  {
    positionAfterAccessRequest = StartPosition + 1ULL;
  }
  else
  {
    positionAfterAccessRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterauthState;
  if (EverParseIsSuccess(positionAfterAccessRequest))
  {
    positionAfterauthState = positionAfterAccessRequest;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "auth_state",
      EverParseErrorReasonOfResult(positionAfterAccessRequest),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest),
      Ctxt,
      Input,
      StartPosition);
    positionAfterauthState = positionAfterAccessRequest;
  }
  if (EverParseIsError(positionAfterauthState))
  {
    return positionAfterauthState;
  }
  uint8_t authState = Input[(uint32_t)StartPosition];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAfterauthState);
  uint64_t positionAfterAccessRequest0;
  if (hasBytes1)
  {
    positionAfterAccessRequest0 = positionAfterauthState + 1ULL;
  }
  else
  {
    positionAfterAccessRequest0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthState);
  }
  uint64_t positionAfterrateCount;
  if (EverParseIsSuccess(positionAfterAccessRequest0))
  {
    positionAfterrateCount = positionAfterAccessRequest0;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "rate_count",
      EverParseErrorReasonOfResult(positionAfterAccessRequest0),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest0),
      Ctxt,
      Input,
      positionAfterauthState);
    positionAfterrateCount = positionAfterAccessRequest0;
  }
  if (EverParseIsError(positionAfterrateCount))
  {
    return positionAfterrateCount;
  }
  uint8_t rateCount = Input[(uint32_t)positionAfterauthState];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes2 = 2ULL <= (InputLength - positionAfterrateCount);
  uint64_t positionAfterAccessRequest1;
  if (hasBytes2)
  {
    positionAfterAccessRequest1 = positionAfterrateCount + 2ULL;
  }
  else
  {
    positionAfterAccessRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrateCount);
  }
  uint64_t positionAfterauthScope;
  if (EverParseIsSuccess(positionAfterAccessRequest1))
  {
    positionAfterauthScope = positionAfterAccessRequest1;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "auth_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest1),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest1),
      Ctxt,
      Input,
      positionAfterrateCount);
    positionAfterauthScope = positionAfterAccessRequest1;
  }
  if (EverParseIsError(positionAfterauthScope))
  {
    return positionAfterauthScope;
  }
  uint16_t r0 = Load16Le(Input + (uint32_t)positionAfterrateCount);
  uint16_t authScope = (uint16_t)(uint32_t)r0;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterauthScope);
  uint64_t positionAfterAccessRequest2;
  if (hasBytes3)
  {
    positionAfterAccessRequest2 = positionAfterauthScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterauthScope);
  }
  uint64_t positionAfterr0PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest2))
  {
    positionAfterr0PathHash = positionAfterAccessRequest2;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest2),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest2),
      Ctxt,
      Input,
      positionAfterauthScope);
    positionAfterr0PathHash = positionAfterAccessRequest2;
  }
  if (EverParseIsError(positionAfterr0PathHash))
  {
    return positionAfterr0PathHash;
  }
  uint32_t r0PathHash = Load32Le(Input + (uint32_t)positionAfterauthScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAfterr0PathHash);
  uint64_t positionAfterAccessRequest3;
  if (hasBytes4)
  {
    positionAfterAccessRequest3 = positionAfterr0PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0PathHash);
  }
  uint64_t positionAfterr0Method;
  if (EverParseIsSuccess(positionAfterAccessRequest3))
  {
    positionAfterr0Method = positionAfterAccessRequest3;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest3),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest3),
      Ctxt,
      Input,
      positionAfterr0PathHash);
    positionAfterr0Method = positionAfterAccessRequest3;
  }
  if (EverParseIsError(positionAfterr0Method))
  {
    return positionAfterr0Method;
  }
  uint8_t r0Method = Input[(uint32_t)positionAfterr0PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterr0Method);
  uint64_t positionAfterAccessRequest4;
  if (hasBytes5)
  {
    positionAfterAccessRequest4 = positionAfterr0Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0Method);
  }
  uint64_t positionAfterr0MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest4))
  {
    positionAfterr0MinRole = positionAfterAccessRequest4;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest4),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest4),
      Ctxt,
      Input,
      positionAfterr0Method);
    positionAfterr0MinRole = positionAfterAccessRequest4;
  }
  if (EverParseIsError(positionAfterr0MinRole))
  {
    return positionAfterr0MinRole;
  }
  uint8_t r0MinRole = Input[(uint32_t)positionAfterr0Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes6 = 2ULL <= (InputLength - positionAfterr0MinRole);
  uint64_t positionAfterAccessRequest5;
  if (hasBytes6)
  {
    positionAfterAccessRequest5 = positionAfterr0MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0MinRole);
  }
  uint64_t positionAfterr0ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest5))
  {
    positionAfterr0ReqScope = positionAfterAccessRequest5;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r0_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest5),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest5),
      Ctxt,
      Input,
      positionAfterr0MinRole);
    positionAfterr0ReqScope = positionAfterAccessRequest5;
  }
  if (EverParseIsError(positionAfterr0ReqScope))
  {
    return positionAfterr0ReqScope;
  }
  uint16_t r1 = Load16Le(Input + (uint32_t)positionAfterr0MinRole);
  uint16_t r0ReqScope = (uint16_t)(uint32_t)r1;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes7 = 4ULL <= (InputLength - positionAfterr0ReqScope);
  uint64_t positionAfterAccessRequest6;
  if (hasBytes7)
  {
    positionAfterAccessRequest6 = positionAfterr0ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr0ReqScope);
  }
  uint64_t positionAfterr1PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest6))
  {
    positionAfterr1PathHash = positionAfterAccessRequest6;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest6),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest6),
      Ctxt,
      Input,
      positionAfterr0ReqScope);
    positionAfterr1PathHash = positionAfterAccessRequest6;
  }
  if (EverParseIsError(positionAfterr1PathHash))
  {
    return positionAfterr1PathHash;
  }
  uint32_t r1PathHash = Load32Le(Input + (uint32_t)positionAfterr0ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterr1PathHash);
  uint64_t positionAfterAccessRequest7;
  if (hasBytes8)
  {
    positionAfterAccessRequest7 = positionAfterr1PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1PathHash);
  }
  uint64_t positionAfterr1Method;
  if (EverParseIsSuccess(positionAfterAccessRequest7))
  {
    positionAfterr1Method = positionAfterAccessRequest7;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest7),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest7),
      Ctxt,
      Input,
      positionAfterr1PathHash);
    positionAfterr1Method = positionAfterAccessRequest7;
  }
  if (EverParseIsError(positionAfterr1Method))
  {
    return positionAfterr1Method;
  }
  uint8_t r1Method = Input[(uint32_t)positionAfterr1PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes9 = 1ULL <= (InputLength - positionAfterr1Method);
  uint64_t positionAfterAccessRequest8;
  if (hasBytes9)
  {
    positionAfterAccessRequest8 = positionAfterr1Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1Method);
  }
  uint64_t positionAfterr1MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest8))
  {
    positionAfterr1MinRole = positionAfterAccessRequest8;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest8),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest8),
      Ctxt,
      Input,
      positionAfterr1Method);
    positionAfterr1MinRole = positionAfterAccessRequest8;
  }
  if (EverParseIsError(positionAfterr1MinRole))
  {
    return positionAfterr1MinRole;
  }
  uint8_t r1MinRole = Input[(uint32_t)positionAfterr1Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes10 = 2ULL <= (InputLength - positionAfterr1MinRole);
  uint64_t positionAfterAccessRequest9;
  if (hasBytes10)
  {
    positionAfterAccessRequest9 = positionAfterr1MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest9 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1MinRole);
  }
  uint64_t positionAfterr1ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest9))
  {
    positionAfterr1ReqScope = positionAfterAccessRequest9;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r1_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest9),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest9),
      Ctxt,
      Input,
      positionAfterr1MinRole);
    positionAfterr1ReqScope = positionAfterAccessRequest9;
  }
  if (EverParseIsError(positionAfterr1ReqScope))
  {
    return positionAfterr1ReqScope;
  }
  uint16_t r2 = Load16Le(Input + (uint32_t)positionAfterr1MinRole);
  uint16_t r1ReqScope = (uint16_t)(uint32_t)r2;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes11 = 4ULL <= (InputLength - positionAfterr1ReqScope);
  uint64_t positionAfterAccessRequest10;
  if (hasBytes11)
  {
    positionAfterAccessRequest10 = positionAfterr1ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr1ReqScope);
  }
  uint64_t positionAfterr2PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest10))
  {
    positionAfterr2PathHash = positionAfterAccessRequest10;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest10),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest10),
      Ctxt,
      Input,
      positionAfterr1ReqScope);
    positionAfterr2PathHash = positionAfterAccessRequest10;
  }
  if (EverParseIsError(positionAfterr2PathHash))
  {
    return positionAfterr2PathHash;
  }
  uint32_t r2PathHash = Load32Le(Input + (uint32_t)positionAfterr1ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes12 = 1ULL <= (InputLength - positionAfterr2PathHash);
  uint64_t positionAfterAccessRequest11;
  if (hasBytes12)
  {
    positionAfterAccessRequest11 = positionAfterr2PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2PathHash);
  }
  uint64_t positionAfterr2Method;
  if (EverParseIsSuccess(positionAfterAccessRequest11))
  {
    positionAfterr2Method = positionAfterAccessRequest11;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest11),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest11),
      Ctxt,
      Input,
      positionAfterr2PathHash);
    positionAfterr2Method = positionAfterAccessRequest11;
  }
  if (EverParseIsError(positionAfterr2Method))
  {
    return positionAfterr2Method;
  }
  uint8_t r2Method = Input[(uint32_t)positionAfterr2PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterr2Method);
  uint64_t positionAfterAccessRequest12;
  if (hasBytes13)
  {
    positionAfterAccessRequest12 = positionAfterr2Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2Method);
  }
  uint64_t positionAfterr2MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest12))
  {
    positionAfterr2MinRole = positionAfterAccessRequest12;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest12),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest12),
      Ctxt,
      Input,
      positionAfterr2Method);
    positionAfterr2MinRole = positionAfterAccessRequest12;
  }
  if (EverParseIsError(positionAfterr2MinRole))
  {
    return positionAfterr2MinRole;
  }
  uint8_t r2MinRole = Input[(uint32_t)positionAfterr2Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes14 = 2ULL <= (InputLength - positionAfterr2MinRole);
  uint64_t positionAfterAccessRequest13;
  if (hasBytes14)
  {
    positionAfterAccessRequest13 = positionAfterr2MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2MinRole);
  }
  uint64_t positionAfterr2ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest13))
  {
    positionAfterr2ReqScope = positionAfterAccessRequest13;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r2_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest13),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest13),
      Ctxt,
      Input,
      positionAfterr2MinRole);
    positionAfterr2ReqScope = positionAfterAccessRequest13;
  }
  if (EverParseIsError(positionAfterr2ReqScope))
  {
    return positionAfterr2ReqScope;
  }
  uint16_t r3 = Load16Le(Input + (uint32_t)positionAfterr2MinRole);
  uint16_t r2ReqScope = (uint16_t)(uint32_t)r3;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterr2ReqScope);
  uint64_t positionAfterAccessRequest14;
  if (hasBytes15)
  {
    positionAfterAccessRequest14 = positionAfterr2ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest14 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr2ReqScope);
  }
  uint64_t positionAfterr3PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest14))
  {
    positionAfterr3PathHash = positionAfterAccessRequest14;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest14),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest14),
      Ctxt,
      Input,
      positionAfterr2ReqScope);
    positionAfterr3PathHash = positionAfterAccessRequest14;
  }
  if (EverParseIsError(positionAfterr3PathHash))
  {
    return positionAfterr3PathHash;
  }
  uint32_t r3PathHash = Load32Le(Input + (uint32_t)positionAfterr2ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes16 = 1ULL <= (InputLength - positionAfterr3PathHash);
  uint64_t positionAfterAccessRequest15;
  if (hasBytes16)
  {
    positionAfterAccessRequest15 = positionAfterr3PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest15 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3PathHash);
  }
  uint64_t positionAfterr3Method;
  if (EverParseIsSuccess(positionAfterAccessRequest15))
  {
    positionAfterr3Method = positionAfterAccessRequest15;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest15),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest15),
      Ctxt,
      Input,
      positionAfterr3PathHash);
    positionAfterr3Method = positionAfterAccessRequest15;
  }
  if (EverParseIsError(positionAfterr3Method))
  {
    return positionAfterr3Method;
  }
  uint8_t r3Method = Input[(uint32_t)positionAfterr3PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterr3Method);
  uint64_t positionAfterAccessRequest16;
  if (hasBytes17)
  {
    positionAfterAccessRequest16 = positionAfterr3Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3Method);
  }
  uint64_t positionAfterr3MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest16))
  {
    positionAfterr3MinRole = positionAfterAccessRequest16;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest16),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest16),
      Ctxt,
      Input,
      positionAfterr3Method);
    positionAfterr3MinRole = positionAfterAccessRequest16;
  }
  if (EverParseIsError(positionAfterr3MinRole))
  {
    return positionAfterr3MinRole;
  }
  uint8_t r3MinRole = Input[(uint32_t)positionAfterr3Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes18 = 2ULL <= (InputLength - positionAfterr3MinRole);
  uint64_t positionAfterAccessRequest17;
  if (hasBytes18)
  {
    positionAfterAccessRequest17 = positionAfterr3MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest17 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3MinRole);
  }
  uint64_t positionAfterr3ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest17))
  {
    positionAfterr3ReqScope = positionAfterAccessRequest17;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r3_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest17),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest17),
      Ctxt,
      Input,
      positionAfterr3MinRole);
    positionAfterr3ReqScope = positionAfterAccessRequest17;
  }
  if (EverParseIsError(positionAfterr3ReqScope))
  {
    return positionAfterr3ReqScope;
  }
  uint16_t r4 = Load16Le(Input + (uint32_t)positionAfterr3MinRole);
  uint16_t r3ReqScope = (uint16_t)(uint32_t)r4;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes19 = 4ULL <= (InputLength - positionAfterr3ReqScope);
  uint64_t positionAfterAccessRequest18;
  if (hasBytes19)
  {
    positionAfterAccessRequest18 = positionAfterr3ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest18 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr3ReqScope);
  }
  uint64_t positionAfterr4PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest18))
  {
    positionAfterr4PathHash = positionAfterAccessRequest18;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest18),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest18),
      Ctxt,
      Input,
      positionAfterr3ReqScope);
    positionAfterr4PathHash = positionAfterAccessRequest18;
  }
  if (EverParseIsError(positionAfterr4PathHash))
  {
    return positionAfterr4PathHash;
  }
  uint32_t r4PathHash = Load32Le(Input + (uint32_t)positionAfterr3ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes20 = 1ULL <= (InputLength - positionAfterr4PathHash);
  uint64_t positionAfterAccessRequest19;
  if (hasBytes20)
  {
    positionAfterAccessRequest19 = positionAfterr4PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest19 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4PathHash);
  }
  uint64_t positionAfterr4Method;
  if (EverParseIsSuccess(positionAfterAccessRequest19))
  {
    positionAfterr4Method = positionAfterAccessRequest19;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest19),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest19),
      Ctxt,
      Input,
      positionAfterr4PathHash);
    positionAfterr4Method = positionAfterAccessRequest19;
  }
  if (EverParseIsError(positionAfterr4Method))
  {
    return positionAfterr4Method;
  }
  uint8_t r4Method = Input[(uint32_t)positionAfterr4PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes21 = 1ULL <= (InputLength - positionAfterr4Method);
  uint64_t positionAfterAccessRequest20;
  if (hasBytes21)
  {
    positionAfterAccessRequest20 = positionAfterr4Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest20 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4Method);
  }
  uint64_t positionAfterr4MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest20))
  {
    positionAfterr4MinRole = positionAfterAccessRequest20;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest20),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest20),
      Ctxt,
      Input,
      positionAfterr4Method);
    positionAfterr4MinRole = positionAfterAccessRequest20;
  }
  if (EverParseIsError(positionAfterr4MinRole))
  {
    return positionAfterr4MinRole;
  }
  uint8_t r4MinRole = Input[(uint32_t)positionAfterr4Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes22 = 2ULL <= (InputLength - positionAfterr4MinRole);
  uint64_t positionAfterAccessRequest21;
  if (hasBytes22)
  {
    positionAfterAccessRequest21 = positionAfterr4MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest21 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4MinRole);
  }
  uint64_t positionAfterr4ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest21))
  {
    positionAfterr4ReqScope = positionAfterAccessRequest21;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r4_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest21),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest21),
      Ctxt,
      Input,
      positionAfterr4MinRole);
    positionAfterr4ReqScope = positionAfterAccessRequest21;
  }
  if (EverParseIsError(positionAfterr4ReqScope))
  {
    return positionAfterr4ReqScope;
  }
  uint16_t r5 = Load16Le(Input + (uint32_t)positionAfterr4MinRole);
  uint16_t r4ReqScope = (uint16_t)(uint32_t)r5;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes23 = 4ULL <= (InputLength - positionAfterr4ReqScope);
  uint64_t positionAfterAccessRequest22;
  if (hasBytes23)
  {
    positionAfterAccessRequest22 = positionAfterr4ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest22 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr4ReqScope);
  }
  uint64_t positionAfterr5PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest22))
  {
    positionAfterr5PathHash = positionAfterAccessRequest22;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest22),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest22),
      Ctxt,
      Input,
      positionAfterr4ReqScope);
    positionAfterr5PathHash = positionAfterAccessRequest22;
  }
  if (EverParseIsError(positionAfterr5PathHash))
  {
    return positionAfterr5PathHash;
  }
  uint32_t r5PathHash = Load32Le(Input + (uint32_t)positionAfterr4ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes24 = 1ULL <= (InputLength - positionAfterr5PathHash);
  uint64_t positionAfterAccessRequest23;
  if (hasBytes24)
  {
    positionAfterAccessRequest23 = positionAfterr5PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest23 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5PathHash);
  }
  uint64_t positionAfterr5Method;
  if (EverParseIsSuccess(positionAfterAccessRequest23))
  {
    positionAfterr5Method = positionAfterAccessRequest23;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest23),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest23),
      Ctxt,
      Input,
      positionAfterr5PathHash);
    positionAfterr5Method = positionAfterAccessRequest23;
  }
  if (EverParseIsError(positionAfterr5Method))
  {
    return positionAfterr5Method;
  }
  uint8_t r5Method = Input[(uint32_t)positionAfterr5PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAfterr5Method);
  uint64_t positionAfterAccessRequest24;
  if (hasBytes25)
  {
    positionAfterAccessRequest24 = positionAfterr5Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest24 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5Method);
  }
  uint64_t positionAfterr5MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest24))
  {
    positionAfterr5MinRole = positionAfterAccessRequest24;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest24),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest24),
      Ctxt,
      Input,
      positionAfterr5Method);
    positionAfterr5MinRole = positionAfterAccessRequest24;
  }
  if (EverParseIsError(positionAfterr5MinRole))
  {
    return positionAfterr5MinRole;
  }
  uint8_t r5MinRole = Input[(uint32_t)positionAfterr5Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes26 = 2ULL <= (InputLength - positionAfterr5MinRole);
  uint64_t positionAfterAccessRequest25;
  if (hasBytes26)
  {
    positionAfterAccessRequest25 = positionAfterr5MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest25 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5MinRole);
  }
  uint64_t positionAfterr5ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest25))
  {
    positionAfterr5ReqScope = positionAfterAccessRequest25;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r5_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest25),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest25),
      Ctxt,
      Input,
      positionAfterr5MinRole);
    positionAfterr5ReqScope = positionAfterAccessRequest25;
  }
  if (EverParseIsError(positionAfterr5ReqScope))
  {
    return positionAfterr5ReqScope;
  }
  uint16_t r6 = Load16Le(Input + (uint32_t)positionAfterr5MinRole);
  uint16_t r5ReqScope = (uint16_t)(uint32_t)r6;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes27 = 4ULL <= (InputLength - positionAfterr5ReqScope);
  uint64_t positionAfterAccessRequest26;
  if (hasBytes27)
  {
    positionAfterAccessRequest26 = positionAfterr5ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest26 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr5ReqScope);
  }
  uint64_t positionAfterr6PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest26))
  {
    positionAfterr6PathHash = positionAfterAccessRequest26;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest26),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest26),
      Ctxt,
      Input,
      positionAfterr5ReqScope);
    positionAfterr6PathHash = positionAfterAccessRequest26;
  }
  if (EverParseIsError(positionAfterr6PathHash))
  {
    return positionAfterr6PathHash;
  }
  uint32_t r6PathHash = Load32Le(Input + (uint32_t)positionAfterr5ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterr6PathHash);
  uint64_t positionAfterAccessRequest27;
  if (hasBytes28)
  {
    positionAfterAccessRequest27 = positionAfterr6PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest27 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6PathHash);
  }
  uint64_t positionAfterr6Method;
  if (EverParseIsSuccess(positionAfterAccessRequest27))
  {
    positionAfterr6Method = positionAfterAccessRequest27;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest27),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest27),
      Ctxt,
      Input,
      positionAfterr6PathHash);
    positionAfterr6Method = positionAfterAccessRequest27;
  }
  if (EverParseIsError(positionAfterr6Method))
  {
    return positionAfterr6Method;
  }
  uint8_t r6Method = Input[(uint32_t)positionAfterr6PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes29 = 1ULL <= (InputLength - positionAfterr6Method);
  uint64_t positionAfterAccessRequest28;
  if (hasBytes29)
  {
    positionAfterAccessRequest28 = positionAfterr6Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest28 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6Method);
  }
  uint64_t positionAfterr6MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest28))
  {
    positionAfterr6MinRole = positionAfterAccessRequest28;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest28),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest28),
      Ctxt,
      Input,
      positionAfterr6Method);
    positionAfterr6MinRole = positionAfterAccessRequest28;
  }
  if (EverParseIsError(positionAfterr6MinRole))
  {
    return positionAfterr6MinRole;
  }
  uint8_t r6MinRole = Input[(uint32_t)positionAfterr6Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes30 = 2ULL <= (InputLength - positionAfterr6MinRole);
  uint64_t positionAfterAccessRequest29;
  if (hasBytes30)
  {
    positionAfterAccessRequest29 = positionAfterr6MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest29 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6MinRole);
  }
  uint64_t positionAfterr6ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest29))
  {
    positionAfterr6ReqScope = positionAfterAccessRequest29;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r6_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest29),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest29),
      Ctxt,
      Input,
      positionAfterr6MinRole);
    positionAfterr6ReqScope = positionAfterAccessRequest29;
  }
  if (EverParseIsError(positionAfterr6ReqScope))
  {
    return positionAfterr6ReqScope;
  }
  uint16_t r7 = Load16Le(Input + (uint32_t)positionAfterr6MinRole);
  uint16_t r6ReqScope = (uint16_t)(uint32_t)r7;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes31 = 4ULL <= (InputLength - positionAfterr6ReqScope);
  uint64_t positionAfterAccessRequest30;
  if (hasBytes31)
  {
    positionAfterAccessRequest30 = positionAfterr6ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest30 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr6ReqScope);
  }
  uint64_t positionAfterr7PathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest30))
  {
    positionAfterr7PathHash = positionAfterAccessRequest30;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest30),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest30),
      Ctxt,
      Input,
      positionAfterr6ReqScope);
    positionAfterr7PathHash = positionAfterAccessRequest30;
  }
  if (EverParseIsError(positionAfterr7PathHash))
  {
    return positionAfterr7PathHash;
  }
  uint32_t r7PathHash = Load32Le(Input + (uint32_t)positionAfterr6ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes32 = 1ULL <= (InputLength - positionAfterr7PathHash);
  uint64_t positionAfterAccessRequest31;
  if (hasBytes32)
  {
    positionAfterAccessRequest31 = positionAfterr7PathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest31 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7PathHash);
  }
  uint64_t positionAfterr7Method;
  if (EverParseIsSuccess(positionAfterAccessRequest31))
  {
    positionAfterr7Method = positionAfterAccessRequest31;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest31),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest31),
      Ctxt,
      Input,
      positionAfterr7PathHash);
    positionAfterr7Method = positionAfterAccessRequest31;
  }
  if (EverParseIsError(positionAfterr7Method))
  {
    return positionAfterr7Method;
  }
  uint8_t r7Method = Input[(uint32_t)positionAfterr7PathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes33 = 1ULL <= (InputLength - positionAfterr7Method);
  uint64_t positionAfterAccessRequest32;
  if (hasBytes33)
  {
    positionAfterAccessRequest32 = positionAfterr7Method + 1ULL;
  }
  else
  {
    positionAfterAccessRequest32 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7Method);
  }
  uint64_t positionAfterr7MinRole;
  if (EverParseIsSuccess(positionAfterAccessRequest32))
  {
    positionAfterr7MinRole = positionAfterAccessRequest32;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_min_role",
      EverParseErrorReasonOfResult(positionAfterAccessRequest32),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest32),
      Ctxt,
      Input,
      positionAfterr7Method);
    positionAfterr7MinRole = positionAfterAccessRequest32;
  }
  if (EverParseIsError(positionAfterr7MinRole))
  {
    return positionAfterr7MinRole;
  }
  uint8_t r7MinRole = Input[(uint32_t)positionAfterr7Method];
  /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
  BOOLEAN hasBytes34 = 2ULL <= (InputLength - positionAfterr7MinRole);
  uint64_t positionAfterAccessRequest33;
  if (hasBytes34)
  {
    positionAfterAccessRequest33 = positionAfterr7MinRole + 2ULL;
  }
  else
  {
    positionAfterAccessRequest33 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7MinRole);
  }
  uint64_t positionAfterr7ReqScope;
  if (EverParseIsSuccess(positionAfterAccessRequest33))
  {
    positionAfterr7ReqScope = positionAfterAccessRequest33;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "r7_req_scope",
      EverParseErrorReasonOfResult(positionAfterAccessRequest33),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest33),
      Ctxt,
      Input,
      positionAfterr7MinRole);
    positionAfterr7ReqScope = positionAfterAccessRequest33;
  }
  if (EverParseIsError(positionAfterr7ReqScope))
  {
    return positionAfterr7ReqScope;
  }
  uint16_t r = Load16Le(Input + (uint32_t)positionAfterr7MinRole);
  uint16_t r7ReqScope = (uint16_t)(uint32_t)r;
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes35 = 4ULL <= (InputLength - positionAfterr7ReqScope);
  uint64_t positionAfterAccessRequest34;
  if (hasBytes35)
  {
    positionAfterAccessRequest34 = positionAfterr7ReqScope + 4ULL;
  }
  else
  {
    positionAfterAccessRequest34 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterr7ReqScope);
  }
  uint64_t positionAfterreqPathHash;
  if (EverParseIsSuccess(positionAfterAccessRequest34))
  {
    positionAfterreqPathHash = positionAfterAccessRequest34;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "req_path_hash",
      EverParseErrorReasonOfResult(positionAfterAccessRequest34),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest34),
      Ctxt,
      Input,
      positionAfterr7ReqScope);
    positionAfterreqPathHash = positionAfterAccessRequest34;
  }
  if (EverParseIsError(positionAfterreqPathHash))
  {
    return positionAfterreqPathHash;
  }
  uint32_t reqPathHash = Load32Le(Input + (uint32_t)positionAfterr7ReqScope);
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes36 = 1ULL <= (InputLength - positionAfterreqPathHash);
  uint64_t positionAfterAccessRequest35;
  if (hasBytes36)
  {
    positionAfterAccessRequest35 = positionAfterreqPathHash + 1ULL;
  }
  else
  {
    positionAfterAccessRequest35 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqPathHash);
  }
  uint64_t positionAfterreqMethod;
  if (EverParseIsSuccess(positionAfterAccessRequest35))
  {
    positionAfterreqMethod = positionAfterAccessRequest35;
  }
  else
  {
    ErrorHandlerFn("_AccessRequest",
      "req_method",
      EverParseErrorReasonOfResult(positionAfterAccessRequest35),
      EverParseGetValidatorErrorKind(positionAfterAccessRequest35),
      Ctxt,
      Input,
      positionAfterreqPathHash);
    positionAfterreqMethod = positionAfterAccessRequest35;
  }
  if (EverParseIsError(positionAfterreqMethod))
  {
    return positionAfterreqMethod;
  }
  uint8_t reqMethod = Input[(uint32_t)positionAfterreqPathHash];
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes37 = 1ULL <= (InputLength - positionAfterreqMethod);
  uint64_t positionAfterRateOk;
  if (hasBytes37)
  {
    positionAfterRateOk = positionAfterreqMethod + 1ULL;
  }
  else
  {
    positionAfterRateOk =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterreqMethod);
  }
  uint64_t positionAfterAccessRequest36;
  if (EverParseIsError(positionAfterRateOk))
  {
    positionAfterAccessRequest36 = positionAfterRateOk;
  }
  else
  {
    uint8_t rateOk = Input[(uint32_t)positionAfterreqMethod];
    KRML_MAYBE_UNUSED_VAR(rateOk);
    BOOLEAN rateOkConstraintIsOk = rateCount < RBACPOLICY____MAX_RATE;
    uint64_t
    positionAfterRateOk1 = EverParseCheckConstraintOk(rateOkConstraintIsOk, positionAfterRateOk);
    if (EverParseIsError(positionAfterRateOk1))
    {
      positionAfterAccessRequest36 = positionAfterRateOk1;
    }
    else
    {
      /* Validating field _access_ok */
      /* Checking that we have enough space for a UINT8, i.e., 1 byte */
      BOOLEAN hasBytes = 1ULL <= (InputLength - positionAfterRateOk1);
      uint64_t positionAfterAccessOk_refinement;
      if (hasBytes)
      {
        positionAfterAccessOk_refinement = positionAfterRateOk1 + 1ULL;
      }
      else
      {
        positionAfterAccessOk_refinement =
          EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterRateOk1);
      }
      uint64_t positionAfterAccessRequest37;
      if (EverParseIsError(positionAfterAccessOk_refinement))
      {
        positionAfterAccessRequest37 = positionAfterAccessOk_refinement;
      }
      else
      {
        /* reading field_value */
        uint8_t accessOk_refinement = Input[(uint32_t)positionAfterRateOk1];
        KRML_MAYBE_UNUSED_VAR(accessOk_refinement);
        /* start: checking constraint */
        BOOLEAN
        accessOk_refinementConstraintIsOk =
          (r0PathHash == reqPathHash && r0Method == reqMethod && authState >= r0MinRole &&
            ((uint32_t)authScope & (uint32_t)r0ReqScope) == r0ReqScope)
          ||
            (r1PathHash == reqPathHash && r1Method == reqMethod && authState >= r1MinRole &&
              ((uint32_t)authScope & (uint32_t)r1ReqScope) == r1ReqScope)
          ||
            (r2PathHash == reqPathHash && r2Method == reqMethod && authState >= r2MinRole &&
              ((uint32_t)authScope & (uint32_t)r2ReqScope) == r2ReqScope)
          ||
            (r3PathHash == reqPathHash && r3Method == reqMethod && authState >= r3MinRole &&
              ((uint32_t)authScope & (uint32_t)r3ReqScope) == r3ReqScope)
          ||
            (r4PathHash == reqPathHash && r4Method == reqMethod && authState >= r4MinRole &&
              ((uint32_t)authScope & (uint32_t)r4ReqScope) == r4ReqScope)
          ||
            (r5PathHash == reqPathHash && r5Method == reqMethod && authState >= r5MinRole &&
              ((uint32_t)authScope & (uint32_t)r5ReqScope) == r5ReqScope)
          ||
            (r6PathHash == reqPathHash && r6Method == reqMethod && authState >= r6MinRole &&
              ((uint32_t)authScope & (uint32_t)r6ReqScope) == r6ReqScope)
          ||
            (r7PathHash == reqPathHash && r7Method == reqMethod && authState >= r7MinRole &&
              ((uint32_t)authScope & (uint32_t)r7ReqScope) == r7ReqScope);
        /* end: checking constraint */
        positionAfterAccessRequest37 =
          EverParseCheckConstraintOk(accessOk_refinementConstraintIsOk,
            positionAfterAccessOk_refinement);
      }
      if (EverParseIsSuccess(positionAfterAccessRequest37))
      {
        positionAfterAccessRequest36 = positionAfterAccessRequest37;
      }
      else
      {
        ErrorHandlerFn("_AccessRequest",
          "_access_ok.refinement",
          EverParseErrorReasonOfResult(positionAfterAccessRequest37),
          EverParseGetValidatorErrorKind(positionAfterAccessRequest37),
          Ctxt,
          Input,
          positionAfterRateOk1);
        positionAfterAccessRequest36 = positionAfterAccessRequest37;
      }
    }
  }
  if (EverParseIsSuccess(positionAfterAccessRequest36))
  {
    return positionAfterAccessRequest36;
  }
  ErrorHandlerFn("_AccessRequest",
    "_rate_ok",
    EverParseErrorReasonOfResult(positionAfterAccessRequest36),
    EverParseGetValidatorErrorKind(positionAfterAccessRequest36),
    Ctxt,
    Input,
    positionAfterreqMethod);
  return positionAfterAccessRequest36;
}

