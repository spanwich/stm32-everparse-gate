

#ifndef RbacPolicy_H
#define RbacPolicy_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "EverParse.h"

#define RBACPOLICY____PATH_LOGIN (0x11111111U)

#define RBACPOLICY____PATH_LOGOUT (0x22222222U)

#define RBACPOLICY____PATH_STATUS (0x33333333U)

#define RBACPOLICY____PATH_POLICY (0x44444444U)

#define RBACPOLICY____DEAD_HASH (0xDEADDEADU)

#define RBACPOLICY____METHOD_GET (1U)

#define RBACPOLICY____METHOD_POST (2U)

#define RBACPOLICY____METHOD_PUT (3U)

#define RBACPOLICY____ROLE_NONE (0U)

#define RBACPOLICY____ROLE_OPERATOR (1U)

#define RBACPOLICY____ROLE_ADMIN (2U)

#define RBACPOLICY____MAX_RATE (50U)

#define RBACPOLICY____MAX_RULES (8U)

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
);

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
);

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
);

#if defined(__cplusplus)
}
#endif

#define RbacPolicy_H_DEFINED
#endif /* RbacPolicy_H */
