#ifndef GATEWAY_MEDIATION_H
#define GATEWAY_MEDIATION_H
#include "gateway_core.h"
/* Research branch: synchronous, single-owner mediation. kind is selected by
 * the trusted parser, never supplied by a client field. No retained pointers. */
enum { GATEWAY_PUBLIC=0, GATEWAY_LOGIN=1, GATEWAY_ACCESS=2, GATEWAY_UPDATE=3 };
#define GATEWAY_PATH_DASHBOARD 0x66666666UL
#define GATEWAY_PATH_SCRIPT 0x77777777UL
int gateway_mediate(GatewayContext *ctx, unsigned kind);
/* Pure JSON decoding for the login validator; no credentials are checked and
 * no token is issued here. The 106-byte buffer is initialized by the callee. */
bool gateway_login_prepare(const uint8_t *body, size_t length,
                           uint8_t envelope[106], uint32_t *envelope_length);
#endif
