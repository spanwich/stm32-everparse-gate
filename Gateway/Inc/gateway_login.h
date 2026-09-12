#ifndef GATEWAY_LOGIN_H
#define GATEWAY_LOGIN_H
#include "gateway_core.h"
/* Strict two-field JSON, printable ASCII username <=32/password <=64. */
int gateway_login(const uint8_t *body, size_t length, char *response, size_t capacity);
bool gateway_login_validate(const uint8_t *token, size_t length, GatewayIdentity *identity);
#endif
