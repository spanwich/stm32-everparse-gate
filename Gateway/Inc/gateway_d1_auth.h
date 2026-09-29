#ifndef GATEWAY_D1_AUTH_H
#define GATEWAY_D1_AUTH_H
#include "gateway_core.h"

/* Private GATE <-> AUTH protocol. Queue items are copied by the kernel. */
void gateway_d1_auth_start(void);
void gateway_d1_auth_grant_gate(void *task);
bool gateway_d1_auth_identify(const uint8_t *token, size_t length,
                              GatewayIdentity *identity, uint8_t *rate);
int gateway_d1_auth_login(const uint8_t *body, size_t length,
                          char *token, uint8_t *token_length);

/* Called by the privileged initializer before AUTH becomes unprivileged. */
void gateway_d1_auth_secrets_init(void);
const uint8_t *gateway_d1_auth_key(void);
void gateway_auth_credential_init(void);
int gateway_auth_issue_token(const uint8_t *body, size_t length,
                             char *token, uint8_t *token_length);

#endif
