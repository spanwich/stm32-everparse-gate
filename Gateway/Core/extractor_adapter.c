/* This translation unit includes only the extractor's generated runtime. */
#include "gateway_core.h"
#include "HTTP_Extract_Complete.h"
#include "IPC_Extract.h"
#include <string.h>

GatewayResult gateway_extract(GatewayContext *c)
{
    if (!c) return GATEWAY_REJECTED;
    c->security_len = c->app_len = c->gate_len = 0;
    c->result = GATEWAY_REJECTED;
    c->extraction_code = EXTRACT_MALFORMED;
    memset(c->security, 0, sizeof(c->security));
    memset(c->auth, 0, sizeof(c->auth));
    if (!gateway_guards_ok(c) || c->request_len > sizeof(c->request)) return c->result;
    c->extraction_code = extract_security_params(c->request, c->request_len,
                                                 c->security, &c->security_len);
    if (c->extraction_code == EXTRACT_OK && gateway_guards_ok(c) &&
        c->security_len >= SECPARAMS_HEADER_SIZE && c->security_len <= sizeof(c->security))
        c->result = GATEWAY_EXTRACTED;
    else c->security_len = 0;
    return c->result;
}

GatewayResult gateway_set_identity(GatewayContext *c, const GatewayIdentity *id, uint8_t rate)
{
    if (!c) return GATEWAY_REJECTED;
    GatewayResult previous = c->result;
    c->result = GATEWAY_REJECTED;
    c->app_len = c->gate_len = 0;
    /* Never leave a stale role/scope/subject or rate after a failed identity. */
    memset(c->security + 6, 0, 36);
    c->security[0] = 0;
    memset(c->auth, 0, sizeof(c->auth));
    if (!gateway_guards_ok(c) || (previous != GATEWAY_EXTRACTED && previous != GATEWAY_IDENTIFIED) ||
        c->security_len < SECPARAMS_HEADER_SIZE || c->security_len > sizeof(c->security) ||
        !id || !id->valid || id->role > ROLE_ADMIN || id->subject_len > SUBJECT_ID_MAX)
        return c->result;
    c->auth[0] = 1;
    c->auth[1] = id->role;
    c->auth[2] = (uint8_t)id->scope;
    c->auth[3] = (uint8_t)(id->scope >> 8);
    c->auth[4] = id->subject_len;
    memcpy(c->auth + 5, id->subject, id->subject_len);
    populate_auth_fields(c->security, c->auth);
    populate_rate_field(c->security, rate);
    c->result = GATEWAY_IDENTIFIED;
    return c->result;
}
