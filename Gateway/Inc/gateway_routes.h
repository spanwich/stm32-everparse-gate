#ifndef GATEWAY_ROUTES_H
#define GATEWAY_ROUTES_H
/* Handwritten transport route identifier, NOT an F* extractor sentinel.
 * Exact /demo requests are normalized for extraction, then mapped to this ID
 * before authentication/policy evaluation. EverParse compares arbitrary IDs. */
#define GATEWAY_PATH_DEMO 0x55555555u
#endif
