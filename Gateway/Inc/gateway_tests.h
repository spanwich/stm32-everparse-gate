#ifndef GATEWAY_TESTS_H
#define GATEWAY_TESTS_H
#include <stdint.h>
typedef struct { uint32_t passed, total; } GatewayTestStats;
int gateway_test_printf(const char *format, ...) __attribute__((format(printf, 1, 2)));
void gateway_test_check(GatewayTestStats *stats, const char *name, int ok);
GatewayTestStats gateway_tests_run(void);
/* Platform hook: the MCU yields between report records; the host does nothing. */
void gateway_test_yield(void);
void gateway_test_scan(GatewayTestStats *);
void gateway_test_method(GatewayTestStats *);
void gateway_test_path(GatewayTestStats *);
void gateway_test_header(GatewayTestStats *);
void gateway_test_extractor(GatewayTestStats *);
void gateway_test_ipc_extract(GatewayTestStats *);
void gateway_test_boundaries(GatewayTestStats *);
void gateway_test_policy(GatewayTestStats *);
void gateway_test_live_policy(GatewayTestStats *);
void gateway_test_login(GatewayTestStats *);
void gateway_test_http(GatewayTestStats *);
#endif
