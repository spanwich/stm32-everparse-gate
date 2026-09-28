#include "gateway_tests.h"
#include "gateway_core.h"
GatewayContext gateway_test_context;
#include "gateway_log.h"
#include <stdarg.h>
#include <stdio.h>
int paper_equivalence_board_run(void);
int gateway_test_printf(const char *format, ...)
{
    char line[256];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n >= 0) gateway_log_write(line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1);
    gateway_test_yield();
    return n;
}
void gateway_test_check(GatewayTestStats *s, const char *name, int ok)
{
    ++s->total;
    if (ok) ++s->passed;
    gateway_test_printf("  %s: %s\n", ok ? "PASS" : "FAIL", name);
}
GatewayTestStats gateway_tests_run(void)
{
    GatewayTestStats s = {0, 0};
    gateway_test_scan(&s); gateway_test_method(&s); gateway_test_path(&s);
    gateway_test_header(&s); gateway_test_extractor(&s); gateway_test_ipc_extract(&s);
    gateway_test_printf("[Legacy vectors] %lu/%lu\n", (unsigned long)s.passed, (unsigned long)s.total);
    gateway_test_boundaries(&s); gateway_test_policy(&s); gateway_test_http(&s); gateway_test_login(&s); gateway_test_live_policy(&s); gateway_test_mediation(&s);
    gateway_test_check(&s, "paper reference 12527-case equivalence", paper_equivalence_board_run() == 0);
    gateway_test_printf("[CORE SELFTEST] %s %lu/%lu; synthetic identity only\n",
                        s.passed == s.total ? "PASS" : "FAIL",
                        (unsigned long)s.passed, (unsigned long)s.total);
    return s;
}
