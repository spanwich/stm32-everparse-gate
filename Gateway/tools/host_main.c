#include "gateway_tests.h"
#include "gateway_core.h"
#include "gateway_log.h"
#include <stdio.h>
#include <stdarg.h>
/* Host real tick is a fixed value: the normal self-tests reset the rate counter
 * per request (so they are clock-independent) and the rate self-test drives the
 * window through the synthetic clock (gateway_clock_synthetic). */
uint64_t gateway_platform_tick_ms(void) { return 0U; }
int gateway_log_write(const char *text, size_t n) { return (int)fwrite(text, 1, n, stdout); }
void gateway_log(const char *format, ...)
{ va_list args; va_start(args, format); vprintf(format, args); va_end(args); }
void gateway_test_yield(void) {}
int main(void)
{ GatewayTestStats stats = gateway_tests_run(); return stats.total > 0 && stats.passed == stats.total ? 0 : 1; }
