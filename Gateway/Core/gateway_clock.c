/* Interface time source for the verified windowed rate counter. The live path
 * (gateway_http_process, unprivileged gate task) reads gateway_tick_ms and threads
 * the result into the counter. The synthetic override lets the rate self-test drive
 * the window deterministically through the full path on both the host and the real
 * build; it lives in .gateway_gate so the unprivileged gate task reads it live and
 * the (privileged) self-test writes it. gateway_platform_tick_ms is the real tick,
 * defined per platform (osKernelGetTickCount on target, a fixed host value). */
#include "gateway_core.h"

static uint64_t synthetic_now __attribute__((section(".gateway_gate")));
static uint8_t  synthetic_on  __attribute__((section(".gateway_gate")));

uint64_t gateway_tick_ms(void)
{
    return synthetic_on ? synthetic_now : gateway_platform_tick_ms();
}
void gateway_clock_synthetic(uint64_t now_ms) { synthetic_now = now_ms; synthetic_on = 1U; }
void gateway_clock_real(void) { synthetic_on = 0U; }
