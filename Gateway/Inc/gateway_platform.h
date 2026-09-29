#ifndef GATEWAY_PLATFORM_H
#define GATEWAY_PLATFORM_H
#include <stdint.h>
typedef enum {
    GATEWAY_FAULT_STARTUP = 1, GATEWAY_FAULT_ALLOC = 2,
    GATEWAY_FAULT_STACK = 3, GATEWAY_FAULT_ASSERT = 4,
    GATEWAY_FAULT_HARD = 5, GATEWAY_FAULT_MEMORY = 6,
    GATEWAY_FAULT_BUS = 7, GATEWAY_FAULT_USAGE = 8
} GatewayFault;
typedef struct {
    uint32_t reason, line, cfsr, hfsr, msp, psp;
    const char *file;
    const void *task;
} GatewayFaultRecord;
/* Debugger-readable until reset; normal logging is not used from fault paths. */
extern volatile GatewayFaultRecord gateway_fault_record;
void gateway_boot_report(void);
void gateway_platform_start(void);
void gateway_platform_grant_log_access(void *task);
void *gateway_platform_network_task_handle(void);
void gateway_panic(GatewayFault reason) __attribute__((noreturn));
void gateway_assert_failed(const char *file, unsigned line) __attribute__((noreturn));
#endif
