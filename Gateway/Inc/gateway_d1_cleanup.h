#ifndef GATEWAY_D1_CLEANUP_H
#define GATEWAY_D1_CLEANUP_H
#include <stdbool.h>
#include "FreeRTOS.h"
#include "queue.h"
void gateway_d1_cleanup_start(void);
void gateway_d1_cleanup_grant(void *task);
void gateway_d1_cleanup_register(QueueHandle_t handle);
void gateway_d1_cleanup_forget(QueueHandle_t handle);
bool gateway_d1_cleanup_enqueue(QueueHandle_t handle);
#endif
