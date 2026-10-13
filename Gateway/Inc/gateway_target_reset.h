#ifndef GATEWAY_TARGET_RESET_H
#define GATEWAY_TARGET_RESET_H
/* Serial-commanded reset of an external board. PA0 (TGT_NRST) is open-drain and
 * idles released; the line "RESET" on USART3 pulls it low for 100 ms. */
void gateway_target_reset_start(void);
#endif
