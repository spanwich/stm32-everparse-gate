#ifndef GATEWAY_ETHERNETIF_H
#define GATEWAY_ETHERNETIF_H
#include "lwip/netif.h"
#include "cmsis_os2.h"
err_t gateway_ethernet_init(struct netif *netif);
extern osThreadId_t gateway_eth_task, gateway_link_task;
extern volatile uint32_t gateway_link_up, gateway_link_epoch;
extern volatile uint32_t gateway_rx_packets, gateway_tx_packets, gateway_rx_drops, gateway_tx_errors;
#endif
