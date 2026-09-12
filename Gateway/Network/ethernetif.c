/**
  ******************************************************************************
  * @file    LwIP/LwIP_HTTP_Server_Netconn_RTOS/Src/ethernetif.c
  * @author  MCD Application Team
  * @brief   This file implements Ethernet network interface drivers for lwIP
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2016 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* STM32F767 adapter for CubeF7 1.17.4 HAL/LAN8742 and lwIP 2.1.2.
 * RX custom-pbuf chaining follows ST's Nucleo netconn example (license notice above).
 * A copied TX buffer and driver mutex bound ownership through DMA completion.
 */
#include "ethernetif.h"
#include "gateway_platform.h"
#include "gateway_log.h"
#include "main.h"
#include "lan8742.h"
#include "lwip/etharp.h"
#include "lwip/netifapi.h"
#include "lwip/pbuf.h"
#include "FreeRTOS.h"
#include "task.h"
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
extern ETH_HandleTypeDef heth;
extern ETH_TxPacketConfig TxConfig;
#define RX_COUNT 10U
#define FRAME_BYTES 1536U
#define DMA_DATA __attribute__((section(".eth_data"), aligned(32)))
typedef struct {
    struct pbuf_custom custom;
    _Alignas(32) uint8_t bytes[FRAME_BYTES];
} RxBuffer;
static RxBuffer rx[RX_COUNT] DMA_DATA;
static uint8_t tx[FRAME_BYTES] DMA_DATA;
/* 0=free, 1=DMA/HAL, 2=linked packet (HAL or lwIP). */
static uint8_t rx_state[RX_COUNT];
static osSemaphoreId_t rx_sem, tx_sem;
static osMutexId_t driver_mutex;
static lan8742_Object_t phy;
static struct netif *interface;
osThreadId_t gateway_eth_task, gateway_link_task;
volatile uint32_t gateway_link_up, gateway_link_epoch;
volatile uint32_t gateway_rx_packets, gateway_tx_packets, gateway_rx_drops, gateway_tx_errors;
static volatile uint32_t need_reset;
static _Alignas(8) StackType_t input_stack[4096/4], link_stack[2048/4];
static StaticTask_t input_tcb, link_tcb;
static StaticSemaphore_t mutex_cb, rx_cb, tx_cb;
static int32_t io_init(void) { HAL_ETH_SetMDIOClockRange(&heth); return 0; }
static int32_t io_deinit(void) { return 0; }
static int32_t io_read(uint32_t a,uint32_t r,uint32_t *v) { return HAL_ETH_ReadPHYRegister(&heth,a,r,v)==HAL_OK?0:-1; }
static int32_t io_write(uint32_t a,uint32_t r,uint32_t v) { return HAL_ETH_WritePHYRegister(&heth,a,r,v)==HAL_OK?0:-1; }
static int32_t io_tick(void) { return (int32_t)HAL_GetTick(); }
static void rx_free(struct pbuf *p)
{
    RxBuffer *b=(RxBuffer *)p;
    size_t i=(size_t)(b-rx);
    configASSERT(i<RX_COUNT);
    taskENTER_CRITICAL(); rx_state[i]=0; taskEXIT_CRITICAL();
    (void)osSemaphoreRelease(rx_sem);
}
void HAL_ETH_RxAllocateCallback(uint8_t **buffer)
{
    *buffer=NULL;
    taskENTER_CRITICAL();
    for(unsigned i=0;i<RX_COUNT;++i) if(!rx_state[i]) {
        rx_state[i]=1; rx[i].custom.custom_free_function=rx_free;
        pbuf_alloced_custom(PBUF_RAW,0,PBUF_REF,&rx[i].custom,rx[i].bytes,FRAME_BYTES);
        *buffer=rx[i].bytes; break;
    }
    taskEXIT_CRITICAL();
}
void HAL_ETH_RxLinkCallback(void **first,void **last,uint8_t *buffer,uint16_t length)
{
    RxBuffer *b=(RxBuffer *)(buffer - offsetof(RxBuffer,bytes));
    struct pbuf *p=&b->custom.pbuf;
    configASSERT((size_t)(b-rx)<RX_COUNT && length<=FRAME_BYTES);
    rx_state[b-rx]=2;
    p->next=NULL; p->len=length; p->tot_len=0;
    if(!*first) *first=p; else ((struct pbuf *)*last)->next=p;
    *last=p;
    for(p=*first;p;p=p->next) p->tot_len+=length;
}
void HAL_ETH_RxCpltCallback(ETH_HandleTypeDef *h) { (void)h; (void)osSemaphoreRelease(rx_sem); }
void HAL_ETH_TxCpltCallback(ETH_HandleTypeDef *h) { (void)h; (void)osSemaphoreRelease(tx_sem); }
void HAL_ETH_TxFreeCallback(uint32_t *data) { (void)data; }
void HAL_ETH_ErrorCallback(ETH_HandleTypeDef *h)
{
    if(h->DMAErrorCode & ETH_DMASR_FBES) need_reset=1;
    (void)osSemaphoreRelease(rx_sem);
}
void ETH_IRQHandler(void) { HAL_ETH_IRQHandler(&heth); }
/* driver_mutex held; hardware reset definitively ends all outstanding DMA. */
static bool reset_mac(void)
{
    HAL_NVIC_DisableIRQ(ETH_IRQn);
    __HAL_RCC_ETHMAC_FORCE_RESET(); __DSB(); __HAL_RCC_ETHMAC_RELEASE_RESET(); __DSB();
    if(heth.RxDescList.pRxStart) pbuf_free(heth.RxDescList.pRxStart);
    taskENTER_CRITICAL();
    for(unsigned i=0;i<RX_COUNT;++i) if(rx_state[i]==1) rx_state[i]=0;
    taskEXIT_CRITICAL();
    memset(&heth.RxDescList,0,sizeof(heth.RxDescList));
    memset(&heth.TxDescList,0,sizeof(heth.TxDescList));
    heth.gState=HAL_ETH_STATE_READY;
    bool ok=HAL_ETH_Init(&heth)==HAL_OK;
    HAL_NVIC_ClearPendingIRQ(ETH_IRQn); HAL_NVIC_EnableIRQ(ETH_IRQn);
    return ok;
}
static err_t output(struct netif *n,struct pbuf *p)
{
    (void)n;
    if(p->tot_len>sizeof(tx) || osMutexAcquire(driver_mutex,250)!=osOK) return ERR_IF;
    err_t result=ERR_IF;
    if(gateway_link_up && !need_reset) {
        while(osSemaphoreAcquire(tx_sem,0)==osOK) { }
        pbuf_copy_partial(p,tx,p->tot_len,0);
        ETH_BufferTypeDef buffer={.buffer=tx,.len=p->tot_len,.next=NULL};
        TxConfig.Length=p->tot_len; TxConfig.TxBuffer=&buffer; TxConfig.pData=tx;
        __DSB();
        if(HAL_ETH_Transmit_IT(&heth,&TxConfig)==HAL_OK && osSemaphoreAcquire(tx_sem,200)==osOK) {
            HAL_ETH_ReleaseTxPacket(&heth); ++gateway_tx_packets; result=ERR_OK;
        } else {
            ++gateway_tx_errors; gateway_link_up=0; ++gateway_link_epoch;
            /* Do not reuse the bounce buffer until reset has stopped DMA. */
            need_reset=1;
            (void)reset_mac();
        }
    }
    (void)osMutexRelease(driver_mutex); return result;
}
static void input_thread(void *arg)
{
    (void)arg;
    for(;;) {
        (void)osSemaphoreAcquire(rx_sem,100);
        for(unsigned budget=0;budget<16;++budget) {
            struct pbuf *p=NULL;
            (void)osMutexAcquire(driver_mutex,osWaitForever);
            HAL_StatusTypeDef result=HAL_ERROR;
            if(gateway_link_up && !need_reset) result=HAL_ETH_ReadData(&heth,(void **)&p);
            (void)osMutexRelease(driver_mutex);
            if(result!=HAL_OK || !p) break;
            ++gateway_rx_packets;
            if(interface->input(p,interface)!=ERR_OK) { ++gateway_rx_drops; pbuf_free(p); }
        }
        (void)osDelay(1);
    }
}
static void link_thread(void *arg)
{
    (void)arg; int32_t previous=-99;
    bool rmii_good=false;
    for(;;) {
        (void)osMutexAcquire(driver_mutex,osWaitForever);
        int32_t link=LAN8742_GetLinkState(&phy);
        bool up=link>=LAN8742_STATUS_100MBITS_FULLDUPLEX && link<=LAN8742_STATUS_10MBITS_HALFDUPLEX;
        bool changed=link!=previous || need_reset;
        if(changed) {
            gateway_link_up=0; ++gateway_link_epoch;
            bool ok=reset_mac(); need_reset=!ok;
            if(ok && up) {
                ETH_MACConfigTypeDef mac; HAL_ETH_GetMACConfig(&heth,&mac);
                mac.Speed=(link==2 || link==3)?ETH_SPEED_100M:ETH_SPEED_10M;
                mac.DuplexMode=(link==2 || link==4)?ETH_FULLDUPLEX_MODE:ETH_HALFDUPLEX_MODE;
                mac.ChecksumOffload=DISABLE;
                HAL_ETH_SetMACConfig(&heth,&mac);
                gateway_link_up=HAL_ETH_Start_IT(&heth)==HAL_OK;
                if(!gateway_link_up) need_reset=1;
            }
            previous=link;
        }
        /* ST's F767 RMII startup workaround, folded into this bounded monitor. */
        if(!rmii_good && gateway_link_up) {
            if(heth.Instance->MMCRGUFCR) rmii_good=true;
            else if(heth.Instance->MMCRFCECR>10) {
                CLEAR_BIT(SYSCFG->PMC,SYSCFG_PMC_MII_RMII_SEL);
                SET_BIT(SYSCFG->PMC,SYSCFG_PMC_MII_RMII_SEL);
                SET_BIT(heth.Instance->MMCCR,ETH_MMCCR_CR);
            }
        }
        bool active=gateway_link_up!=0;
        (void)osMutexRelease(driver_mutex);
        if(changed) {
            if(active) (void)netifapi_netif_set_link_up(interface);
            else (void)netifapi_netif_set_link_down(interface);
            gateway_log("[ETH] link=%s phy=%ld epoch=%lu\n",active?"UP":"DOWN",(long)link,(unsigned long)gateway_link_epoch);
        }
        (void)osDelay(250);
    }
}
err_t gateway_ethernet_init(struct netif *n)
{
    interface=n;
    memset(rx,0,sizeof(rx)); memset(tx,0,sizeof(tx)); memset(rx_state,0,sizeof(rx_state));
    const osMutexAttr_t ma={.attr_bits=osMutexPrioInherit,.cb_mem=&mutex_cb,.cb_size=sizeof(mutex_cb)};
    const osSemaphoreAttr_t ra={.cb_mem=&rx_cb,.cb_size=sizeof(rx_cb)}, ta={.cb_mem=&tx_cb,.cb_size=sizeof(tx_cb)};
    driver_mutex=osMutexNew(&ma); rx_sem=osSemaphoreNew(1,0,&ra); tx_sem=osSemaphoreNew(1,0,&ta);
    if(!driver_mutex || !rx_sem || !tx_sem) return ERR_MEM;
    heth.Init.RxBuffLen=FRAME_BYTES;
    TxConfig.Attributes=ETH_TX_PACKETS_FEATURES_CRCPAD | ETH_TX_PACKETS_FEATURES_CSUM;
    TxConfig.ChecksumCtrl=ETH_CHECKSUM_DISABLE;
    TxConfig.CRCPadCtrl=ETH_CRC_PAD_INSERT;
    if(!reset_mac()) return ERR_IF;
    lan8742_IOCtx_t io={io_init,io_deinit,io_write,io_read,io_tick};
    if(LAN8742_RegisterBusIO(&phy,&io)!=LAN8742_STATUS_OK || LAN8742_Init(&phy)!=LAN8742_STATUS_OK) return ERR_IF;
    n->name[0]='p'; n->name[1]='g'; n->hwaddr_len=6; memcpy(n->hwaddr,heth.Init.MACAddr,6);
    n->mtu=1500; n->flags=NETIF_FLAG_BROADCAST|NETIF_FLAG_ETHARP;
    n->output=etharp_output; n->linkoutput=output;
    const osThreadAttr_t ia={.name="ETH input",.priority=osPriorityAboveNormal,.stack_mem=input_stack,.stack_size=sizeof(input_stack),.cb_mem=&input_tcb,.cb_size=sizeof(input_tcb)};
    const osThreadAttr_t la={.name="ETH link",.priority=osPriorityBelowNormal,.stack_mem=link_stack,.stack_size=sizeof(link_stack),.cb_mem=&link_tcb,.cb_size=sizeof(link_tcb)};
    gateway_eth_task=osThreadNew(input_thread,NULL,&ia); gateway_link_task=osThreadNew(link_thread,NULL,&la);
    return gateway_eth_task && gateway_link_task?ERR_OK:ERR_MEM;
}
