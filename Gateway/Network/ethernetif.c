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
#include "paper_experiment.h"
#include "main.h"
#include "lan8742.h"
#include "lwip/etharp.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
extern ETH_HandleTypeDef heth;
extern ETH_TxPacketConfig TxConfig;
extern osThreadId_t gateway_tcpip_task;
#define RX_COUNT 10U
#define FRAME_BYTES 1536U
#define FRAME_SLOTS 4U
#define DMA_DATA __attribute__((section(".eth_data"), aligned(32)))
#define SHIM_PRIVATE __attribute__((section(".gateway_privileged")))
typedef struct { uint8_t slot; uint16_t length; } FrameReady;
typedef struct { uint8_t bytes[FRAME_BYTES]; } FrameSlot;
typedef struct { uint16_t length; uint8_t bytes[FRAME_BYTES]; } TxRequest;
typedef struct {
    struct pbuf_custom custom;
    _Alignas(32) uint8_t bytes[FRAME_BYTES];
} RxBuffer;
static RxBuffer rx[RX_COUNT] DMA_DATA;
static uint8_t tx[FRAME_BYTES] DMA_DATA;
#if GATEWAY_D1_PROBE
extern volatile uint32_t gateway_d1_probe_forge_slot, gateway_d1_probe_bad_tx, gateway_d1_probe_result;
#endif
/* 0=free, 1=DMA/HAL, 2=linked packet (HAL or lwIP). */
static uint8_t rx_state[RX_COUNT] SHIM_PRIVATE;
/* The SHIM is the sole DMA reader. FrameSlot is ordinary NET-visible SRAM;
 * FreeRTOS queues copy only slot indices, never pointers from NET to SHIM. */
static FrameSlot frame_slots[FRAME_SLOTS];
static StaticQueue_t free_cb __attribute__((section(".gateway_privileged")));
static StaticQueue_t ready_cb __attribute__((section(".gateway_privileged")));
static uint8_t free_storage[FRAME_SLOTS*sizeof(uint8_t)] __attribute__((section(".gateway_privileged")));
static uint8_t ready_storage[FRAME_SLOTS*sizeof(FrameReady)] __attribute__((section(".gateway_privileged")));
static QueueHandle_t shim_free_slots SHIM_PRIVATE, shim_ready_frames SHIM_PRIVATE;
static QueueHandle_t net_free_slots, net_ready_frames;
static StaticQueue_t tx_request_cb SHIM_PRIVATE, tx_reply_cb SHIM_PRIVATE;
static uint8_t tx_request_storage[sizeof(TxRequest)] SHIM_PRIVATE;
static uint8_t tx_reply_storage[sizeof(uint8_t)] SHIM_PRIVATE;
static QueueHandle_t shim_tx_requests SHIM_PRIVATE, shim_tx_replies SHIM_PRIVATE;
static QueueHandle_t net_tx_requests, net_tx_replies;
static TxRequest net_tx_request;
static TxRequest shim_tx_request SHIM_PRIVATE;
static osSemaphoreId_t rx_sem SHIM_PRIVATE, tx_sem SHIM_PRIVATE;
static osMutexId_t driver_mutex SHIM_PRIVATE;
static lan8742_Object_t phy SHIM_PRIVATE;
static struct netif *net_interface;
osThreadId_t gateway_eth_task, gateway_link_task;
volatile uint32_t gateway_link_up, gateway_link_epoch;
volatile uint32_t gateway_rx_packets, gateway_tx_packets, gateway_rx_drops, gateway_tx_errors;
static volatile uint32_t need_reset SHIM_PRIVATE;
static uint32_t rx_tokens SHIM_PRIVATE;
static TickType_t rx_last_refill SHIM_PRIVATE;
static _Alignas(8) StackType_t input_stack[4096/4] SHIM_PRIVATE;
static _Alignas(8) StackType_t link_stack[3072/4] SHIM_PRIVATE;
static StackType_t tx_stack[3072/4] SHIM_PRIVATE __attribute__((aligned(4096)));
static StackType_t net_input_stack[4096/4] __attribute__((aligned(4096)));
static StaticTask_t input_tcb SHIM_PRIVATE, link_tcb SHIM_PRIVATE;
static StaticTask_t net_input_tcb SHIM_PRIVATE;
static StaticTask_t tx_tcb SHIM_PRIVATE;
static TaskHandle_t net_input_task SHIM_PRIVATE;
extern void gateway_sys_grant_net_input(TaskHandle_t task);
static StaticSemaphore_t mutex_cb SHIM_PRIVATE, rx_cb SHIM_PRIVATE, tx_cb SHIM_PRIVATE;
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
    /* The final pbuf release owns this slot. A byte store is atomic on M7;
     * the privileged allocator protects its scan separately. This callback
     * can run in the unprivileged network task, which cannot enter a kernel
     * critical section directly under MPU wrappers v2. */
    __atomic_store_n(&rx_state[i],0,__ATOMIC_RELEASE);
    (void)osSemaphoreRelease(rx_sem);
}
void HAL_ETH_RxAllocateCallback(uint8_t **buffer)
{
    *buffer=NULL;
    taskENTER_CRITICAL();
    for(unsigned i=0;i<RX_COUNT;++i) if(!__atomic_load_n(&rx_state[i],__ATOMIC_ACQUIRE)) {
        __atomic_store_n(&rx_state[i],1,__ATOMIC_RELEASE); rx[i].custom.custom_free_function=rx_free;
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
    __atomic_store_n(&rx_state[b-rx],2,__ATOMIC_RELEASE);
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
#if GATEWAY_R4_CONTROL
static volatile uint32_t eth_isr_max_cycles SHIM_PRIVATE;
static volatile uint32_t eth_isr_count SHIM_PRIVATE;
void gateway_d1_eth_isr_reset(void)
{
    eth_isr_max_cycles=0U;
    eth_isr_count=0U;
}
uint32_t gateway_d1_eth_isr_max(void) { return eth_isr_max_cycles; }
uint32_t gateway_d1_eth_isr_count(void) { return eth_isr_count; }
#endif
void ETH_IRQHandler(void)
{
#if GATEWAY_R4_CONTROL
    uint32_t entered=DWT->CYCCNT;
#endif
    HAL_ETH_IRQHandler(&heth);
#if GATEWAY_R4_CONTROL
    uint32_t spent=DWT->CYCCNT-entered;
    if(spent>eth_isr_max_cycles) eth_isr_max_cycles=spent;
    ++eth_isr_count;
#endif
}
/* driver_mutex held; hardware reset definitively ends all outstanding DMA. */
static bool reset_mac(void)
{
    HAL_NVIC_DisableIRQ(ETH_IRQn);
    __HAL_RCC_ETHMAC_FORCE_RESET(); __DSB(); __HAL_RCC_ETHMAC_RELEASE_RESET(); __DSB();
    if(heth.RxDescList.pRxStart) pbuf_free(heth.RxDescList.pRxStart);
    taskENTER_CRITICAL();
    for(unsigned i=0;i<RX_COUNT;++i) if(__atomic_load_n(&rx_state[i],__ATOMIC_ACQUIRE)==1)
        __atomic_store_n(&rx_state[i],0,__ATOMIC_RELEASE);
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
    if(p->tot_len==0U || p->tot_len>sizeof(net_tx_request.bytes)) return ERR_IF;
#if GATEWAY_D1_PROBE == 15
    if(gateway_d1_probe_bad_tx==1U) {
        /* NET asks the SHIM to transmit an overlong frame. */
        gateway_d1_probe_bad_tx=2U; net_tx_request.length=0xFFFFU;
        uint8_t bad_ok=0xEEU; BaseType_t sent=xQueueSend(net_tx_requests,&net_tx_request,pdMS_TO_TICKS(250));
        if(sent==pdPASS) (void)xQueueReceive(net_tx_replies,&bad_ok,pdMS_TO_TICKS(500));
        gateway_d1_probe_result=((uint32_t)(sent==pdPASS)<<8)|bad_ok;   /* logged by the NET HTTP task */
    }
#endif
    net_tx_request.length=p->tot_len;
    if(pbuf_copy_partial(p,net_tx_request.bytes,p->tot_len,0)!=p->tot_len ||
       xQueueSend(net_tx_requests,&net_tx_request,pdMS_TO_TICKS(250))!=pdPASS)
        return ERR_IF;
    uint8_t ok=0;
    if(xQueueReceive(net_tx_replies,&ok,pdMS_TO_TICKS(500))!=pdPASS) return ERR_IF;
    return ok?ERR_OK:ERR_IF;
}
static uint8_t transmit_frame(const TxRequest *request)
{
    if(request->length==0U || request->length>sizeof(tx) ||
       osMutexAcquire(driver_mutex,250)!=osOK) return 0;
    err_t result=ERR_IF;
    if(gateway_link_up && !need_reset) {
        while(osSemaphoreAcquire(tx_sem,0)==osOK) { }
        memcpy(tx,request->bytes,request->length);
        ETH_BufferTypeDef buffer={.buffer=tx,.len=request->length,.next=NULL};
        TxConfig.Length=request->length; TxConfig.TxBuffer=&buffer; TxConfig.pData=tx;
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
    (void)osMutexRelease(driver_mutex); return result==ERR_OK;
}
static void tx_thread(void *arg)
{
    (void)arg;
    for(;;) {
        if(xQueueReceive(shim_tx_requests,&shim_tx_request,portMAX_DELAY)!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
        uint8_t ok=transmit_frame(&shim_tx_request);
        if(xQueueSend(shim_tx_replies,&ok,pdMS_TO_TICKS(500))!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
    }
}
static void input_thread(void *arg)
{
    (void)arg;
    rx_tokens=64U;
    rx_last_refill=xTaskGetTickCount();
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
#if GATEWAY_D1_TOKEN_BUCKET
            /* At most 64 queued frames in a burst, then two per 1 ms tick.
             * Drop before copying into NET SRAM; bounded integer arithmetic
             * avoids an attacker-controlled overflow after long idle time. */
            TickType_t now=xTaskGetTickCount();
            TickType_t elapsed=now-rx_last_refill;
            if(elapsed) {
                rx_tokens=elapsed>=32U?64U:
                    rx_tokens+2U*elapsed>64U?64U:rx_tokens+2U*elapsed;
                rx_last_refill=now;
            }
            if(rx_tokens==0U) {
                ++gateway_rx_drops;
                pbuf_free(p);
                continue;
            }
            --rx_tokens;
#endif
            uint8_t slot;
            uint16_t length=p->tot_len;
            if(length==0U || length>FRAME_BYTES ||
               xQueueReceive(shim_free_slots,&slot,0)!=pdPASS) {
                ++gateway_rx_drops;
                pbuf_free(p);
                continue;
            }
            configASSERT(slot<FRAME_SLOTS);
            uint16_t copied=pbuf_copy_partial(p,frame_slots[slot].bytes,length,0);
            pbuf_free(p);
            FrameReady ready={slot,length};
            if(copied!=length || xQueueSend(shim_ready_frames,&ready,0)!=pdPASS) {
                ++gateway_rx_drops;
                configASSERT(xQueueSend(shim_free_slots,&slot,0)==pdPASS);
            }
        }
        (void)osDelay(1);
    }
}
#if GATEWAY_D1_PROBE
void *gateway_d1_probe_dma_address(void) { return (void *)tx; }
#endif
static void link_up_callback(void *arg) { netif_set_link_up((struct netif *)arg); }
static void link_down_callback(void *arg) { netif_set_link_down((struct netif *)arg); }
static void net_input_thread(void *arg)
{
    (void)arg;
    uint32_t observed_epoch=0;
    /* This is unprivileged NET logic. The SHIM copies and validates frame
     * lengths before publishing a slot; NET allocates its own lwIP pbuf. */
    for(;;) {
        FrameReady ready;
        if(observed_epoch!=gateway_link_epoch) {
            observed_epoch=gateway_link_epoch;
            (void)tcpip_callback(gateway_link_up?link_up_callback:link_down_callback,
                                 net_interface);
        }
        if(xQueueReceive(net_ready_frames,&ready,pdMS_TO_TICKS(100))!=pdPASS)
            continue;
        if(ready.slot>=FRAME_SLOTS || ready.length==0U || ready.length>FRAME_BYTES)
            gateway_panic(GATEWAY_FAULT_ASSERT);
        struct pbuf *copy=pbuf_alloc(PBUF_RAW,ready.length,PBUF_POOL);
        if(!copy || pbuf_take(copy,frame_slots[ready.slot].bytes,ready.length)!=ERR_OK) {
            ++gateway_rx_drops;
            if(copy) pbuf_free(copy);
        } else if(net_interface->input(copy,net_interface)!=ERR_OK) {
            ++gateway_rx_drops;
            pbuf_free(copy);
        }
#if GATEWAY_D1_PROBE == 14
        if(gateway_d1_probe_forge_slot==1U) {   /* set only by the once-per-boot NET probe */
            /* Return an out-of-range index instead of the slot just consumed. */
            gateway_d1_probe_forge_slot=2U; ready.slot=200U;
        }
#endif
        if(xQueueSend(net_free_slots,&ready.slot,0)!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
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
            gateway_log("[ETH] link=%s phy=%ld epoch=%lu\n",active?"UP":"DOWN",(long)link,(unsigned long)gateway_link_epoch);
        }
        (void)osDelay(250);
    }
}
err_t gateway_ethernet_init(struct netif *n)
{
    net_interface=n;
    memset(rx,0,sizeof(rx)); memset(tx,0,sizeof(tx)); memset(rx_state,0,sizeof(rx_state));
    const osMutexAttr_t ma={.attr_bits=osMutexPrioInherit,.cb_mem=&mutex_cb,.cb_size=sizeof(mutex_cb)};
    const osSemaphoreAttr_t ra={.cb_mem=&rx_cb,.cb_size=sizeof(rx_cb)}, ta={.cb_mem=&tx_cb,.cb_size=sizeof(tx_cb)};
    driver_mutex=osMutexNew(&ma); rx_sem=osSemaphoreNew(1,0,&ra); tx_sem=osSemaphoreNew(1,0,&ta);
    if(!driver_mutex || !rx_sem || !tx_sem) return ERR_MEM;
    shim_free_slots=xQueueCreateStatic(FRAME_SLOTS,sizeof(uint8_t),free_storage,&free_cb);
    shim_ready_frames=xQueueCreateStatic(FRAME_SLOTS,sizeof(FrameReady),ready_storage,&ready_cb);
    shim_tx_requests=xQueueCreateStatic(1,sizeof(TxRequest),tx_request_storage,&tx_request_cb);
    shim_tx_replies=xQueueCreateStatic(1,sizeof(uint8_t),tx_reply_storage,&tx_reply_cb);
    if(!shim_free_slots || !shim_ready_frames || !shim_tx_requests || !shim_tx_replies)
        return ERR_MEM;
    net_free_slots=shim_free_slots; net_ready_frames=shim_ready_frames;
    net_tx_requests=shim_tx_requests; net_tx_replies=shim_tx_replies;
    for(uint8_t i=0;i<FRAME_SLOTS;++i)
        if(xQueueSend(shim_free_slots,&i,0)!=pdPASS) return ERR_MEM;
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
    /* Only the two SHIM tasks touch HAL/PHY and the DMA bank. */
    gateway_eth_task=(osThreadId_t)xTaskCreateStatic(input_thread,"ETH input",
        sizeof(input_stack)/sizeof(StackType_t),NULL,
        (UBaseType_t)osPriorityRealtime|portPRIVILEGE_BIT,input_stack,&input_tcb);
    gateway_link_task=(osThreadId_t)xTaskCreateStatic(link_thread,"ETH link",
        sizeof(link_stack)/sizeof(StackType_t),NULL,
        (UBaseType_t)osPriorityRealtime|portPRIVILEGE_BIT,link_stack,&link_tcb);
    TaskHandle_t tx_task=xTaskCreateStatic(tx_thread,"ETH TX",3072/sizeof(StackType_t),NULL,
        (UBaseType_t)osPriorityRealtime|portPRIVILEGE_BIT,tx_stack,&tx_tcb);
    if(!tx_task) return ERR_MEM;
    const TaskParameters_t net_params={
        .pvTaskCode=net_input_thread,.pcName="NET input",.usStackDepth=4096/sizeof(StackType_t),
        .pvParameters=NULL,.uxPriority=(UBaseType_t)osPriorityBelowNormal,
        .puxStackBuffer=net_input_stack,
        .xRegions={
            {(void *)0x20000000UL,512U*1024U,
                portMPU_REGION_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                portMPU_REGION_CACHEABLE_BUFFERABLE|(0xE0UL<<8)},
            {(void *)0x20020000UL,16U*1024U,
                portMPU_REGION_PRIVILEGED_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                portMPU_REGION_CACHEABLE_BUFFERABLE},
            GATEWAY_ITCM_SHARED_REGION},.pxTaskBuffer=&net_input_tcb};
    if(xTaskCreateRestrictedStatic(&net_params,&net_input_task)!=pdPASS) net_input_task=NULL;
    if(!net_input_task) return ERR_MEM;
    vGrantAccessToQueue(net_input_task,shim_ready_frames);
    vGrantAccessToQueue(net_input_task,shim_free_slots);
    gateway_sys_grant_net_input(net_input_task);
    vGrantAccessToQueue((TaskHandle_t)gateway_tcpip_task,shim_tx_requests);
    vGrantAccessToQueue((TaskHandle_t)gateway_tcpip_task,shim_tx_replies);
    vTaskPrioritySet(net_input_task,(UBaseType_t)osPriorityNormal);
    return gateway_eth_task && gateway_link_task?ERR_OK:ERR_MEM;
}
