#include "gateway_network.h"
#include "gateway_http.h"
#include "gateway_r4_boundary.h"
#include "gateway_audit.h"
#include "../Web/dashboard_html.h"
_Static_assert(sizeof(gateway_dashboard)<=16384 && sizeof(gateway_dashboard_js)<=16384, "static asset bound");
#include "gateway_platform.h"
#include "gateway_log.h"
#include "paper_experiment.h"
#if GATEWAY_PAPER_CONTROL
#include "paper_control.h"
#endif
#if GATEWAY_PAPER_ALLOC
#include "paper_alloc.h"
#endif
#include "ethernetif.h"
#include "main.h"
#include "lwip/tcpip.h"
#include "lwip/netifapi.h"
#include "lwip/api.h"
#include "lwip/stats.h"
#include "lwip/memp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include <stdio.h>
#include <string.h>
static GatewayContext gateway_network_context;
extern osThreadId_t gateway_tcpip_task;
static struct netif network;
static GatewayHttp http;
static volatile uint32_t ready, requests, rx_failures;
static uint32_t heap_used, heap_peak, heap_errors;
static volatile int last_status, last_send;
#if GATEWAY_R4_TRACE_NET
static volatile uint32_t network_phase, accept_count, close_count, delete_count;
static volatile uint32_t close_errors, delete_errors, pcb_used, pcb_peak, pcb_errors;
static volatile int last_accept, last_close, last_delete;
#endif
#if GATEWAY_PAPER_CONTROL
static uint32_t request_cycles, request_calls;
#endif
#if GATEWAY_PAPER_ALLOC
static volatile uint32_t decision_allocations;
static uint32_t decision_allocations_total, decision_allocations_checked;
#endif
static void tcp_ready(void *sem) { (void)osSemaphoreRelease(sem); }
static void sample_heap(void *unused)
{
    (void)unused;
    /* This callback executes on the sole lwIP owner thread. A 32-bit
     * diagnostic snapshot does not require a privileged critical section. */
    heap_used=lwip_stats.mem.used; heap_peak=lwip_stats.mem.max; heap_errors=lwip_stats.mem.err;
#if GATEWAY_R4_TRACE_NET
    if(lwip_stats.memp[MEMP_TCP_PCB]) {
        pcb_used=lwip_stats.memp[MEMP_TCP_PCB]->used;
        pcb_peak=lwip_stats.memp[MEMP_TCP_PCB]->max;
        pcb_errors=lwip_stats.memp[MEMP_TCP_PCB]->err;
    }
#endif
}
osSemaphoreId_t gateway_tcpip_boot_sem;
static void gateway_tcpip_drop_privilege(void *sem)
{
    vPortSwitchToUserMode();
    (void)osSemaphoreRelease((osSemaphoreId_t)sem);
}
void gateway_network_mpu(void)
{
    MPU_Region_InitTypeDef r={0};
    HAL_MPU_Disable();
    r.Enable=MPU_REGION_ENABLE; r.Number=MPU_REGION_NUMBER1;
    r.BaseAddress=0x20070000; r.Size=MPU_REGION_SIZE_64KB;
    r.AccessPermission=MPU_REGION_FULL_ACCESS; r.DisableExec=MPU_INSTRUCTION_ACCESS_DISABLE;
    r.TypeExtField=MPU_TEX_LEVEL1; /* Normal, non-cacheable payload RAM. */
    HAL_MPU_ConfigRegion(&r);
    r.Number=MPU_REGION_NUMBER2; r.Size=MPU_REGION_SIZE_1KB;
    r.TypeExtField=MPU_TEX_LEVEL0; r.IsBufferable=MPU_ACCESS_BUFFERABLE;
    r.IsShareable=MPU_ACCESS_SHAREABLE; /* Device descriptors. */
    HAL_MPU_ConfigRegion(&r);
    HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);
}
void gateway_network_diagnostics(void)
{
    if(!ready) return;
    (void)tcpip_try_callback(sample_heap,NULL);
    uint32_t t=(uint32_t)uxTaskGetStackHighWaterMark(gateway_tcpip_task)*sizeof(StackType_t);
    uint32_t e=(uint32_t)uxTaskGetStackHighWaterMark(gateway_eth_task)*sizeof(StackType_t);
    uint32_t l=(uint32_t)uxTaskGetStackHighWaterMark(gateway_link_task)*sizeof(StackType_t);
    uint32_t used,peak,errors;
    taskENTER_CRITICAL(); used=heap_used; peak=heap_peak; errors=heap_errors; taskEXIT_CRITICAL();
    gateway_log("[NET] link=%lu req=%lu rx=%lu tx=%lu drop=%lu txerr=%lu stack=%lu/%lu/%lu margin=%s lwip=%lu/%lu err=%lu\n",
        (unsigned long)gateway_link_up,(unsigned long)requests,(unsigned long)gateway_rx_packets,
        (unsigned long)gateway_tx_packets,(unsigned long)gateway_rx_drops,(unsigned long)gateway_tx_errors,
        (unsigned long)t,(unsigned long)e,(unsigned long)l,t>=1024 && e>=1024 && l>=512?"OK":"LOW",
        (unsigned long)used,(unsigned long)peak,(unsigned long)errors);
#if GATEWAY_R4_TRACE_NET
    extern volatile uint32_t gateway_d1_mbox_post_failures;
    extern volatile uint32_t gateway_d1_mbox_post_handle;
    extern volatile uint32_t gateway_d1_accept_mbox_handle;
    extern volatile int32_t gateway_d1_accept_get_status;
    extern volatile uint32_t gateway_d1_tcpip_fetch_handle;
    extern volatile int32_t gateway_d1_tcpip_fetch_status;
    extern volatile uint32_t gateway_d1_tcpip_fetch_count;
    extern volatile uint32_t gateway_d1_try_post_failures;
    extern volatile uint32_t gateway_d1_try_post_handle;
    gateway_log("[NETSTATE] phase=%lu accept=%lu close=%lu delete=%lu errors=%lu/%lu last=%d/%d/%d pcb=%lu/%lu err=%lu\n",
        (unsigned long)network_phase,(unsigned long)accept_count,
        (unsigned long)close_count,(unsigned long)delete_count,
        (unsigned long)close_errors,(unsigned long)delete_errors,
        last_accept,last_close,last_delete,(unsigned long)pcb_used,
        (unsigned long)pcb_peak,(unsigned long)pcb_errors);
    gateway_log("[D1MBOX] accept_handle=%lu get_status=%ld post_fail=%lu post_handle=%lu\n",
        (unsigned long)gateway_d1_accept_mbox_handle,
        (long)gateway_d1_accept_get_status,
        (unsigned long)gateway_d1_mbox_post_failures,
        (unsigned long)gateway_d1_mbox_post_handle);
    gateway_log("[D1TCPIP] fetch_handle=%lu status=%ld count=%lu try_fail=%lu try_handle=%lu\n",
        (unsigned long)gateway_d1_tcpip_fetch_handle,
        (long)gateway_d1_tcpip_fetch_status,
        (unsigned long)gateway_d1_tcpip_fetch_count,
        (unsigned long)gateway_d1_try_post_failures,
        (unsigned long)gateway_d1_try_post_handle);
#endif
#if GATEWAY_PAPER_CONTROL
    PaperGateCycles gate=gateway_paper_gate_take();
    uint32_t cycles=request_cycles,calls=request_calls;
    request_cycles=0;request_calls=0;
    gateway_log("[GATECPU] decision_cycles=%lu decision_calls=%lu request_cycles=%lu request_calls=%lu\n",
        (unsigned long)gate.cycles,(unsigned long)gate.calls,
        (unsigned long)cycles,(unsigned long)calls);
#endif
#if GATEWAY_PAPER_ALLOC
    gateway_log("[ALLOC] decision_path_calls=%lu allocations=%lu\n",
        (unsigned long)decision_allocations_checked,
        (unsigned long)decision_allocations_total);
    decision_allocations_checked=0;decision_allocations_total=0;
#endif
    if(t<1024 || e<1024 || l<512) HAL_GPIO_WritePin(LD3_GPIO_Port,LD3_Pin,GPIO_PIN_SET);
}
static void serve(struct netconn *conn)
{
    GatewayContext *c=&gateway_network_context;
    const GatewayR4Reply *decision=NULL;
    GatewayAuditRecord audit={0};
#if GATEWAY_PAPER_ALLOC
    decision_allocations=0;
#endif
    gateway_begin_request(c); gateway_http_init(&http);
    netconn_set_sendtimeout(conn,2000); netconn_set_recvtimeout(conn,250);
    /* Close returns after queuing FIN; lwIP retains and ACKs copied TCP data.
     * Positive linger stalled the netconn caller with no per-request UART. */
    conn->linger=-1;
    uint32_t start=osKernelGetTickCount(),epoch=gateway_link_epoch;
    int status=0;
    while(!status) {
        if(!gateway_link_up || epoch!=gateway_link_epoch) { ++rx_failures; return; }
        if((uint32_t)(osKernelGetTickCount()-start)>=5000) { status=408; break; }
        struct netbuf *buffer=NULL;
        err_t err=netconn_recv(conn,&buffer);
        if(err==ERR_TIMEOUT) continue;
        if(err!=ERR_OK) { if(buffer) netbuf_delete(buffer); ++rx_failures; return; }
        for(struct pbuf *p=buffer->p;p;p=p->next) {
            if(status==1 && p->len) { status=400; break; }
            status=gateway_http_feed(&http,c,p->payload,p->len);
            if(status>1) break;
        }
        netbuf_delete(buffer);
    }
    if(status==1) {
#if GATEWAY_PAPER_ALLOC
        paper_alloc_begin();
#endif
#if GATEWAY_PAPER_CONTROL
        uint32_t start_cycles=DWT->CYCCNT;
#endif
        decision=gateway_r4_submit(&http);
        status=decision?decision->status:500;
#if GATEWAY_PAPER_CONTROL
        request_cycles+=DWT->CYCCNT-start_cycles;++request_calls;
#endif
#if GATEWAY_PAPER_ALLOC
        PaperAllocCounts alloc=paper_alloc_end();
        decision_allocations=alloc.freertos+alloc.libc+alloc.newlib+alloc.lwip_heap+alloc.lwip_pool;
        decision_allocations_total+=decision_allocations;
        ++decision_allocations_checked;
#endif
    }
    if(decision) audit=decision->audit;
    const char *body="{\"status\":\"error\"}";
    size_t length=strlen(body);
    if(decision && decision->gate_len>=GATE_RESPONSE_HEADER_SIZE &&
       (status==200 || status==400 || status==401 || status==403 || status==429)) {
        const GateResponse *r=(const GateResponse *)decision->gate;
        if(r->body_len==decision->gate_len-GATE_RESPONSE_HEADER_SIZE) { body=(const char *)r->body; length=r->body_len; }
    }
    const char *type="application/json";
    if(status==200 && decision && decision->dashboard) { body=(const char *)gateway_dashboard; length=sizeof(gateway_dashboard); type="text/html; charset=utf-8"; }
    if(status==200 && decision && decision->script) { body=(const char *)gateway_dashboard_js; length=sizeof(gateway_dashboard_js); type="application/javascript; charset=utf-8"; }
    if(status==200 && decision && decision->demo) type="text/plain; charset=utf-8";
    /* Raw input is no longer owned by extraction. Small responses are coalesced;
     * larger immutable flash assets stream after the header using the same
     * absolute send deadline. No large response allocation is required. */
    char *response=(char *)http.raw;
    int n=gateway_http_typed_header(response,sizeof(http.raw),status,length,type);
    if(n>=2) {
        int extra=snprintf(response+n-2,sizeof(http.raw)-(size_t)(n-2),
            "X-PG-Audit-Id: %lu\r\nX-PG-Audit-Accepts: %lu\r\nX-PG-Audit-Effects: %lu\r\nX-PG-Audit-Violations: %lu\r\n"
#if GATEWAY_PAPER_ALLOC
            "X-PG-Decision-Allocations: %lu\r\n"
#endif
            "\r\n",
            (unsigned long)audit.request_id,(unsigned long)audit.acceptances,
            (unsigned long)audit.effects,(unsigned long)audit.violations
#if GATEWAY_PAPER_ALLOC
            ,(unsigned long)decision_allocations
#endif
            );
        n=extra>=0 && (size_t)extra<sizeof(http.raw)-(size_t)(n-2)?n-2+extra:-1;
    }
    if(n>0 && gateway_link_up && epoch==gateway_link_epoch) {
        const char *parts[2]={response,body}; size_t sizes[2]={(size_t)n,length}; unsigned count=2;
        if(length<=sizeof(http.raw)-(size_t)n) {
            memcpy(response+n,body,length); sizes[0]+=length; count=1;
        }
        uint32_t send_start=osKernelGetTickCount(); last_send=ERR_OK;
        for(unsigned part=0;part<count && last_send==ERR_OK;++part) {
            size_t offset=0;
            while(offset<sizes[part]) {
                uint32_t elapsed=osKernelGetTickCount(); elapsed-=send_start;
                if(elapsed>=2000 || !gateway_link_up || epoch!=gateway_link_epoch) { last_send=ERR_TIMEOUT; break; }
                netconn_set_sendtimeout(conn,2000-elapsed);
                size_t written=0;
                last_send=netconn_write_partly(conn,parts[part]+offset,sizes[part]-offset,NETCONN_COPY,&written);
                if(last_send!=ERR_OK) break;
                if(!written) { last_send=ERR_TIMEOUT; break; }
                offset+=written;
            }
        }
    }
    last_status=status;
#if !GATEWAY_R4_NO_HTTP_LOG
    gateway_log("[HTTP] status=%d bytes=%lu header=%d send=%d\n",status,(unsigned long)http.used,n,last_send);
#endif
    ++requests;
}
void gateway_network_run(void)
{
    gateway_init(&gateway_network_context);
    gateway_r4_boundary_start();
    osSemaphoreId_t sem=osSemaphoreNew(1,0,NULL);
    if(!sem) gateway_panic(GATEWAY_FAULT_ALLOC);
    gateway_tcpip_boot_sem=sem;
    tcpip_init(tcp_ready,sem);
    if(osSemaphoreAcquire(sem,10000)!=osOK) gateway_panic(GATEWAY_FAULT_STARTUP);
    (void)osSemaphoreDelete(sem);
    ip4_addr_t ip,mask,gw;
    IP4_ADDR(&ip,192,168,40,128); IP4_ADDR(&mask,255,255,255,0); IP4_ADDR(&gw,0,0,0,0);
    if(netifapi_netif_add(&network,&ip,&mask,&gw,NULL,gateway_ethernet_init,tcpip_input)!=ERR_OK ||
        netifapi_netif_set_default(&network)!=ERR_OK || netifapi_netif_set_up(&network)!=ERR_OK)
        gateway_panic(GATEWAY_FAULT_STARTUP);
    struct netconn *listener=netconn_new(NETCONN_TCP);
    if(!listener || netconn_bind(listener,IP_ADDR_ANY,80)!=ERR_OK || netconn_listen_with_backlog(listener,1)!=ERR_OK)
        gateway_panic(GATEWAY_FAULT_STARTUP);
    netconn_set_recvtimeout(listener,250);
    osSemaphoreId_t drop_sem=osSemaphoreNew(1,0,NULL);
    if(!drop_sem) gateway_panic(GATEWAY_FAULT_ALLOC);
    vGrantAccessToQueue((TaskHandle_t)gateway_tcpip_task,(QueueHandle_t)drop_sem);
    if(tcpip_callback(gateway_tcpip_drop_privilege,drop_sem)!=ERR_OK ||
       osSemaphoreAcquire(drop_sem,5000)!=osOK)
        gateway_panic(GATEWAY_FAULT_STARTUP);
    (void)osSemaphoreDelete(drop_sem);
    ready=1;
    gateway_log("[HTTP] READY 192.168.40.128/24:80 lab_bearer=%u RAM policy; no TLS\n",GATEWAY_LAB_AUTH);
    gateway_r4_network_drop_privilege();
    for(;;) {
        struct netconn *conn=NULL;
#if GATEWAY_R4_TRACE_NET
        network_phase=1;
#endif
        err_t err=netconn_accept(listener,&conn);
        if(err!=ERR_OK) {
#if GATEWAY_R4_TRACE_NET
            last_accept=err;network_phase=5;
#endif
            (void)osDelay(10); continue;
        }
#if GATEWAY_R4_TRACE_NET
        ++accept_count;network_phase=2;
#endif
        serve(conn);
#if GATEWAY_R4_TRACE_NET
        network_phase=3;
#endif
        err_t closed=netconn_close(conn);
#if !GATEWAY_R4_TRACE_NET
        (void)closed;
#endif
#if GATEWAY_R4_TRACE_NET
        last_close=closed;++close_count;if(closed!=ERR_OK) ++close_errors;
        network_phase=4;
#endif
        err_t deleted=netconn_delete(conn);
#if !GATEWAY_R4_TRACE_NET
        (void)deleted;
#endif
#if GATEWAY_R4_TRACE_NET
        last_delete=deleted;++delete_count;if(deleted!=ERR_OK) ++delete_errors;
#endif
    }
}
