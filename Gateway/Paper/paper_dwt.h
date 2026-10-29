/* Measurement-only DWT cycle counter enable, shared by the paper timing paths.
 * Cortex-M7 DWT has a software lock: with no debugger attached, writes to
 * DWT->CTRL are ignored until DWT->LAR = 0xC5ACCE55. A debug session unlocks it
 * and the unlock survives a warm reset, so an unlocked-by-debugger board can mask
 * the missing unlock. Sequence: TRCENA, unlock, CYCCNT=0, CYCCNTENA, then verify
 * that CYCCNTENA is set and the counter advances. Failure is loud, never a silent
 * zero distribution. Not part of the gate, mediation or glue code. */
#ifndef PAPER_DWT_H
#define PAPER_DWT_H
#include "main.h"
#include "gateway_log.h"
#include <stdbool.h>

static inline bool paper_dwt_enable(const char *who)
{
    for (unsigned attempt = 0; attempt < 4U; ++attempt) {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->LAR = 0xC5ACCE55UL;
        DWT->CYCCNT = 0U;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
        if ((DWT->CTRL & DWT_CTRL_CYCCNTENA_Msk) != 0U) {
            uint32_t a = DWT->CYCCNT;
            for (volatile unsigned i = 0; i < 64U; ++i) { }
            if (DWT->CYCCNT != a) return true;
        }
    }
    gateway_log("[DWT] FATAL %s: cycle counter does not run (CTRL=0x%08lx LSR=0x%08lx); measurement aborted\n",
                who, (unsigned long)DWT->CTRL, (unsigned long)DWT->LSR);
    return false;
}
#endif
