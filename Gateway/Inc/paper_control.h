#ifndef PAPER_CONTROL_H
#define PAPER_CONTROL_H
#include <stdint.h>
typedef struct { uint32_t cycles, calls; } PaperGateCycles;
PaperGateCycles gateway_paper_gate_take(void);
#endif
