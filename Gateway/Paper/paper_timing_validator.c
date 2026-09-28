#include "paper_experiment.h"
#if GATEWAY_PAPER_TIMING
#include <stdbool.h>
#include <stdint.h>
#include "../Generated/Policy/RbacPolicyWrapper.h"
bool paper_timing_validate(uint8_t *bytes)
{
    return RbacPolicyCheckAccessRequest(bytes, 75);
}
#endif
