#!/usr/bin/env python3
"""Add NET probes 16-18 (A2 ITCM boundary) to gateway_r4_boundary.c."""
from pathlib import Path
p = Path('/home/iamfo470/stm32-projects/policy_gate/Gateway/Network/gateway_r4_boundary.c')
s = p.read_text()
assert s.count('#if GATEWAY_D1_PROBE >= 1 && GATEWAY_D1_PROBE <= 15') == 2
s = s.replace('#if GATEWAY_D1_PROBE >= 1 && GATEWAY_D1_PROBE <= 15',
              '#if GATEWAY_D1_PROBE >= 1 && GATEWAY_D1_PROBE <= 18')
old = """    default: return;
    }
    PROBE_ESCAPED(id);"""
new = """#if GATEWAY_D1_PROBE >= 16
    /* A2 ITCM boundary (GATEWAY_ITCM images only). */
    case 16: *(volatile uint16_t *)0x00002000UL=0U; break;                 /* write shared ITCM code */
    case 17: { extern char __itcm_priv_start__[];                          /* run privileged ITCM (queue.c) */
               void (*jump)(void)=(void (*)(void))((uintptr_t)__itcm_priv_start__|1U);
               jump(); break; }
    case 18: { volatile uint32_t v=*(volatile const uint32_t *)0x00000000UL; /* read ITCM null guard */
               PROBE_LOG("[PROBE] id=18 read=%lu\\n",(unsigned long)v); break; }
#endif
    default: return;
    }
    PROBE_ESCAPED(id);"""
assert s.count(old) == 1
s = s.replace(old, new)
old = "#if GATEWAY_D1_PROBE\n/* NET-visible probe plumbing, present only in probe images. */"
assert s.count(old) == 1
s = s.replace(old, "#if GATEWAY_D1_PROBE >= 16 && !GATEWAY_ITCM\n"
              "#error \"probes 16-18 test the A2 ITCM regions; build with GATEWAY_ITCM = 1\"\n#endif\n" + old)
p.write_text(s)
print('applied')
