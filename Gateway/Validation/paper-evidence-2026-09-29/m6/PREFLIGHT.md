# M6 MPU preflight — no isolation verdict yet

The currently flashed images use `configENABLE_MPU 0`. Every task can write the
global `gateway_test_context`, which contains the policy, security buffer and
application request. The HAL MPU setup in `gateway_network_mpu()` configures
Ethernet memory attributes, not per-task isolation. Current H4 is therefore
unsupported by the primary image.

The vendor FreeRTOS GCC `ARM_CM7_MPU/r0p1` port is present in STM32CubeF7
1.17.4. Its `portmacro.h` reserves regions 0–3 for flash, privileged flash,
privileged RAM and peripherals, region 4 for each task stack, leaving regions
5–7 as three per-task configurable regions. Its `prvSetupMPU()` expects linker
symbols for privileged code/data that the current linker script does not define.
The firmware currently uses MPU regions 1 and 2 for the 64 KiB Ethernet bank and
1 KiB descriptor overlay, so simply switching FreeRTOS ports would collide with
those fixed assignments. This needs a reviewed memory-attribute and linker
redesign before the variant can boot.

The linker reserves general RAM below `0x20070000`; `.eth_desc` begins at
`0x20070000` and `.eth_data` at `0x20070400`. The post-link check verifies the
section and descriptor bounds. That spatial separation does not alone prove
that all programmed DMA buffer addresses remain in the Ethernet bank; driver
descriptor writes and the RX/TX callback paths must be audited and fault
injections still run.

Implementation sequence for the MPU variant:

1. Split the current global context into aligned gate-only policy/validator
   storage, unprivileged network input, and a separate gate-to-application
   channel. Keep startup self-tests out of production-owned buffers.
2. Introduce privileged FreeRTOS wrappers and linker symbols for the vendor MPU
   port, with a region map showing all eight hardware regions for every task.
3. Reconcile Ethernet memory attributes with port regions 0–4 and prove from
   linked addresses and driver configuration that DMA only touches the reserved
   bank.
4. Boot the variant, then run each of the five fault injections separately.
   Record the fault registers and confirm no protected effect before reset or
   stop. A direct call from unprivileged code must be tested explicitly: the MPU
   controls data access, not call targets by itself.
5. Repeat M2 and M3 on the exact MPU ELF and report measured overhead.

No fault injection or FreeRTOS MPU build has been performed yet. Region-budget
feasibility is open; this preflight is a dependency map, not a successful H4 test.
