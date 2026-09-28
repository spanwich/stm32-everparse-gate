# M6 isolated MPU-port attempt

The primary R1 firmware has `configENABLE_MPU=0`. The HAL configures Ethernet
memory attributes, but does not give FreeRTOS tasks distinct write permissions.
Any task with an arbitrary-write defect can corrupt `GatewayContext`.

An isolated copy under `/tmp/policy-gate-mpu-attempt` substituted the CubeF7
FreeRTOS `ARM_CM7_MPU/r0p1` port, enabled `configENABLE_MPU=1`, and copied the
matching `portable/Common/mpu_wrappers.c`. No MPU experiment was flashed. The
first build (`build-attempt/build.log`) failed with missing `MPU_*` wrappers.
The second (`build-with-wrappers/build.log`) compiled but failed to link because
the existing linker script does not define `__SRAM_segment_start__`,
`__SRAM_segment_end__`, `__FLASH_segment_start__`, `__FLASH_segment_end__`,
`__privileged_functions_end__`, or privileged-data boundaries. Merely defining
those symbols would produce a linkable image, not protected task memory.

The selected FreeRTOS port fixes MPU regions 0–3 as general flash, privileged
flash, privileged RAM, and peripherals; region 4 is the active task stack; only
5–7 are task-configurable. The existing `gateway_network_mpu()` configures
regions 1 and 2 for Ethernet DMA memory before the scheduler, so port startup
would overwrite those settings. Ethernet attributes must be assigned without
clobbering the port's fixed regions.

The primary Debug map has `gateway_network_context` at `0x20002450`, size
`0x229c`; the built control variant has it at `0x20002468`, also size
`0x229c`. The RX descriptor array starts at `0x20070000`, the TX array at
`0x200700a0`, RX payloads occupy `0x20070400`–`0x2007413f`, and TX payloads
`0x20074140`–`0x2007473f`. Ethernet memory is reserved through `0x2007ffff`.
These ranges are disjoint in that linked image. This is an address-layout check, not
proof that all DMA writes are confined to that range under faults.

The policy store, validator input, raw request, application input and response
are fields of the same 8,860-byte `GatewayContext`. The single gateway task
receives network input *and* invokes the verified gate. Thus the current
application cannot be made into the requested unprivileged network/lwIP tasks,
gate-only policy writer, and read-only application receiver by changing MPU
attributes alone. It needs separate gate and network tasks, separate aligned
state objects and a bounded inter-task channel. Until those changes are made,
five meaningful unprivileged fault-injection runs and M2/M3 MPU-overhead runs
cannot be performed. H4 is unsupported by this image and the MPU build attempt.
