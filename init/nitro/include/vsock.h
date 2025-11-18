// SPDX-License-Identifier: Apache-2.0

#ifndef _KRUN_NITRO_INIT_VSOCK_H
#define _KRUN_NITRO_INIT_VSOCK_H

#include <stddef.h>
#include <stdint.h>

int vsock_hypervisor_signal();
int vsock_rcv(int, void **, uint32_t *);
int vsock_char_list_build(int, char ***);

#endif // _KRUN_NITRO_INIT_VSOCK_H
