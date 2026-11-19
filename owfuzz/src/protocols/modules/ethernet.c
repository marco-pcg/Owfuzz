/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../protocol.h"
#include <string.h>
static int arp_request(struct ow_context *c, struct ow_packet *p)
{
    /* Ethernet/IPv4 ARP request, padded to the 60-byte frame minimum (no FCS). */
    static const uint8_t arp[] = {0,1, 8,0, 6,4, 0,1};
    memset(p->data, 0, 60);
    memcpy(p->data, c->destination, 6);
    memcpy(p->data + 6, c->source, 6);
    p->data[12] = 8; p->data[13] = 6;
    memcpy(p->data + 14, arp, sizeof(arp));
    memcpy(p->data + 22, c->source, 6);
    p->data[28] = 192; p->data[29] = 0; p->data[30] = 2; p->data[31] = 1;
    p->data[38] = 192; p->data[39] = 0; p->data[40] = 2; p->data[41] = 2;
    p->len = 60;
    return 0;
}
static const struct ow_frame frames[] = {{1, "arp_request", arp_request}};
const struct ow_family ow_module_ethernet = {"ethernet", 1, frames, sizeof(frames)/sizeof(frames[0])};
