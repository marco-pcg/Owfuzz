/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../protocol.h"
#include <string.h>
/* Experimental Basic Multi-Link element corpus, not a complete MLO session.
 * Layout reference: hostapd src/ap/ieee802_11_eht.c and ieee802_11_defs.h.
 * Common info: length (including itself), MLD MAC. Control type = Basic (0).
 */
static int ml_probe_response(struct ow_context *c, struct ow_packet *p)
{
    memset(p->data, 0, 50);
    p->data[0] = 0x50; /* Probe response, 24-byte management header */
    memcpy(p->data + 4, c->destination, 6);
    memcpy(p->data + 10, c->source, 6);
    memcpy(p->data + 16, c->bssid, 6);
    p->data[22] = (uint8_t)((c->iteration & 15) << 4);
    p->data[23] = (uint8_t)((c->iteration >> 4) & 255);
    p->data[32] = 100; /* beacon interval, little endian */
    p->data[34] = 1; /* ESS capability */
    p->data[36] = 0; p->data[37] = 0; /* empty SSID */
    p->data[38] = 255; p->data[39] = 10; /* extension IE and payload length */
    p->data[40] = 107; /* Multi-Link extension ID */
    p->data[41] = 0; p->data[42] = 0; /* Basic control, no optional fields */
    p->data[43] = 7; /* common info length includes length octet */
    memcpy(p->data + 44, c->source, 6);
    p->len = 50;
    return 0;
}
static int ml_bad_length(struct ow_context *c, struct ow_packet *p)
{ ml_probe_response(c, p); p->data[43] = 255; return 0; }
static const struct ow_frame frames[] = {
    {1, "ml_probe_response", ml_probe_response},
    {2, "ml_invalid_common_length", ml_bad_length}
};
const struct ow_family ow_module_wifi_be = {"802.11be", 105, frames, sizeof(frames)/sizeof(frames[0])};
