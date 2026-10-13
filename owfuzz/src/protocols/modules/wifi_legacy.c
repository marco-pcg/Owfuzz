/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../protocol.h"
#include "../../frames/legacy_registry.h"
static struct ow_frame frames[256];
static int build(struct ow_context *c, struct ow_packet *p)
{
    struct ether_addr bssid, source, dest;
    struct packet received = {0}, result;
    const struct ow_wifi_frame *frame = c->frame_id <= 255 ? ow_wifi_find_id(c->frame_id) : NULL;
    if (!frame || c->received_len > sizeof(received.data)) return -1;
    memcpy(bssid.ether_addr_octet, c->bssid, 6);
    memcpy(source.ether_addr_octet, c->source, 6);
    memcpy(dest.ether_addr_octet, c->destination, 6);
    if (c->received_len) {
        if (!c->received) return -1;
        memcpy(received.data, c->received, c->received_len);
        received.len = c->received_len;
    }
    result = frame->build(bssid, source, dest, c->received_len ? &received : NULL);
    if (!result.len || result.len > sizeof(p->data)) return -1;
    memcpy(p->data, result.data, result.len);
    p->len = result.len;
    return 0;
}
struct ow_family ow_module_wifi_legacy = {"802.11", 105, frames, 0};
int ow_prepare_wifi_legacy(void)
{
    size_t i;
    if (ow_wifi_frame_count > 256) return -1;
    for (i=0; i<ow_wifi_frame_count; i++) {
        frames[i].id = ow_wifi_frames[i].id;
        frames[i].name = ow_wifi_frames[i].name;
        frames[i].build = build;
    }
    ow_module_wifi_legacy.count = ow_wifi_frame_count;
    return 0;
}
