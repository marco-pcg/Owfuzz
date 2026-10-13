/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef OW_LEGACY_REGISTRY_H
#define OW_LEGACY_REGISTRY_H
#include "frame.h"
typedef struct packet (*ow_wifi_builder)(struct ether_addr, struct ether_addr, struct ether_addr, struct packet *);
struct ow_wifi_frame {
    uint8_t id;
    const char *name, *symbol, *label;
    ow_wifi_builder build, baseline;
    void (*save)(void), (*load)(void);
};
extern const struct ow_wifi_frame ow_wifi_frames[];
extern const size_t ow_wifi_frame_count;
const struct ow_wifi_frame *ow_wifi_find_id(uint8_t id);
const struct ow_wifi_frame *ow_wifi_find_name(const char *name);
#endif
