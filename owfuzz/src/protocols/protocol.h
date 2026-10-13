/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef OW_PROTOCOL_H
#define OW_PROTOCOL_H
#include <stddef.h>
#include <stdint.h>
#define OW_PACKET_CAPACITY 4096
#define OW_MAX_FAMILIES 32
struct ow_packet { uint8_t data[OW_PACKET_CAPACITY]; size_t len; uint32_t linktype; };
struct ow_context {
    uint8_t source[6], destination[6], bssid[6];
    uint64_t iteration;
    uint32_t frame_id;
    uint32_t random_state;
    const uint8_t *received;
    size_t received_len;
    void *user;
};
/* Builders create baseline frames; mutation and delivery are independent strategies. */
typedef int (*ow_builder)(struct ow_context *, struct ow_packet *);
struct ow_frame { uint32_t id; const char *name; ow_builder build; };
struct ow_family {
    const char *name;
    uint32_t linktype; /* PCAP LINKTYPE, never an implicit WiFi assumption */
    const struct ow_frame *frames;
    size_t count;
};
struct ow_registry { const struct ow_family *families[OW_MAX_FAMILIES]; size_t count; };
struct ow_mutator { const char *name; int (*apply)(struct ow_context *, struct ow_packet *); };
struct ow_transport { uint32_t linktype; void *user; int (*send)(void *, const struct ow_packet *); };
int ow_register(struct ow_registry *, const struct ow_family *);
const struct ow_family *ow_find_family(const struct ow_registry *, const char *);
const struct ow_frame *ow_find_frame(const struct ow_family *, const char *);
int ow_generate(const struct ow_family *, const struct ow_frame *, struct ow_context *,
                const struct ow_mutator *, struct ow_packet *);
int ow_deliver(const struct ow_transport *, const struct ow_packet *);
uint32_t ow_random(struct ow_context *);
extern const struct ow_mutator ow_mutators[];
extern const size_t ow_mutator_count;
int ow_register_modules(struct ow_registry *); /* generated from module source files */
int ow_protocol_cli(int argc, char **argv); /* -2 means legacy invocation */
#endif
