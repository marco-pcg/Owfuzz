/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "protocol.h"
#include <string.h>
int ow_register(struct ow_registry *r, const struct ow_family *f)
{
    size_t i, j;
    if (!r || !f || !f->name || !*f->name || !f->frames || !f->count ||
        !f->linktype || r->count >= OW_MAX_FAMILIES) return -1;
    for (i = 0; i < r->count; i++)
        if (!strcmp(r->families[i]->name, f->name)) return -1;
    for (i = 0; i < f->count; i++) {
        if (!f->frames[i].name || !*f->frames[i].name || !f->frames[i].build) return -1;
        for (j = 0; j < i; j++)
            if (f->frames[i].id == f->frames[j].id ||
                !strcmp(f->frames[i].name, f->frames[j].name)) return -1;
    }
    r->families[r->count++] = f;
    return 0;
}
const struct ow_family *ow_find_family(const struct ow_registry *r, const char *name)
{
    size_t i;
    if (!r || !name) return NULL;
    for (i = 0; i < r->count; i++)
        if (!strcmp(name, r->families[i]->name)) return r->families[i];
    return NULL;
}
const struct ow_frame *ow_find_frame(const struct ow_family *f, const char *name)
{
    size_t i;
    if (!f || !name) return NULL;
    for (i = 0; i < f->count; i++)
        if (!strcmp(name, f->frames[i].name)) return &f->frames[i];
    return NULL;
}
int ow_generate(const struct ow_family *f, const struct ow_frame *frame,
                struct ow_context *c, const struct ow_mutator *m, struct ow_packet *p)
{
    size_t i;
    if (!f || !frame || !c || !p || !m || !m->apply) return -1;
    for (i = 0; i < f->count && frame != &f->frames[i]; i++) {}
    if (i == f->count) return -1;
    memset(p, 0, sizeof(*p));
    p->linktype = f->linktype;
    c->frame_id = frame->id;
    if (frame->build(c, p) || !p->len || p->len > sizeof(p->data) ||
        p->linktype != f->linktype) return -1;
    if (m->apply(c, p) || !p->len || p->len > sizeof(p->data) ||
        p->linktype != f->linktype) return -1;
    return 0;
}
int ow_deliver(const struct ow_transport *t, const struct ow_packet *p)
{
    if (!t || !t->send || !p || !p->len || p->len > sizeof(p->data) ||
        t->linktype != p->linktype) return -1;
    return t->send(t->user, p);
}
uint32_t ow_random(struct ow_context *c)
{
    /* Defined for seed zero too; state belongs to the campaign, not a global. */
    c->random_state = c->random_state * UINT32_C(1664525) + UINT32_C(1013904223);
    return c->random_state;
}
static int identity(struct ow_context *c, struct ow_packet *p) { (void)c; (void)p; return 0; }
static int bitflip(struct ow_context *c, struct ow_packet *p)
{
    size_t pos = ow_random(c) % p->len;
    p->data[pos] ^= (uint8_t)(1u << (ow_random(c) % 8));
    return 0;
}
static int truncate_packet(struct ow_context *c, struct ow_packet *p)
{ p->len = 1 + ow_random(c) % p->len; return 0; }
const struct ow_mutator ow_mutators[] = {
    {"none", identity}, {"bitflip", bitflip}, {"truncate", truncate_packet}
};
const size_t ow_mutator_count = sizeof(ow_mutators) / sizeof(ow_mutators[0]);
