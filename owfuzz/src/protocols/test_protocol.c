/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int sends;
static int send_packet(void *u, const struct ow_packet *p)
{ (void)u; assert(p->len); sends++; return 0; }
static int empty(struct ow_context *c, struct ow_packet *p) { (void)c; (void)p; return 0; }
static int oversized(struct ow_context *c, struct ow_packet *p)
{ (void)c; p->len = OW_PACKET_CAPACITY+1; return 0; }
int main(void)
{
    struct ow_registry r = {{0},0};
    struct ow_context c = {0}, repeat = {0};
    struct ow_packet p, q;
    const struct ow_family *eth, *be;
    const struct ow_frame *arp, *ml;
    struct ow_transport transport = {1,NULL,send_packet};
    const struct ow_frame invalid_frames[] = {{0,"empty",empty},{1,"oversized",oversized}};
    const struct ow_family invalid = {"invalid",1,invalid_frames,2};
    const struct ow_frame duplicate_frames[] = {{0,"a",empty},{0,"b",empty}};
    const struct ow_family duplicate = {"duplicate",1,duplicate_frames,2};
    size_t i;
    assert(!ow_register_modules(&r));
    eth = ow_find_family(&r,"ethernet"); be = ow_find_family(&r,"802.11be");
    assert(eth && be && eth->linktype==1 && be->linktype==105);
    assert(!ow_find_family(&r,"unknown"));
    assert(ow_register(&r,eth)==-1);
    assert(ow_register(&r,&duplicate)==-1);
    assert(ow_register(NULL,eth)==-1);
    assert(!ow_register(&r,&invalid));
    arp = ow_find_frame(eth,"arp_request"); ml = ow_find_frame(be,"ml_probe_response");
    assert(arp && ml && !ow_find_frame(be,"arp_request"));
    c.source[0] = 2; c.source[5] = 7; memset(c.destination,255,6);
    assert(!ow_generate(eth,arp,&c,&ow_mutators[0],&p));
    assert(p.len==60 && p.data[12]==8 && p.data[13]==6);
    assert(!memcmp(p.data+22,c.source,6));
    assert(!ow_deliver(&transport,&p) && sends==1);
    assert(!ow_generate(be,ml,&c,&ow_mutators[0],&p));
    assert(p.len==50 && p.data[38]==255 && p.data[39]==10 && p.data[40]==107 && p.data[43]==7);
    assert(!memcmp(p.data+44,c.source,6));
    assert(ow_deliver(&transport,&p)==-1 && sends==1);
    assert(ow_generate(eth,ml,&c,&ow_mutators[0],&p)==-1);
    assert(ow_generate(&invalid,&invalid_frames[0],&c,&ow_mutators[0],&p)==-1);
    assert(ow_generate(&invalid,&invalid_frames[1],&c,&ow_mutators[0],&p)==-1);
    ml = ow_find_frame(be,"ml_invalid_common_length");
    assert(!ow_generate(be,ml,&c,&ow_mutators[0],&p) && p.data[43]==255);
    c.random_state = 0; repeat = c;
    for (i=0;i<100;i++) {
        assert(!ow_generate(eth,arp,&c,&ow_mutators[1],&p));
        assert(!ow_generate(eth,arp,&repeat,&ow_mutators[1],&q));
        assert(p.len==q.len && !memcmp(p.data,q.data,p.len));
        assert(c.random_state==repeat.random_state);
    }
    assert(!ow_generate(eth,arp,&c,&ow_mutators[2],&p) && p.len>=1 && p.len<=60);
    puts("Protocol registry, packet bounds, deterministic mutation, and transport isolation passed");
    return 0;
}
