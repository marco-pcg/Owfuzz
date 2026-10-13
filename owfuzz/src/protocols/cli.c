/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#ifndef OW_STANDALONE
#include "../../linux_wifi/trans/osdep/osdep.h"
#include "../frames/80211_packet_common.h"
extern fuzzing_option fuzzing_opt;
#endif
static void usage(void)
{
    puts("Protocol campaigns: --list-protocols | --protocol-help\n"
         "  --protocol FAMILY --frame NAME [--strategy none|bitflip|truncate]\n"
         "  [--seed UINT32] [--count N] [--output PATH.pcap]\n"
         "  [--source MAC] [--destination MAC] [--bssid MAC]\n"
         "  [--interface NAME --channel N] (live WiFi; full build only)\n"
         "Defaults: seed 1, count 1, strategy none, PCAP to stdout.\n"
         "This campaign path is separate from legacy interactive WiFi modes.");
}
static int number(const char *s, uint32_t *out)
{
    char *end;
    unsigned long long value;
    if (!s || !*s || *s == '-' || *s == '+') return -1;
    errno = 0;
    value = strtoull(s, &end, 10);
    if (errno || *end || value > UINT32_MAX) return -1;
    *out = (uint32_t)value;
    return 0;
}
static int mac(const char *s, uint8_t out[6])
{
    unsigned i;
    if (strlen(s) != 17) return -1;
    for (i = 0; i < 6; i++) {
        char byte[3] = {s[i*3], s[i*3+1], 0}, *end;
        unsigned long value;
        if ((i < 5 && s[i*3+2] != ':') ||
            !strchr("0123456789abcdefABCDEF", byte[0]) ||
            !strchr("0123456789abcdefABCDEF", byte[1])) return -1;
        value = strtoul(byte, &end, 16);
        if (*end) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}
static int write32(FILE *fp, uint32_t value)
{
    uint8_t b[4] = {(uint8_t)value, (uint8_t)(value >> 8),
                    (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    return fwrite(b, 1, 4, fp) == 4 ? 0 : -1;
}
static int pcap_header(FILE *fp, uint32_t linktype)
{
    const uint8_t version[] = {2,0,4,0};
    if (write32(fp, UINT32_C(0xa1b2c3d4)) || fwrite(version,1,4,fp) != 4 ||
        write32(fp,0) || write32(fp,0) || write32(fp,OW_PACKET_CAPACITY) || write32(fp,linktype)) return -1;
    return 0;
}
struct pcap_sink { FILE *fp; uint64_t sequence; };
static int pcap_send(void *user, const struct ow_packet *p)
{
    struct pcap_sink *sink = user;
    /* Synthetic timestamps keep byte-for-byte seeded corpus comparisons stable. */
    uint64_t n = sink->sequence++;
    if (write32(sink->fp,(uint32_t)(n/1000000)) || write32(sink->fp,(uint32_t)(n%1000000)) ||
        write32(sink->fp,(uint32_t)p->len) || write32(sink->fp,(uint32_t)p->len) ||
        fwrite(p->data,1,p->len,sink->fp) != p->len) return -1;
    return 0;
}
#ifndef OW_STANDALONE
static int wifi_send(void *user, const struct ow_packet *p)
{ return wi_write(user, (unsigned char *)p->data, (int)p->len, NULL) < 0 ? -1 : 0; }
#endif
int ow_protocol_cli(int argc, char **argv)
{
    struct ow_registry registry = {{0},0};
    struct ow_context context = {0};
    struct ow_packet packet;
    const struct ow_family *family;
    const struct ow_frame *frame;
    const struct ow_mutator *strategy = &ow_mutators[0];
    const char *family_name = NULL, *frame_name = NULL, *strategy_name = "none", *output = NULL, *iface = NULL;
    uint32_t count = 1, channel = 1;
    struct pcap_sink sink = {NULL,0};
    struct ow_transport transport;
    int i, requested = 0, list = 0, status = 1;
    size_t j;
#ifndef OW_STANDALONE
    struct wif *wi = NULL;
#endif
    for (i=1; i<argc; i++)
        if (!strcmp(argv[i],"--protocol") || !strcmp(argv[i],"--list-protocols") ||
            !strcmp(argv[i],"--protocol-help")) requested = 1;
    if (!requested) return -2;
    context.random_state = 1;
    memset(context.destination,255,6);
    context.source[0] = context.bssid[0] = 2;
    context.source[5] = context.bssid[5] = 1;
    for (i=1; i<argc; i++) {
        const char *key = argv[i], *value;
        if (!strcmp(key,"--protocol-help")) { usage(); return 0; }
        if (!strcmp(key,"--list-protocols")) { list = 1; continue; }
        if (i+1 == argc) goto invalid;
        value = argv[++i];
        if (!strcmp(key,"--protocol")) family_name = value;
        else if (!strcmp(key,"--frame")) frame_name = value;
        else if (!strcmp(key,"--strategy")) strategy_name = value;
        else if (!strcmp(key,"--output")) output = value;
        else if (!strcmp(key,"--interface")) iface = value;
        else if (!strcmp(key,"--seed")) { if (number(value,&context.random_state)) goto invalid; }
        else if (!strcmp(key,"--count")) { if (number(value,&count) || !count || count>1000000) goto invalid; }
        else if (!strcmp(key,"--channel")) { if (number(value,&channel) || !channel || channel>255) goto invalid; }
        else if (!strcmp(key,"--source")) { if (mac(value,context.source)) goto invalid; }
        else if (!strcmp(key,"--destination")) { if (mac(value,context.destination)) goto invalid; }
        else if (!strcmp(key,"--bssid")) { if (mac(value,context.bssid)) goto invalid; }
        else goto invalid;
    }
    if (ow_register_modules(&registry)) { fputs("Protocol registration failed\n",stderr); return 1; }
    if (list) {
        for (j=0; j<registry.count; j++) {
            size_t k;
            family = registry.families[j];
            printf("%s (linktype %u):",family->name,family->linktype);
            for (k=0; k<family->count; k++) printf(" %s",family->frames[k].name);
            puts("");
        }
        return 0;
    }
    family = ow_find_family(&registry,family_name);
    frame = ow_find_frame(family,frame_name);
    if (!family || !frame) { fputs("Unknown protocol/frame; use --list-protocols\n",stderr); return 1; }
    for (j=0; j<ow_mutator_count; j++) if (!strcmp(strategy_name,ow_mutators[j].name)) { strategy = &ow_mutators[j]; break; }
    if (j==ow_mutator_count) { fputs("Unknown strategy\n",stderr); return 1; }
    transport.linktype = family->linktype;
    transport.user = &sink;
    transport.send = pcap_send;
    if (iface) {
        if (output || family->linktype != 105) { fputs("Live WiFi requires linktype 105 and no --output\n",stderr); return 1; }
#ifdef OW_STANDALONE
        fputs("Live transport requires the full owfuzz build\n",stderr); return 1;
#else
        wi = wi_open((char *)iface);
        if (!wi || wi_set_channel(wi,(int)channel)) { if (wi) wi_close(wi); fputs("Cannot open/configure WiFi interface\n",stderr); return 1; }
        transport.user = wi; transport.send = wifi_send;
#endif
    } else {
        sink.fp = output ? fopen(output,"wb") : stdout;
        if (!sink.fp) { perror("PCAP output"); return 1; }
        if (pcap_header(sink.fp,family->linktype)) goto cleanup;
    }
#ifndef OW_STANDALONE
    /* Legacy builders retain their existing globals; generic modules do not use them. */
    fuzz_logger_init(-2, NULL); /* Keep legacy log text out of binary PCAP stdout. */
    srandom(context.random_state);
    fuzzing_opt.auth_type = OPEN_NONE;
    strcpy(fuzzing_opt.target_ssid,"owfuzz");
#endif
    for (context.iteration=0; context.iteration<count; context.iteration++) {
        if (ow_generate(family,frame,&context,strategy,&packet) || ow_deliver(&transport,&packet)) {
            fprintf(stderr,"Campaign failed at iteration %llu\n",(unsigned long long)context.iteration);
            goto cleanup;
        }
    }
    status = 0;
cleanup:
#ifndef OW_STANDALONE
    if (wi) wi_close(wi);
#endif
    if (sink.fp) {
        if (fflush(sink.fp)) status = 1;
        if (output && fclose(sink.fp)) status = 1;
    }
    return status;
invalid:
    fputs("Invalid/missing protocol campaign option\n",stderr); usage(); return 1;
}
#ifdef OW_STANDALONE
int main(int argc, char **argv)
{
    int status = ow_protocol_cli(argc,argv);
    if (status == -2) { usage(); return 1; }
    return status;
}
#endif
