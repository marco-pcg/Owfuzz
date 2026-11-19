/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Original frame dispatch Copyright (C) 2020-2021 Hongjian Cao <haimohk@gmail.com>. */
/* Adapters preserve existing frame-builder behavior and wire IDs. */
#include "legacy_registry.h"
#include <string.h>
extern fuzzing_option fuzzing_opt;
static struct packet build_association_response(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_association_response(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_reassociation_response(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_reassociation_response(bssid, dmac, 0);
    return pkt;
}
static struct packet build_probe_response(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		if (recv_pkt && recv_pkt->len >= sizeof(struct ieee_hdr))
			pkt = create_probe_response(bssid, dmac, 0, NULL, recv_pkt->data + sizeof(struct ieee_hdr), recv_pkt->len - sizeof(struct ieee_hdr));
		else
			pkt = create_probe_response(bssid, dmac, 0, NULL, NULL, 0);
    return pkt;
}
static struct packet build_timing_advertisement(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_timing_advertisement(bssid, dmac, 0);
    return pkt;
}
static struct packet build_beacon(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_beacon(bssid, 0, NULL);
    return pkt;
}
static struct packet build_atim(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_atim(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_disassociation(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_disassociation(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_deauthentication(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_deauthentication(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_action(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_action(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_action_no_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_action_no_ack(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_association_request(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_association_request(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_reassociation_request(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_reassociation_request(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_probe_request(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_probe_request(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_authentication(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_authentication(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_ack(dmac);
    return pkt;
}
static struct packet build_beamforming_report_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_beamforming_report_poll(bssid, smac, dmac);
    return pkt;
}
static struct packet build_vht_ndp_announcement(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_vht_ndp_announcement(bssid, smac, dmac);
    return pkt;
}
static struct packet build_control_frame_extension(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_control_frame_extension(bssid, smac, dmac);
    return pkt;
}
static struct packet build_control_wrapper(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_control_wrapper(bssid, smac, dmac);
    return pkt;
}
static struct packet build_block_ack_request(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_block_ack_request(bssid, smac, dmac);
    return pkt;
}
static struct packet build_block_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_block_ack(bssid, smac, dmac);
    return pkt;
}
static struct packet build_ps_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_ps_poll(bssid, smac, dmac);
    return pkt;
}
static struct packet build_rts(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_rts(bssid, smac, dmac);
    return pkt;
}
static struct packet build_cts(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_cts(bssid, smac, dmac);
    return pkt;
}
static struct packet build_cf_end(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_cf_end(bssid, smac, dmac);
    return pkt;
}
static struct packet build_cf_end_cf_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_cf_end_cf_ack(bssid, smac, dmac);
    return pkt;
}
static struct packet build_qos_data(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_data(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_data(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_data(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_data_cf_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_data_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_data_cf_ack_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_data_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_null(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_data_null(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_cf_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_d_cf_ack(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_d_cf_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_cf_ack_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_d_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_data_cf_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_data_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_data_cf_ack_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_data_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_null(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_null(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_cf_ack(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_cf_ack(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_cf_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet build_qos_cf_ack_cf_poll(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
		pkt = create_qos_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
    return pkt;
}
static struct packet baseline_beacon(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{ (void)smac; (void)dmac; (void)recv_pkt; return create_ap_beacon(bssid, 0, fuzzing_opt.auth_type); }
static struct packet baseline_association_response(struct ether_addr bssid, struct ether_addr smac,
    struct ether_addr dmac, struct packet *recv_pkt)
{ (void)recv_pkt; return create_ap_association_response(bssid, smac, dmac, 0); }
const struct ow_wifi_frame ow_wifi_frames[] = {
    {IEEE80211_TYPE_ASSOCRES, "association_response", "IEEE80211_TYPE_ASSOCRES", "(management)IEEE80211_TYPE_ASSOCRES", build_association_response, baseline_association_response, save_association_response_state, load_association_response_state},
    {IEEE80211_TYPE_REASSOCRES, "reassociation_response", "IEEE80211_TYPE_REASSOCRES", "(management)IEEE80211_TYPE_REASSOCRES", build_reassociation_response, NULL, save_reassociation_response_state, load_reassociation_response_state},
    {IEEE80211_TYPE_PROBERES, "probe_response", "IEEE80211_TYPE_PROBERES", "(management)IEEE80211_TYPE_PROBERES", build_probe_response, NULL, save_probe_response_state, load_probe_response_state},
    {IEEE80211_TYPE_TIMADVERT, "timing_advertisement", "IEEE80211_TYPE_TIMADVERT", "(management)IEEE80211_TYPE_TIMADVERT", build_timing_advertisement, NULL, save_timing_advertisement_state, load_timing_advertisement_state},
    {IEEE80211_TYPE_BEACON, "beacon", "IEEE80211_TYPE_BEACON", "(management)IEEE80211_TYPE_BEACON", build_beacon, baseline_beacon, save_beacon_state, load_beacon_state},
    {IEEE80211_TYPE_ATIM, "atim", "IEEE80211_TYPE_ATIM", "(management)IEEE80211_TYPE_ATIM", build_atim, NULL, save_atim_state, load_atim_state},
    {IEEE80211_TYPE_DISASSOC, "disassociation", "IEEE80211_TYPE_DISASSOC", "(management)IEEE80211_TYPE_DISASSOC", build_disassociation, NULL, save_disassociation_state, load_disassociation_state},
    {IEEE80211_TYPE_DEAUTH, "deauthentication", "IEEE80211_TYPE_DEAUTH", "(management)IEEE80211_TYPE_DEAUTH", build_deauthentication, NULL, save_deauthentication_state, load_deauthentication_state},
    {IEEE80211_TYPE_ACTION, "action", "IEEE80211_TYPE_ACTION", "(management)IEEE80211_TYPE_ACTION", build_action, NULL, save_action_state, load_action_state},
    {IEEE80211_TYPE_ACTIONNOACK, "action_no_ack", "IEEE80211_TYPE_ACTIONNOACK", "(management)IEEE80211_TYPE_ACTIONNOACK", build_action_no_ack, NULL, save_action_no_ack_state, load_action_no_ack_state},
    {IEEE80211_TYPE_ASSOCREQ, "association_request", "IEEE80211_TYPE_ASSOCREQ", "(management)IEEE80211_TYPE_ASSOCREQ", build_association_request, NULL, save_association_request_state, load_association_request_state},
    {IEEE80211_TYPE_REASSOCREQ, "reassociation_request", "IEEE80211_TYPE_REASSOCREQ", "(management)IEEE80211_TYPE_REASSOCREQ", build_reassociation_request, NULL, save_reassociation_request_state, load_reassociation_request_state},
    {IEEE80211_TYPE_PROBEREQ, "probe_request", "IEEE80211_TYPE_PROBEREQ", "(management)IEEE80211_TYPE_PROBEREQ", build_probe_request, NULL, save_probe_request_state, load_probe_request_state},
    {IEEE80211_TYPE_AUTH, "authentication", "IEEE80211_TYPE_AUTH", "(management)IEEE80211_TYPE_AUTH", build_authentication, NULL, save_authentication_state, load_authentication_state},
    {IEEE80211_TYPE_ACK, "ack", "IEEE80211_TYPE_ACK", "(control)IEEE80211_TYPE_ACK", build_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_BEAMFORMING, "beamforming_report_poll", "IEEE80211_TYPE_BEAMFORMING", "(control)IEEE80211_TYPE_BEAMFORMING", build_beamforming_report_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_VHT, "vht_ndp_announcement", "IEEE80211_TYPE_VHT", "(control)IEEE80211_TYPE_VHT", build_vht_ndp_announcement, NULL, NULL, NULL},
    {IEEE80211_TYPE_CTRLFRMEXT, "control_frame_extension", "IEEE80211_TYPE_CTRLFRMEXT", "(control)IEEE80211_TYPE_CTRLFRMEXT", build_control_frame_extension, NULL, NULL, NULL},
    {IEEE80211_TYPE_CTRLWRAP, "control_wrapper", "IEEE80211_TYPE_CTRLWRAP", "(control)IEEE80211_TYPE_CTRLWRAP", build_control_wrapper, NULL, NULL, NULL},
    {IEEE80211_TYPE_BLOCKACKREQ, "block_ack_request", "IEEE80211_TYPE_BLOCKACKREQ", "(control)IEEE80211_TYPE_BLOCKACKREQ", build_block_ack_request, NULL, NULL, NULL},
    {IEEE80211_TYPE_BLOCKACK, "block_ack", "IEEE80211_TYPE_BLOCKACK", "(control)IEEE80211_TYPE_BLOCKACK", build_block_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_PSPOLL, "ps_poll", "IEEE80211_TYPE_PSPOLL", "(control)IEEE80211_TYPE_PSPOLL", build_ps_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_RTS, "rts", "IEEE80211_TYPE_RTS", "(control)IEEE80211_TYPE_RTS", build_rts, NULL, NULL, NULL},
    {IEEE80211_TYPE_CTS, "cts", "IEEE80211_TYPE_CTS", "(control)IEEE80211_TYPE_CTS", build_cts, NULL, NULL, NULL},
    {IEEE80211_TYPE_CFEND, "cf_end", "IEEE80211_TYPE_CFEND", "(control)IEEE80211_TYPE_CFEND", build_cf_end, NULL, NULL, NULL},
    {IEEE80211_TYPE_CFENDACK, "cf_end_cf_ack", "IEEE80211_TYPE_CFENDACK", "(control)IEEE80211_TYPE_CFENDACK", build_cf_end_cf_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSDATA, "qos_data", "IEEE80211_TYPE_QOSDATA", "(data)IEEE80211_TYPE_QOSDATA", build_qos_data, NULL, NULL, NULL},
    {IEEE80211_TYPE_DATA, "data", "IEEE80211_TYPE_DATA", "(data)IEEE80211_TYPE_DATA", build_data, NULL, NULL, NULL},
    {IEEE80211_TYPE_DATACFACK, "data_cf_ack", "IEEE80211_TYPE_DATACFACK", "(data)IEEE80211_TYPE_DATACFACK", build_data_cf_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_DATACFPOLL, "data_cf_poll", "IEEE80211_TYPE_DATACFPOLL", "(data)IEEE80211_TYPE_DATACFPOLL", build_data_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_DATACFACKPOLL, "data_cf_ack_cf_poll", "IEEE80211_TYPE_DATACFACKPOLL", "(data)IEEE80211_TYPE_DATACFACKPOLL", build_data_cf_ack_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_NULL, "null", "IEEE80211_TYPE_NULL", "(data)IEEE80211_TYPE_NULL", build_null, NULL, NULL, NULL},
    {IEEE80211_TYPE_CFACK, "cf_ack", "IEEE80211_TYPE_CFACK", "(data)IEEE80211_TYPE_CFACK", build_cf_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_CFPOLL, "cf_poll", "IEEE80211_TYPE_CFPOLL", "(data)IEEE80211_TYPE_CFPOLL", build_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_CFACKPOLL, "cf_ack_cf_poll", "IEEE80211_TYPE_CFACKPOLL", "(data)IEEE80211_TYPE_CFACKPOLL", build_cf_ack_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSDATACFACK, "qos_data_cf_ack", "IEEE80211_TYPE_QOSDATACFACK", "(data)IEEE80211_TYPE_QOSDATACFACK", build_qos_data_cf_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSDATACFPOLL, "qos_data_cf_poll", "IEEE80211_TYPE_QOSDATACFPOLL", "(data)IEEE80211_TYPE_QOSDATACFPOLL", build_qos_data_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSDATACFACKPOLL, "qos_data_cf_ack_cf_poll", "IEEE80211_TYPE_QOSDATACFACKPOLL", "(data)IEEE80211_TYPE_QOSDATACFACKPOLL", build_qos_data_cf_ack_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSNULL, "qos_null", "IEEE80211_TYPE_QOSNULL", "(data)IEEE80211_TYPE_QOSNULL", build_qos_null, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSCFACK, "qos_cf_ack", "IEEE80211_TYPE_QOSCFACK", "(data)IEEE80211_TYPE_QOSCFACK", build_qos_cf_ack, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSCFPOLL, "qos_cf_poll", "IEEE80211_TYPE_QOSCFPOLL", "(data)IEEE80211_TYPE_QOSCFPOLL", build_qos_cf_poll, NULL, NULL, NULL},
    {IEEE80211_TYPE_QOSCFACKPOLL, "qos_cf_ack_cf_poll", "IEEE80211_TYPE_QOSCFACKPOLL", "(data)IEEE80211_TYPE_QOSCFACKPOLL", build_qos_cf_ack_cf_poll, NULL, NULL, NULL},
};
const size_t ow_wifi_frame_count = sizeof(ow_wifi_frames)/sizeof(ow_wifi_frames[0]);
const struct ow_wifi_frame *ow_wifi_find_id(uint8_t id)
{
    size_t i;
    for (i=0; i<ow_wifi_frame_count; i++) if (ow_wifi_frames[i].id == id) return &ow_wifi_frames[i];
    return NULL;
}
const struct ow_wifi_frame *ow_wifi_find_name(const char *name)
{
    size_t i;
    if (!name) return NULL;
    for (i=0; i<ow_wifi_frame_count; i++) if (!strcmp(ow_wifi_frames[i].name, name)) return &ow_wifi_frames[i];
    return NULL;
}
