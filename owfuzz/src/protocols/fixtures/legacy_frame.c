/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Original frame dispatch Copyright (C) 2020-2021 Hongjian Cao <haimohk@gmail.com>. */
/* Frozen pre-refactor dispatch for behavior regression; intentionally retained. */
#include "frame.h"
extern fuzzing_option fuzzing_opt;
struct packet baseline_get_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt)
{
	struct packet pkt = {0};

	// fuzzing_opt.fuzz_pkt_num++;
	if (recv_pkt)
	{
		pkt.channel = recv_pkt->channel;
	}

	fuzzing_opt.current_frame = frame_type;

	// fuzz_logger_log(FUZZ_LOG_INFO, "[%s:%d] frame_type: %x (%s)", __FILE__, __LINE__, frame_type, return_frame_type(frame_type));
	switch (frame_type)
	{
	// management
	case IEEE80211_TYPE_ASSOCRES: // AP
		pkt = create_association_response(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_REASSOCRES:
		pkt = create_reassociation_response(bssid, dmac, 0);
		break;
	case IEEE80211_TYPE_PROBERES:
		if (recv_pkt)
			pkt = create_probe_response(bssid, dmac, 0, NULL, recv_pkt->data + sizeof(struct ieee_hdr), recv_pkt->len - sizeof(struct ieee_hdr));
		else
			pkt = create_probe_response(bssid, dmac, 0, NULL, NULL, 0);
		break;
	case IEEE80211_TYPE_TIMADVERT:
		pkt = create_timing_advertisement(bssid, dmac, 0);
		break;
	case IEEE80211_TYPE_BEACON:
		pkt = create_beacon(bssid, 0, NULL);
		break;
	case IEEE80211_TYPE_ATIM: // xx
		pkt = create_atim(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DISASSOC:
		pkt = create_disassociation(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DEAUTH:
		pkt = create_deauthentication(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ACTION:
		pkt = create_action(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ACTIONNOACK:
		pkt = create_action_no_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ASSOCREQ: // STA
		pkt = create_association_request(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_REASSOCREQ:
		pkt = create_reassociation_request(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_PROBEREQ:
		pkt = create_probe_request(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_AUTH:
		pkt = create_authentication(bssid, smac, dmac, 0, recv_pkt);
		break;
	// control
	case IEEE80211_TYPE_ACK:
		pkt = create_ack(dmac);
		break;
	case IEEE80211_TYPE_BEAMFORMING:
		pkt = create_beamforming_report_poll(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_VHT:
		pkt = create_vht_ndp_announcement(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CTRLFRMEXT:
		pkt = create_control_frame_extension(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CTRLWRAP:
		pkt = create_control_wrapper(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_BLOCKACKREQ:
		pkt = create_block_ack_request(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_BLOCKACK:
		pkt = create_block_ack(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_PSPOLL:
		pkt = create_ps_poll(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_RTS:
		pkt = create_rts(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CTS:
		pkt = create_cts(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CFEND:
		pkt = create_cf_end(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CFENDACK:
		pkt = create_cf_end_cf_ack(bssid, smac, dmac);
		break;
	// data
	case IEEE80211_TYPE_QOSDATA:
		pkt = create_qos_data(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATA:
		pkt = create_data(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATACFACK:
		pkt = create_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATACFPOLL:
		pkt = create_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATACFACKPOLL:
		pkt = create_data_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_NULL:
		pkt = create_data_null(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_CFACK:
		pkt = create_d_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_CFPOLL:
		pkt = create_d_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_CFACKPOLL:
		pkt = create_d_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSDATACFACK:
		pkt = create_qos_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSDATACFPOLL:
		pkt = create_qos_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSDATACFACKPOLL:
		pkt = create_qos_data_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSNULL:
		pkt = create_qos_null(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSCFACK:
		pkt = create_qos_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSCFPOLL:
		pkt = create_qos_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSCFACKPOLL:
		pkt = create_qos_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	// extension
	case IEEE80211_TYPE_DMGBEACON:
		break;
	default:
		break;
	}

	return pkt;
}

