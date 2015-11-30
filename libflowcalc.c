/*
 * libflowcalc: library for calculating IP flow features
 * Copyright (C) 2012-2015 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Copyright (C) 2015 Akamai Technologies, Inc. <http://www.akamai.com/>
 *
 * Author: Paweł Foremski <pjf@foremski.pl>
 * Inspired by lpi_protoident.cc by Shane Alcock, et al.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * FIXME: handle the TCP_ANYSTART option better (@1): the case in which
 *        first==1 for a TCP connection started by any packet is not
 *        the same as the one started by the proper SYN/SYN+ACK/ACK triplet
 *        e.g. the classification by first 5 packets would need this
 * FIXME: add flow_cleanup() callback, because flow_cb() can be skipped
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libtrace.h>
#include <libflowmanager.h>

#include "libflowcalc.h"

static void flow_summarize(struct lfc *lfc, Flow *flow)
{
	struct lfc_ext *le;
	struct lfc_plugin *lp;

	le = (struct lfc_ext *) flow->extension;
	if (!le || le->done) return;

	/* skip TCP flows that didnt shutdown properly */
	if (lfc->reqclose && le->lf.proto == TRACE_IPPROTO_TCP) {
		switch (flow->flow_state) {
			case FLOW_STATE_CLOSE:
			case FLOW_STATE_RESET:
			case FLOW_STATE_HALFCLOSE:
				break;
			default:
				le->done = true;
				return;
			}
	}

	/* skip TCP flows with unrecovered packet losses */
	if (lfc->noloss && le->lf.proto == TRACE_IPPROTO_TCP) {
		if (le->lf.tcp_up.lost_ts > 0 || le->lf.tcp_down.lost_ts > 0) {
			le->done = true;
			return;
		}
	}

	uint8_t *bptr = (uint8_t *) le->data;
	tlist_reset(lfc->plugins);
	while ((lp = (struct lfc_plugin *) tlist_iter(lfc->plugins))) {
		if (lp->flowcb) lp->flowcb(lfc, lp->plugin, &le->lf, bptr);
		bptr += lp->datalen;
	}

	le->done = true;
}

static void free_tcp(struct lfc_flow_tcp *ftcp)
{
	struct lfc_tcplost *tl;

	if (ftcp->lost_list) {
		tlist_reset(ftcp->lost_list);
		while ((tl = (struct lfc_tcplost *) tlist_iter(ftcp->lost_list)))
			mmatic_free(tl);
		tlist_free(ftcp->lost_list);
	}
}

static void expire_flows(struct lfc *lfc, double ts, bool force)
{
	Flow *ltflow;
	struct lfc_ext *le;

	while ((ltflow = lfm_expire_next_flow(ts, force)) != NULL) {
		le = (struct lfc_ext *) ltflow->extension;

		flow_summarize(lfc, ltflow);

		free_tcp(&(le->lf.tcp_up));
		free_tcp(&(le->lf.tcp_down));
		if (lfc->datalen_sum)
			mmatic_free(le->data);
		mmatic_free(le);
		delete(ltflow);
	}
}

static void per_packet(struct lfc *lfc, libtrace_packet_t *ltpkt)
{
	struct lfc_pkt pkt = {0};
	struct lfc_flow *flow = NULL;
	static double last_gc = 0.0;

	/*
	 * move the garbage collector forward?
	 */
	pkt.ts = trace_get_seconds(ltpkt);
	if (pkt.ts - last_gc > 3.0) {
		expire_flows(lfc, pkt.ts, false);
		last_gc = pkt.ts;
	}

	/*
	 * get network layer info
	 */
	uint16_t l3_proto;
	void *ptr;
	uint32_t rem;

	/* skip non-IP */
	ptr = trace_get_layer3(ltpkt, &l3_proto, &rem);
	if (!ptr) return;
	if (l3_proto == TRACE_ETHERTYPE_IP && rem >= sizeof *(pkt.ip4))
		pkt.ip4 = (libtrace_ip_t *) ptr;
	else if (l3_proto == TRACE_ETHERTYPE_IPV6 && rem >= sizeof *(pkt.ip6))
		pkt.ip6 = (libtrace_ip6_t *) ptr;
	else return;

	/*
	 * get transport layer info
	 */
	uint8_t l4_proto;

	/* skip non-TCP/UDP */
	ptr = trace_get_transport(ltpkt, &l4_proto, &rem);
	if (!ptr) return;
	if (l4_proto == TRACE_IPPROTO_TCP && rem >= sizeof *pkt.tcp) {
		pkt.tcp = (libtrace_tcp_t *) ptr;
		pkt.sport = ntohs(pkt.tcp->source);
		pkt.dport = ntohs(pkt.tcp->dest);
	} else if (l4_proto == TRACE_IPPROTO_UDP && rem >= sizeof *pkt.udp) {
		pkt.udp = (libtrace_udp_t *) ptr;
		pkt.sport = ntohs(pkt.udp->source);
		pkt.dport = ntohs(pkt.udp->dest);
	} else return;

	/*
	 * get flow data @1
	 */
	Flow *ltflow;
	struct lfc_ext *le;

	/* get libflowmanager info */
	int dir = 0;
	if (pkt.ip4) dir = memcmp(&pkt.ip4->ip_src, &pkt.ip4->ip_dst, sizeof pkt.ip4->ip_src);
	else         dir = memcmp(&pkt.ip6->ip_src, &pkt.ip6->ip_dst, sizeof pkt.ip6->ip_src);
	if (dir > 0 || (dir == 0 && pkt.sport > pkt.dport)) dir = 1;

	ltflow = lfm_match_packet_to_flow(ltpkt, dir, &pkt.first);
	if (!ltflow) return;

	/* record information on first packet? */
	if (pkt.first) {
		pkt.up = true;

		le = (struct lfc_ext *) mmatic_zalloc(lfc->mm, sizeof(*le));
		if (lfc->datalen_sum)
			le->data = mmatic_zalloc(lfc->mm, lfc->datalen_sum);
		ltflow->extension = le;

		flow = &le->lf;
		flow->id = ++lfc->last_id;
		flow->ts_first = pkt.ts;

		/* copy IP address */
		if (pkt.ip6) {
			flow->is_ip6 = true;
			memcpy(&flow->src.addr.ip6, &pkt.ip6->ip_src, sizeof pkt.ip6->ip_src);
			memcpy(&flow->dst.addr.ip6, &pkt.ip6->ip_dst, sizeof pkt.ip6->ip_dst);
		} else {
			flow->is_ip6 = false;
			memcpy(&flow->src.addr.ip4, &pkt.ip4->ip_src, sizeof pkt.ip4->ip_src);
			memcpy(&flow->dst.addr.ip4, &pkt.ip4->ip_dst, sizeof pkt.ip4->ip_dst);
		}

		/* transport protocol */
		flow->proto = l4_proto;
		flow->src.port = pkt.sport;
		flow->dst.port = pkt.dport;
	} else {
		le = (struct lfc_ext *) ltflow->extension;
		flow = &le->lf;

		if (le->done) goto skip;

		/*
		 * NOTE: we make our own notion of "packet direction", different than in the libflowmanager. In
		 * libflowcalc, packet direction is 1 if it follows the same direction as the first packet in
		 * the flow (ie. the initial packet), or 0 otherwise. This somehow defines the "upload" (1) and
		 * "download" (0) direction of data transfer, relative to the flow inception.
		 *
		 * The code below gets packet direction as in libflowcalc
		 */
		if (pkt.ip6)
			pkt.up = (memcmp(&(pkt.ip6->ip_src), &(flow->src.addr.ip6), sizeof(pkt.ip6->ip_src)) == 0);
		else
			pkt.up = (memcmp(&(pkt.ip4->ip_src), &(flow->src.addr.ip4), sizeof(pkt.ip4->ip_src)) == 0);

		if (pkt.up) {
			if (pkt.tcp) pkt.up = (ntohs(pkt.tcp->source) == flow->src.port);
			else         pkt.up = (ntohs(pkt.udp->source) == flow->src.port);
		}
	}

	/*
	 * record additional data
	 */
	flow->ts_last = pkt.ts;
	pkt.ltpkt = ltpkt;
	pkt.size  = trace_get_wire_length(ltpkt);
	pkt.psize = trace_get_payload_length(ltpkt);

	if (pkt.tcp) pkt.data = trace_get_payload_from_tcp(pkt.tcp, &rem);
	else         pkt.data = trace_get_payload_from_udp(pkt.udp, &rem);
	if (rem > 0) pkt.len = rem;
	else         pkt.data = NULL;

	/*
	 * detect dupes @2
	 */
	if (pkt.ip4) {
		pkt.id = htons(pkt.ip4->ip_id) << 16;
		pkt.id |= htons(pkt.ip4->ip_off) & 0x1FFF;
	} else { /* NB: work-around for IPv6 */
		pkt.id = (pkt.tcp) ? pkt.tcp->seq : (uint32_t) pkt.udp->check;
		pkt.id ^= pkt.ip6->plen << 16;
	}

	if (pkt.up) {
		pkt.dup = (pkt.id == flow->last_id_up);
		flow->last_id_up = pkt.id;
	} else {
		pkt.dup = (pkt.id == flow->last_id_down);
		flow->last_id_down = pkt.id;
	}

	/*
	 * detect TCP packet loss
	 */
	uint32_t seq, len, from, to;
	struct lfc_flow_tcp *ftcp;
	struct lfc_tcplost *tl, *tl2;

	if (lfc->noloss && pkt.tcp) {
		seq = ntohl(pkt.tcp->seq);
		len = trace_get_payload_length(ltpkt);
		from = seq;
		to = len > 0 ? seq + len - 1 : 0; /* dont use if len is 0 */
		ftcp = pkt.up ? &(flow->tcp_up) : &(flow->tcp_down);

		dbg(5, "%u %u -> %u: seq %u len %u -> next %u\t",
			pkt.up, flow->src.port, flow->dst.port, seq, len, seq+len);

		/* special case: initial packets */
		if (pkt.tcp->syn && ftcp->next_seq == 0) {
			ftcp->next_seq = seq + 1;
			dbg(5, "=INIT");
		}

		/* typical case: no loss */
		else if (seq == ftcp->next_seq) {
			ftcp->next_seq = seq + len;
			dbg(5, "=OK");
		}

		/* happens: segment lost (packet reorder?) */
		else if (seq > ftcp->next_seq) {

			/* collect data on lost segment */
			tl = (struct lfc_tcplost *) mmatic_zalloc(lfc->mm, sizeof *tl);
			tl->from = ftcp->next_seq;
			tl->to   = seq - 1;
			tl->ts   = pkt.ts;

			/* push it to flow tcp info */
			if (!ftcp->lost_list)
				ftcp->lost_list = tlist_create(NULL, lfc->mm);
			tlist_push(ftcp->lost_list, tl);
			if (ftcp->lost_ts == 0)
				ftcp->lost_ts = pkt.ts;

			dbg(5, "=LOST from %u to %u (total %u)", ftcp->next_seq, seq - 1, tlist_count(ftcp->lost_list));

			ftcp->next_seq = seq + len;
		}

		else if (len == 0) {
			dbg(5, "=SKIP");
		}

		/* happens: retransmissions (dont use seq/len here) */
		else if (seq < ftcp->next_seq) {
			dbg(5, "=RETRANS");

			/* look-up and delete from lost list */
			tlist_reset(ftcp->lost_list);
			while ((tl = (struct lfc_tcplost *) tlist_iter(ftcp->lost_list))) {
				if (to < tl->from) break; // list sorted by tl->from
				if (!((from >= tl->from && from <= tl->to)
					||  (to >= tl->from &&   to <= tl->to))) continue;

				/* segment retransmitted */
				tlist_remove(ftcp->lost_list);

				/* segment starts in middle */
				if (from > tl->from) {
					tl2 = (struct lfc_tcplost *) mmatic_zalloc(lfc->mm, sizeof *tl2);
					tl2->from = tl->from;
					tl2->to   = from - 1;
					tl2->ts   = tl->ts;
					tlist_insertbefore(ftcp->lost_list, tl2);
				}

				/* segment ends in middle */
				if (to < tl->to) {
					tl2 = (struct lfc_tcplost *) mmatic_zalloc(lfc->mm, sizeof *tl2);
					tl2->from = to + 1;
					tl2->to   = tl->to;
					tl2->ts   = tl->ts;
					tlist_insertbefore(ftcp->lost_list, tl2);
				}
				/* segments ends after */
				else if (to > tl->to) {
					from = tl->to + 1;
				}

				mmatic_free(tl);
			}

			dbg(5, " =RECOVERED from %u to %u", seq, to);

			/* update lost_ts to first ts in tlist */
			if (tlist_count(ftcp->lost_list) == 0) {
				dbg(5, " =RECOVERING DONE", seq, to);
				ftcp->lost_ts = 0;
			} else {
				dbg(5, " =STILL RECOVERING(%u)", tlist_count(ftcp->lost_list));
				tlist_reset(ftcp->lost_list);
				tl = (struct lfc_tcplost *) tlist_peek(ftcp->lost_list);
				ftcp->lost_ts = tl->ts;
			}
		}

		dbg(5, "\n");
	}

	/*
	 * behind the time limit?
	 */
	if (lfc->t > 0.0 && pkt.ts - flow->ts_first > lfc->t) {
		flow_summarize(lfc, ltflow);
		goto skip;
	}

	/*
	 * run callbacks
	 */
	{
		uint8_t *bptr = (uint8_t *) le->data;
		struct lfc_plugin *lp;

		tlist_reset(lfc->plugins);
		while ((lp = (struct lfc_plugin *) tlist_iter(lfc->plugins))) {
			if (lp->pktcb) lp->pktcb(lfc, lp->plugin, flow, &pkt, bptr);
			bptr += lp->datalen;
		}
	}


	/*
	 * packet limit
	 */
	if (trace_get_payload_length(ltpkt) > 0)
		flow->n++;

	if (lfc->n > 0 && flow->n == lfc->n)
		flow_summarize(lfc, ltflow);

skip:
	/*
	 * flow maintenance
	 */
	if (pkt.tcp)
		lfm_check_tcp_flags(ltflow, pkt.tcp, dir, pkt.ts);
	lfm_update_flow_expiry_timeout(ltflow, pkt.ts);
}

/**********************************/

struct lfc *lfc_init()
{
	mmatic *mm;
	struct lfc *lfc;

	mm = (mmatic *) mmatic_create();
	lfc = (struct lfc *) mmatic_zalloc(mm, sizeof *lfc);
	lfc->mm = mm;
	lfc->plugins = tlist_create(NULL, mm);

	return lfc;
}

void lfc_deinit(struct lfc *lfc)
{
	expire_flows(lfc, 0, true);
	mmatic_destroy(lfc->mm);
}

void lfc_enable(struct lfc *lfc, enum lfc_option option, void *val)
{
	int one = 1;

	switch (option) {
		case LFC_OPT_TCP_ANYSTART:
			dbg(4, "enabling LFM_CONFIG_TCP_ANYSTART\n");
			lfm_set_config_option(LFM_CONFIG_TCP_ANYSTART, &one);
			break;
		case LFC_OPT_TCP_WAIT:
			lfm_set_config_option(LFM_CONFIG_TCP_TIMEWAIT, &one);
			break;
		case LFC_OPT_PACKET_LIMIT:
			lfc->n = *((int *) val);
			break;
		case LFC_OPT_TIME_LIMIT:
			lfc->t = *((double *) val);
			break;
		case LFC_OPT_TCP_NOLOSS:
			lfc->noloss = true;
			break;
		case LFC_OPT_TCP_REQCLOSE:
			lfc->reqclose = true;
			break;
	}
}

void lfc_register(struct lfc *lfc,
	const char *name, int datalen, pkt_cb pktcb, flow_cb flowcb, void *plugin)
{
	struct lfc_plugin *lp;

	lp = (struct lfc_plugin *) mmatic_zalloc(lfc->mm, sizeof *lp);
	lp->name = mmatic_strdup(lfc->mm, name);
	lp->datalen = datalen;
	lp->pktcb = pktcb;
	lp->flowcb = flowcb;
	lp->plugin = plugin;

	tlist_push(lfc->plugins, lp);
	lfc->datalen_sum += datalen;
}

bool lfc_run(struct lfc *lfc, const char *uri, const char *filterstring)
{
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter = NULL;

	if (!uri || !uri[0] || streq(uri, "-")) {
		uri = "pcap:-";
		setvbuf(stdin, 0, _IONBF, 0);
	}

	packet = trace_create_packet();
	if (!packet) {
		dbg(1, "error while creating libtrace packet\n");
		return false;
	}

	/***/

	trace = trace_create(uri);
	if (!trace) {
		dbg(1, "error while creating libtrace object\n");
		return false;
	}

	if (trace_is_err(trace)) {
		trace_perror(trace, "Opening trace file");
		return false;
	}

	if (filterstring) {
		filter = trace_create_filter(filterstring);

		if (trace_config(trace, TRACE_OPTION_FILTER, filter) == -1) {
			trace_perror(trace, "Configuring filter");
			return false;
		}
	}

	/***/

	if (trace_start(trace) == -1) {
		trace_perror(trace, "Starting trace");
		return false;
	}

	while (trace_read_packet(trace, packet) > 0)
		per_packet(lfc, packet);

	if (trace_is_err(trace)) {
		trace_perror(trace, "Reading packets");
		return false;
	}

	expire_flows(lfc, 0, true);

	trace_destroy(trace);
	trace_destroy_packet(packet);

	return true;
}
