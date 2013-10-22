/*
 * libflowcalc - library for calculating IP flows out of PCAP files
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Licensed under GNU GPL v. 3
 *
 * Inspired by lpi_protoident.cc by Shane Alcock, et al.
 *
 * FIXME: handle the TCP_ANYSTART option better (@1): the case in which
 *        is_new==1 for a TCP connection started by any packet is not
 *        the same as the one started by the proper SYN/SYN+ACK/ACK triplet
 *        e.g. the classification by first 5 packets would need this
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libtrace.h>
#include <libflowmanager.h>

#include "libflowcalc.h"

static void flow_summarize(struct lfc *lfc, struct lfc_ext *le)
{
	struct lfc_plugin *lp;
	void *ptr;

	if (le->done) return;

	ptr = le->data;
	tlist_reset(lfc->plugins);

	while ((lp = (struct lfc_plugin *) tlist_iter(lfc->plugins))) {
		if (lp->flowcb)
			lp->flowcb(lfc, lp->pdata, &le->lf, ptr);

		ptr += lp->datalen;
	}

	le->done = true;
}

static void expire_flows(struct lfc *lfc, double ts, bool force)
{
	Flow *flow;
	struct lfc_ext *le;

	while ((flow = lfm_expire_next_flow(ts, force)) != NULL) {
		le = (struct lfc_ext *) flow->extension;

		flow_summarize(lfc, le);

		if (lfc->datalen_sum)
			mmatic_free(le->data);
		mmatic_free(le);
		delete(flow);
	}
}

static void per_packet(struct lfc *lfc, libtrace_packet_t *pkt)
{
	/*
	 * move the garbage collector forward
	 */
	double ts;
	ts = trace_get_seconds(pkt);
	expire_flows(lfc, ts, false);

	/*
	 * get network layer info
	 */
	void *l3;
	uint16_t l3_proto;
	uint32_t rem;
	libtrace_ip_t *ip4 = NULL;
	libtrace_ip6_t *ip6 = NULL;
	int dir;

	/* skip non-IP */
	l3 = trace_get_layer3(pkt, &l3_proto, &rem);
	if (!l3)
		return;
	else if (l3_proto == TRACE_ETHERTYPE_IP && rem >= sizeof *ip4)
		ip4 = (libtrace_ip_t *) l3;
	else if (l3_proto == TRACE_ETHERTYPE_IPV6 && rem >= sizeof *ip6)
		ip6 = (libtrace_ip6_t *) l3;
	else
		return;

	/*
	 * get transport layer info
	 */
	void *l4;
	uint8_t l4_proto;
	libtrace_tcp_t *tcp = NULL;
	libtrace_udp_t *udp = NULL;
	uint16_t src_port;
	uint16_t dst_port;

	/* skip non-TCP/UDP */
	l4 = trace_get_transport(pkt, &l4_proto, &rem);
	if (!l4)
		return;
	else if (l4_proto == TRACE_IPPROTO_TCP && rem >= sizeof(*tcp))
		tcp = (libtrace_tcp_t *) l4;
	else if (l4_proto == TRACE_IPPROTO_UDP && rem >= sizeof(*udp))
		udp = (libtrace_udp_t *) l4;
	else
		return;

	src_port = trace_get_source_port(pkt);
	dst_port = trace_get_destination_port(pkt);

	/*
	 * get libflowmanager direction
	 */
	if (ip4)
		dir = memcmp(&(ip4->ip_src), &(ip4->ip_dst), sizeof(ip4->ip_src));
	else
		dir = memcmp(&(ip6->ip_src), &(ip6->ip_dst), sizeof(ip6->ip_src));

	if (dir < 0) {
		dir = 0;
	} else if (dir > 0) {
		dir = 1;
	} else {
		if (src_port < dst_port)
			dir = 0;
		else if (src_port > dst_port)
			dir = 1;
		else
			dir = 0;
	}

	/*
	 * get flow data @1
	 */
	bool is_new = false;
	Flow *f;
	struct lfc_ext *le;
	struct lfc_flow *lf;
	bool up;

	f = lfm_match_packet_to_flow(pkt, dir, &is_new);
	if (!f)
		return;

	if (is_new) {
		le = (struct lfc_ext *) mmatic_zalloc(lfc->mm, sizeof(*le));
		if (lfc->datalen_sum)
			le->data = mmatic_zalloc(lfc->mm, lfc->datalen_sum);
		f->extension = le;

		/*
		 * record information on first packet
		 */
		lf = &le->lf;
		lf->id = ++lfc->last_id;
		lf->ts_first = ts;

		/* copy IP address */
		if (ip6) {
			lf->is_ip6 = true;
			memcpy(&(lf->src.addr.ip6), &(ip6->ip_src), sizeof(ip6->ip_src));
			memcpy(&(lf->dst.addr.ip6), &(ip6->ip_dst), sizeof(ip6->ip_dst));
		} else {
			lf->is_ip6 = false;
			memcpy(&(lf->src.addr.ip4), &(ip4->ip_src), sizeof(ip4->ip_src));
			memcpy(&(lf->dst.addr.ip4), &(ip4->ip_dst), sizeof(ip4->ip_dst));
		}

		/* transport protocol */
		lf->proto = l4_proto;
		lf->src.port = src_port;
		lf->dst.port = dst_port;

		up = true;
	} else {
		le = (struct lfc_ext *) f->extension;
		lf = &le->lf;

		if (le->done)
			goto skip;

		/*
		 * NOTE: we make our own notion of "packet direction", different than in the libflowmanager. In
		 * libflowcalc, packet direction is 1 if it follows the same direction as the first packet in
		 * the flow (ie. the initial packet), or 0 otherwise. This somehow defines the "upload" (1) and
		 * "download" (0) direction of data transfer, relative to the flow inception.
		 *
		 * The code below gets packet direction as in libflowcalc
		 */
		if (ip6)
			up = (memcmp(&(ip6->ip_src), &(lf->src.addr.ip6), sizeof(ip6->ip_src)) == 0);
		else
			up = (memcmp(&(ip4->ip_src), &(lf->src.addr.ip4), sizeof(ip4->ip_src)) == 0);

		if (up) {
			if (tcp)
				up = (ntohs(tcp->source) == lf->src.port);
			else
				up = (ntohs(udp->source) == lf->src.port);
		}
	}

	/*
	 * time limit
	 */
	if (lfc->t > 0.0 && ts - lf->ts_first > lfc->t) {
		flow_summarize(lfc, le);
		goto skip;
	}

	/*
	 * callbacks
	 */
	struct lfc_plugin *lp;
	void *ptr;

	ptr = le->data;
	tlist_reset(lfc->plugins);
	while ((lp = (struct lfc_plugin *) tlist_iter(lfc->plugins))) {
		if (lp->pktcb)
			lp->pktcb(lfc, lp->pdata, lf, ptr, ts, up, is_new, pkt);
		ptr += lp->datalen;
	}

	lf->ts_last = ts;

	/*
	 * packet limit
	 */
	if (trace_get_payload_length(pkt) > 0)
		lf->n++;

	if (lfc->n > 0 && lf->n == lfc->n)
		flow_summarize(lfc, le);

skip:
	/*
	 * flow maintenance
	 */
	if (tcp)
		lfm_check_tcp_flags(f, tcp, dir, ts);
	lfm_update_flow_expiry_timeout(f, ts);
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
	}
}

void lfc_register(struct lfc *lfc,
	const char *name, int datalen, pkt_cb pktcb, flow_cb flowcb, void *pdata)
{
	struct lfc_plugin *lp;

	lp = (struct lfc_plugin *) mmatic_zalloc(lfc->mm, sizeof *lp);
	lp->name = mmatic_strdup(lfc->mm, name);
	lp->datalen = datalen;
	lp->pktcb = pktcb;
	lp->flowcb = flowcb;
	lp->pdata = pdata;

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
