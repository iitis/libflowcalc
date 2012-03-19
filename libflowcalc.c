/*
 * flowcalc - calculate IP flows and statistics from PCAP files
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Inspired by lpi_protoident.cc by Shane Alcock, et al.
 */

/* TODO
 * - integrate libflowmanager - see lpi_arff
 * - think if it is possible to move the per_packet and flow_timeout callbacks e.g. to JavaScript,
 *   Python, etc. - maybe it'd wise to make this tool a library
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libtrace.h>
#include <libflowmanager.h>

#include "libflowcalc.h"

/* copied from libprotoident/tools/tools_common.cc */
static int port_get_direction(libtrace_packet_t *pkt)
{
	uint16_t src_port;
	uint16_t dst_port;
	int dir = -1;
	void *l3;
	uint16_t ethertype;
	uint32_t rem;
	libtrace_ip_t *ip = NULL;
	libtrace_ip6_t *ip6 = NULL;
	uint8_t proto;

	src_port = trace_get_source_port(pkt);
	dst_port = trace_get_destination_port(pkt);

	l3 = trace_get_layer3(pkt, &ethertype, &rem);
	if (ethertype == TRACE_ETHERTYPE_IP && rem >= sizeof(libtrace_ip_t)) {
		ip = (libtrace_ip_t *) l3;
		proto = ip->ip_p;
	} else if (ethertype == TRACE_ETHERTYPE_IPV6 && rem >= sizeof(libtrace_ip6_t)) {
		ip6 = (libtrace_ip6_t *) l3;
		proto = ip6->nxt;
	} else {
		return dir;
	}

	if (src_port == dst_port) {
		if (l3 == NULL || rem == 0)
			return dir;

		if (ip)
			return (ip->ip_src.s_addr > ip->ip_dst.s_addr);
		else
			return (memcmp(&(ip6->ip_src), &(ip6->ip_dst), sizeof(struct in6_addr)) >= 0);
	}

	if (trace_get_server_port(proto, src_port, dst_port) == USE_SOURCE)
		return 0;
	else
		return 1;
}

static void expire_flows(struct lfc *lfc, double ts, bool force)
{
	Flow *flow;
	void *data;
	struct lfc_plugin *lp;

	while ((flow = lfm_expire_next_flow(ts, force)) != NULL) {
		data = (void *) flow->extension;

		tlist_reset(lfc->plugins);
		while (lp = (struct lfc_plugin *) tlist_iter(lfc->plugins)) {
			lp->flowcb(lfc, data);
			data += lp->datalen;
		}

		mmatic_free(flow->extension);
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
	 * get some packet info
	 */
	uint16_t l3_type;
	void *l3;
	int dir;
	libtrace_tcp_t *tcp;

	/* skip non-IP */
	l3 = trace_get_layer3(pkt, &l3_type, NULL);
	if (!l3 || (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6))
		return;

	dir = port_get_direction(pkt); // TODO: I dont like it
	tcp = trace_get_tcp(pkt);

	/*
	 * get flow data
	 */
	bool is_new = false;
	Flow *f;
	void *data;

	f = lfm_match_packet_to_flow(pkt, dir, &is_new);
	if (!f)
		return;

	if (is_new) {
		data = mmatic_zalloc(lfc->mm, lfc->datalen_sum);
		f->extension = data;
	} else {
		data = f->extension;
	}

	/*
	 * callbacks
	 */
	struct lfc_plugin *lp;
	tlist_reset(lfc->plugins);
	while (lp = (struct lfc_plugin *) tlist_iter(lfc->plugins)) {
		lp->pktcb(lfc, ts, dir, pkt, data);
		data += lp->datalen;
	}

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
	mmatic_destroy(lfc->mm);
}

void lfc_register(struct lfc *lfc, const char *name, int datalen, pkt_cb pktcb, flow_cb flowcb)
{
	struct lfc_plugin *lp;

	lp = (struct lfc_plugin *) mmatic_zalloc(lfc->mm, sizeof *lp);
	lp->name = mmatic_strdup(lfc->mm, name);
	lp->datalen = datalen;
	lp->pktcb = pktcb;
	lp->flowcb = flowcb;

	tlist_push(lfc->plugins, lp);
	lfc->datalen_sum += datalen;
}

void lfc_run(struct lfc *lfc, const char *uri, const char *filterstring)
{
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter = NULL;

	packet = trace_create_packet();
	if (!packet)
		die("TODO: Creating libtrace packet");

	/***/

	trace = trace_create(uri);
	if (!trace)
		die("TODO: Creating libtrace trace");

	if (trace_is_err(trace)) {
		trace_perror(trace, "Opening trace file");
		die("TODO");
	}

	if (filterstring) {
		filter = trace_create_filter(filterstring);

		if (trace_config(trace, TRACE_OPTION_FILTER, filter) == -1) {
			trace_perror(trace, "Configuring filter");
			die("TODO");
		}
	}

	/***/

	if (trace_start(trace) == -1) {
		trace_perror(trace, "Starting trace");
		die("TODO");
	}

	while (trace_read_packet(trace, packet) > 0)
		per_packet(lfc, packet);

	if (trace_is_err(trace)) {
		trace_perror(trace, "Reading packets");
		die("TODO");
	}

	trace_destroy(trace);
	trace_destroy_packet(packet);
}
