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
 */

#ifndef _LIBFLOWCALC_H_
#define _LIBFLOWCALC_H_

#include <libpjf/lib.h>
#include <libtrace.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lfc;
struct lfc_plugin;
struct lfc_flow;
struct lfc_pkt;
struct lfc_ext;

/****************************************************************************/

/** A per-packet callback function
 * @param lfc    libflowcalc global data
 * @param plugin libflowcalc per-plugin data
 * @param flow   libflowcalc per-flow data
 * @param pkt    libflowcalc per-packet data
 * @param data   plugin flow data
 * @param ts     packet timestamp
 * @param up     if true, this packet flows in the same direction as the
 *               the first packet that created the flow
 * @param is_new true for first packet in flow
 * @param pkt    libtrace packet - access to packet data
 */
typedef void (*pkt_cb)(struct lfc *lfc, void *plugin,
	struct lfc_flow *flow, struct lfc_pkt *pkt, void *data);

/** A callback to call when a flow is closed
 * @param lfc    libflowcalc global data
 * @param plugin libflowcalc per-plugin data
 * @param flow   libflowcalc per-flow data
 * @param data   plugin flow data
 */
typedef void (*flow_cb)(struct lfc *lfc, void *plugin,
	struct lfc_flow *flow, void *data);

/****************************************************************************/

/** Main libflowcalc data structure */
struct lfc {
	mmatic *mm;           /**> memory allocator */
	tlist *plugins;       /**> list of struct lfc_plugin */
	int datalen_sum;      /**> sum of plugins->datalen */
	unsigned int last_id; /**> last assigned lfc_flow::id */

	unsigned long n;      /**> flow packet limit */
	double t;             /**> flow time limit */
	bool noloss;          /**> no flows with TCP packet loss? */
	bool reqclose;        /**> require clean TCP finish? */
};

/** Represents attached plugin */
struct lfc_plugin {
	const char *name;    /**> plugin name */
	int datalen;         /**> flow data size */

	pkt_cb  pktcb;       /**> packet callback function */
	flow_cb flowcb;      /**> flow callback function */
	void *plugin;        /**> plugin data */
};

/** Flow TCP sequence number tracking */
struct lfc_flow_tcp {
	uint32_t next_seq;         /**> expected seq on next packet */
	double lost_ts;            /**> timestamp of last loss */
	tlist *lost_list;          /**> list of lfc_lost */
};

/** Info on lost TCP segment */
struct lfc_tcplost {
	uint32_t from;             /**> from which seq? */
	uint32_t to;               /**> to which seq? */
	double ts;                 /**> timestamp of last update on this range */
};

/** Flow data */
struct lfc_flow {
	unsigned int id;               /**> flow id - sequential number */
	double ts_first;               /**> first packet timestamp */
	double ts_last;                /**> last packet timestamp */
	unsigned long n;               /**> number of packets with payload */

	bool is_ip6;                   /**> is IPv6? */
	uint16_t proto;                /**> transport protocol */

	struct lfc_flow_addr {
		union {
			struct in_addr ip4;
			struct in6_addr ip6;
		} addr;
		uint16_t port;             /**> transport protocol port number */
	} src;                         /**> source address */
	struct lfc_flow_addr dst;      /**> destination address */

	struct lfc_flow_tcp tcp_up;   /**> TCP seq numbers: upload */
	struct lfc_flow_tcp tcp_down; /**> TCP seq numbers: download */

	uint32_t last_id_up;          /**> last IP identification + frag offset - up */
	uint32_t last_id_down;        /**> last IP identification + frag offset - down */
};

/** Packet data */
struct lfc_pkt {
	bool first;                    /**> true if the first packet in flow */
	bool up;                       /**> direction: if true, same as first packet */
	uint32_t id;                   /**> packet identifier (see @2 in libflowcalc.c) */
	bool dup;                      /**> true if immediate duplicate (retransmission) */

	double ts;                     /**> packet timestamp */
	size_t size;                   /**> wire packet length */
	size_t psize;                  /**> wire payload length */

	libtrace_packet_t *ltpkt;      /**> basic libtrace packet data */
	libtrace_ip_t *ip4;            /**> if not NULL, points at full IPv4 header */
	libtrace_ip6_t *ip6;           /**> if not NULL, points at full IPv6 header */
	libtrace_tcp_t *tcp;           /**> if not NULL, points at full TCP header */
	libtrace_udp_t *udp;           /**> if not NULL, points at full UDP header */

	uint16_t sport;                /**> source port */
	uint16_t dport;                /**> destination port */

	void *data;                    /**> if not NULL, points at first byte of payload */
	uint32_t len;                  /**> if >0, holds number of bytes under data */
};

/** Represents libflowmanager extension data */
struct lfc_ext {
	struct lfc_flow lf;            /**> basic flow information */
	bool done;                     /**> true if flow already summarized */
	void *data;                    /**> plugin data */
};

/** libflowcalc options
 * Kind of code duplication, for two reasons:
 *   1) the original header does not work cleanly in C
 *   2) lfc_option may be a buffer for future changes in libflowmanager
 */
enum lfc_option {
	LFC_OPT_TCP_ANYSTART = 1,           /**> LFM_CONFIG_TCP_ANYSTART */
	LFC_OPT_TCP_WAIT,                   /**> LFM_CONFIG_TCP_TIMEWAIT */
	LFC_OPT_PACKET_LIMIT,               /**> flow packet limit (val is unsigned long) */
	LFC_OPT_TIME_LIMIT,                 /**> flow time limit (val is double) */
	LFC_OPT_TCP_NOLOSS,                 /**> skip TCP flows with packet loss */
	LFC_OPT_TCP_REQCLOSE,               /**> skip TCP flows that didnt close via (HALF)CLOSE or RST */
};

/****************************************************************************/

/** Initialize libflowcalc */
struct lfc *lfc_init();

/** Deinitialize libflowcalc */
void lfc_deinit(struct lfc *lfc);

/** Enable given libflowcalc option
 * @param option     option number (see enum lfc_option)
 * @param val        address to option value (optional)
 */
void lfc_enable(struct lfc *lfc, enum lfc_option option, void *val);

/** Register a plugin
 * @param name     plugin name
 * @param datalen  require flow data size
 * @param pktcb    per-packet callback function
 * @param flowcb   flow-close callback function
 * @param plugin   plugin data to pass to pkt_cb and flow_cb
 */
void lfc_register(struct lfc *lfc,
	const char *name, int datalen, pkt_cb pktcb, flow_cb flowcb, void *plugin);

/** Run libflowcalc for given libtrace URI and optional filter
 * @param uri      libtrace URI - see libtrace_create() documentation
 * @param filter   optional BPF filter string
 * @retval true    success
 * @retval false   failed
 */
bool lfc_run(struct lfc *lfc, const char *uri, const char *filter);

#ifdef __cplusplus
}
#endif

#endif
