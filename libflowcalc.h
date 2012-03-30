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
struct lfc_ext;

/****************************************************************************/

/** A per-packet callback function
 * @param pdata  plugin data
 * @param ts     packet timestamp
 * @param up     if true, this packet flows in the same direction as the
 *               the first packet that created the flow
 * @param is_new true for first packet in flow
 * @param pkt    libtrace packet - access to packet data
 * @param data   flow data
 */
typedef void (*pkt_cb)(struct lfc *lfc, void *pdata,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt, void *data);

/** A callback to call when a flow is closed
 * @param pdata  plugin data
 * @param lf     basic flow information
 * @param data   flow data
 */
typedef void (*flow_cb)(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data);

/****************************************************************************/

/** Main libflowcalc data structure */
struct lfc {
	mmatic *mm;          /**> memory allocator */
	tlist *plugins;      /**> list of struct lfc_plugin */
	int datalen_sum;     /**> sum of plugins->datalen */
};

/** Represents attached plugin */
struct lfc_plugin {
	const char *name;    /**> plugin name */
	int datalen;         /**> flow data size */

	pkt_cb  pktcb;       /**> packet callback function */
	flow_cb flowcb;      /**> flow callback function */
	void *pdata;         /**> plugin data */
};

/** Flow data */
struct lfc_flow {
	double ts_first;               /**> first packet timestamp */
	double ts_last;                /**> last packet timestamp */

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
};

/** Represents libflowmanager extension data */
struct lfc_ext {
	struct lfc_flow lf;            /**> basic flow information */
	void *data;                    /**> plugin data */
};

/****************************************************************************/

/** Initialize libflowcalc */
struct lfc *lfc_init();

/** Deinitialize libflowcalc */
void lfc_deinit(struct lfc *lfc);

/** Register a plugin
 * @param name     plugin name
 * @param datalen  require flow data size
 * @param pktcb    per-packet callback function
 * @param flowcb   flow-close callback function
 * @param pdata    plugin data to pass to pkt_cb and flow_cb
 */
void lfc_register(struct lfc *lfc,
	const char *name, int datalen, pkt_cb pktcb, flow_cb flowcb, void *pdata);

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
