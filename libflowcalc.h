#ifndef _LIBFLOWCALC_H_
#define _LIBFLOWCALC_H_

#include <libpjf/lib.h>
#include <libtrace.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lfc;

/****************************************************************************/

/** A per-packet callback function
 * @param ts     packet timestamp
 * @param dir    packet direction: 0 (client-to-server) or 1 (server-to-client)
 * @param pkt    libtrace packet - access to packet data
 * @param data   flow data
 */
typedef void (*pkt_cb)(struct lfc *lfc, double ts, int dir, libtrace_packet_t *pkt, void *data);

/** A callback to call when a flow is closed
 * @param data   flow data
 */
typedef void (*flow_cb)(struct lfc *lfc, void *data);

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
 */
void lfc_register(struct lfc *lfc, const char *name, int datalen, pkt_cb pktcb, flow_cb flowcb);

/** Run libflowcalc for given libtrace URI and optional filter
 * @param uri      libtrace URI - see libtrace_create() documentation
 * @param filter   optional BPF filter string
 */
void lfc_run(struct lfc *lfc, const char *uri, const char *filter);

#ifdef __cplusplus
}
#endif

#endif
