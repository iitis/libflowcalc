/*
 * example: exemplary program demonstrating libflowcalc
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Licensed under GNU GPL v. 3
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libpjf/main.h>
#include "libflowcalc.h"

struct flow {
	int pkts_up;
	int pkts_down;

	int bytes_up;
	int bytes_down;
};

void pkt(struct lfc *lfc, void *plugin,
	struct lfc_flow *flow, struct lfc_pkt *pkt, void *data)
{
	struct flow *t = data;

	if (pkt->up) {
		t->pkts_up++;
		t->bytes_up += pkt->psize;
	} else {
		t->pkts_down++;
		t->bytes_down += pkt->psize;
	}
}

void flow(struct lfc *lfc, void *plugin, struct lfc_flow *lf, void *data)
{
	struct flow *t = data;

//	printf("# %.6f\n", lf->ts_first);

	if (lf->proto == IPPROTO_UDP)
		printf("UDP ");
	else
		printf("TCP ");

	printf("%s:%d ", inet_ntoa(lf->src.addr.ip4), lf->src.port);
	printf("%s:%d ", inet_ntoa(lf->dst.addr.ip4), lf->dst.port);

	printf("pkts %d/%d ", t->pkts_up, t->pkts_down);
	printf("bytes %d/%d ", t->bytes_up, t->bytes_down);

	printf("\n");
}

int main(int argc, char *argv[])
{
	struct lfc *lfc;

	if (argc < 2) {
		fprintf(stderr, "Usage: example file.pcap [\"filter\"]\n");
		return 1;
	}

	debug = 5;

	lfc = lfc_init();

	lfc_register(lfc, "example", sizeof(struct flow), pkt, flow, NULL);
	lfc_run(lfc, argv[1], argv[2]);

	lfc_deinit(lfc);
	return 0;
}
