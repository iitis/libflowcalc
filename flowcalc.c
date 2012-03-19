#include <libpjf/main.h>
#include "libflowcalc.h"

struct test {
	int init_dir;
	int counter;
};

void pkt(struct lfc *lfc, double ts, int dir, libtrace_packet_t *pkt, void *data)
{
	struct test *t = data;

	if (t->counter == 0)
		t->init_dir = dir;

	t->counter++;
}

void flow(struct lfc *lfc, void *data)
{
	struct test *t = data;

	printf("init_dir=%d counter:%d\n", t->init_dir, t->counter);
}

int main(int argc, char *argv[])
{
	struct lfc *lfc;

	debug = 5;

	lfc = lfc_init();

	lfc_register(lfc, "test", sizeof(struct test), pkt, flow);
	lfc_run(lfc, argv[1], NULL);

	lfc_deinit(lfc);
	return 0;
}
