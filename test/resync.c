/*
 * Publisher standalone test
 *
 * To use:
 *   testclient tcp://127.0.0.1:5569 tcp://127.0.0.1:5568
 *
 * Will ask for snapshot and then monitor for changes
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/if_link.h>

#include <czmq.h>
#include <libmnl/libmnl.h>

#include "publisher.h"

int debug;

static void usage(void)
{
	fprintf(stderr, "Usage: nlserver URL interface...\n");
	exit(1);
}

void __panic(const char *funcname, const char *fmt, ...)
{
	va_list ap;
	const char *err = errno ? strerror(errno) : NULL;
	char line[1024];

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	fprintf(stderr, "PANIC in %s()\n", funcname);
	if (err)
		fprintf(stderr, "%s: %s\n", line, err);
	else
		fprintf(stderr, "%s\n", line);
	exit(1);
}

int main(int argc, char *argv [])
{
	char filter[128];

	if (strcmp(argv[1], "-d") == 0) {
		++debug;
		--argc, ++argv;
	}

	if (argc < 3)
		usage();

	zsock_t *snapshot = zsock_new_dealer(*++argv);
	if (!snapshot)
		panic("zsock_new_dealer: %s", *argv);

	zsock_t *subscriber = zsock_new_sub(*++argv, "");
	if (!subscriber)
		panic("zsock_new_sub %s", *argv);

	fprintf(stderr, "getting snapshot\n");
	/* Get snapshot */
	zstr_send(snapshot, "HITME");
	uint64_t sequence = 0;
	while (1) {
		nlmsg_t *nmsg = nlmsg_recv(snapshot);
		if (!nmsg)
			break;

		sequence = nlmsg_seqno(nmsg);
		if (streq(nlmsg_key(nmsg), "end"))
			break;

		nlmsg_dump(NULL, nmsg);
		nlmsg_free(nmsg);
	}

	/* Listen for and decode netlink messages */
	fprintf(stderr, "waiting for messages...\n");
	while (!zctx_interrupted) {
		nlmsg_t *nmsg = nlmsg_recv(subscriber);
		if (!nmsg)
			break;

		uint64_t this = nlmsg_seqno(nmsg);
		if (this > sequence) {
			sequence = this;
			nlmsg_dump(NULL, nmsg);
		} else
			fprintf(stderr, ".");
		nlmsg_free(nmsg);
	}

	zsock_destroy(&snapshot);
	zsock_destroy(&subscriber);

	return 0;
}
