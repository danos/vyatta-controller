/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * bfdtest - Create/update/delete BFD sessions in the dataplane via the
 *           cstore and monitor state updates via the event socket.
 *
 * Example usage:
 *
 * Create a session with source 1.2.3.4, dest 1.2.3.5 via interface dp0s2
 * and monitor for state updates:
 *
 * bfdtest -s 1.2.3.4 -d 1.2.3.5 -i dp0s2 -m
 *
 * Delete the above session:
 *
 * bfdtest -s 1.2.3.4 -d 1.2.3.5 -i dp0s2 -x
 *
 * Create a session, specifying client id:
 *
 * bfdtest -s 1.2.3.4 -d 1.2.3.5 -i dp0s2 -c 2
 *
 * Monitor state updates for current sessions:
 *
 * bfdtest -m
 */

#include <getopt.h>
#include <net/if.h>
#include <czmq.h>

#include "vplaned.h"

/* Defaults */
#define TX_DESIRED 300000
#define RX_REQUIRED 300000
#define DET_MULT 3
#define NO_ADMIN_DOWN 0
#define CLIENT_ID 1
#define VRF_DEFAULT_ID 1

enum bfd_state {
	BFD_STATE_ADMIN_DOWN = 0,
	BFD_STATE_DOWN       = 1,
	BFD_STATE_INIT       = 2,
	BFD_STATE_UP         = 3,
	BFD_NUM_STATES
};

static const char *bfd_state_strings[BFD_NUM_STATES] = {
	"Admin Down",
	"Down",
	"Init",
	"Up"
};

static const char *bfd_state_name(enum bfd_state state)
{
	if (state >= BFD_NUM_STATES)
		return "";

	return bfd_state_strings[state];
}

static struct option longopts[] = {
	{ "source", required_argument, NULL, 's' },
	{ "dest", required_argument, NULL, 'd' },
	{ "vrf", required_argument, NULL, 'v' },
	{ "interface", required_argument, NULL, 'i' },
	{ "client-id", required_argument, NULL, 'c' },
	{ "password", required_argument, NULL, 'p' },
	{ "monitor", no_argument, NULL, 'm' },
	{ "admin-down", no_argument, NULL, 'a' },
	{ "help", no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};

static const char *progname;

static void usage(void)
{
	printf("Usage: %s [OPTION...]\n\n"
	       "vPlaned BFD test.\n\n"
	       "-s, --source     Session source address (required)\n"
	       "-d, --dest       Session dest address (required)\n"
	       "-v, --vrf        VRF id\n"
	       "-i, --interface  Interface (single hop)\n"
	       "-c, --client-id  Client id\n"
	       "-t, --tx-des     Min tx desired interval (ms)\n"
	       "-r, --rx-req     Min rx required interval (ms)\n"
	       "-u, --det-mult   Detect multiplier\n"
	       "-p, --password   Simple authentication password\n"
	       "-m, --monitor    Monitor state update events\n"
	       "-a, --admin-down Hold session down\n"
	       "-x, --delete     Delete the session\n"
	       "-h, --help       Display help and exit\n\n",
	       progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	uint32_t ifi = 0;
	uint32_t clid = CLIENT_ID;
	uint32_t vrfid = VRF_DEFAULT_ID;
	uint32_t admin_down = NO_ADMIN_DOWN;
	uint32_t tx_des = TX_DESIRED;
	uint32_t rx_req = RX_REQUIRED;
	uint32_t det_mult = DET_MULT;
	int flag;
	bool monitor = false;
	char *src = NULL, *dest = NULL, *intf = NULL, *passwd = NULL;
	char cstore_key[100];
	char cstore_cmd[100];
	char auth[30] = {0};
	zsock_t *sub;
	bool add = false;
	bool del = false;

	progname = argv[0];

	while ((flag = getopt_long(argc, argv, "ac:s:d:v:i:p:mx",
				   longopts, 0)) != EOF) {
		switch (flag) {
		case 'a':
			admin_down = 1;
			break;
		case 'c':
			clid = atoi(optarg);
			break;
		case 'd':
			dest = optarg;
			break;
		case 's':
			src = optarg;
			break;
		case 'v':
			vrfid = atoi(optarg);
			break;
		case 't':
			tx_des = atoi(optarg) * 1000;
			break;
		case 'r':
			rx_req = atoi(optarg) * 1000;
			break;
		case 'u':
			det_mult = atoi(optarg);
			break;
		case 'i':
			intf = optarg;
			ifi = if_nametoindex(intf);
			if (!ifi) {
				printf("Interface %s not found\n", intf);
				exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			passwd = optarg;
			break;
		case 'm':
			monitor = true;
			break;
		case 'x':
			del = true;
			add = false;
			break;
		default:
			usage();
		}
	}

	/* If src and dest addrs given, assume session add/update */
	if (src && dest && !add && !del)
		add = true;

	/* If adding or deleting, must have src/dest */
	if ((add || del) && (!src || !dest))
		usage();

	if (add || del)
		printf("%s%s session %u from %s to %s, "
		       "via intf %s(%d) with passwd %s\n",
		       add ? "Update" : "", del ? "Delete" : "",
		       clid, src, dest,
		       intf ? intf : "none",
		       ifi,
		       passwd ? passwd : "none");

	if (monitor)
		sub = vplaned_event_subscribe("BFD");

	if (add || del)
		snprintf(cstore_key, sizeof(cstore_key),
			 "bfdsess %u %u %s %s", ifi, vrfid, src, dest);
	if (add) {
		if (passwd)
			snprintf(auth, sizeof(auth),
				 " 1 %zd 1 %s\n", strlen(passwd), passwd);

		snprintf(cstore_cmd, sizeof(cstore_cmd),
			 "bfd add %u %u %s %s %u %u %u %u %u%s",
			 ifi, vrfid, src, dest,
			 admin_down, clid,
			 tx_des, rx_req, det_mult,
			 auth);
	}

	if (del)
		snprintf(cstore_cmd, sizeof(cstore_cmd),
			 "bfd del %u %u %s %s %u",
			 ifi, vrfid, src, dest, admin_down);

	if (add || del)
		if (vplaned_cstore_store(cstore_key, cstore_cmd, NULL,
					 add ? "SET" : "DELETE", 0) != 0) {
			printf("Failed to update session\n");
			return EXIT_FAILURE;
		}

	if (monitor) {
		printf("Monitoring ...\n\n");
		while (1) {
			zmsg_t *msg = zmsg_recv(sub);
			zframe_t *frame;
			uint32_t client;
			uint32_t state;
			char *event_type;

			if (zsys_interrupted)
				break;

			if (zmsg_size(msg) != 3) {
				printf("Incomplete message from dp\n");
				break;
			}

			event_type = zmsg_popstr(msg);

			frame = zmsg_pop(msg);
			client = *(uint32_t *)zframe_data(frame);
			zframe_destroy(&frame);

			frame = zmsg_pop(msg);
			state = *(uint32_t *)zframe_data(frame);
			zframe_destroy(&frame);

			printf("%s Client %2x State %4s\n", event_type, client,
			       bfd_state_name(state));

			free(event_type);
			zmsg_destroy(&msg);
		}
		vplaned_event_disconnect(&sub);
	}

	return EXIT_SUCCESS;
}
