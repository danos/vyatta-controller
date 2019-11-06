/*
 * Vyatta Controller Snapshot Utility
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>

#include <sys/fcntl.h>
#include <czmq.h>

#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <libmnl/libmnl.h>

#include "vplaned.h"

static const char *progname;
static int debug;

static char *get_request_url(void)
{
	zsock_t *sock = vplaned_connect();
	char *url = NULL;
	int rc;

	if (sock == NULL) {
		fprintf(stderr, "vplaned connect failed\n");
		return NULL;
	}

	rc = vplaned_request_config(sock);
	if (rc < 0)
		fprintf(stderr, "vplaned request failed: '%s'\n",
			strerror(-rc));
	else
		url = vplaned_ctrl_get_request_url(sock, 5 * 1000);

	vplaned_disconnect(&sock);
	return url;
}

static zsock_t *open_controller_dealer()
{
	zsock_t *zsock;
	char *endpoint;

	endpoint = get_request_url();
	if (endpoint == NULL) {
		fprintf(stderr,
			"controller request URL not found\n");
		exit(EXIT_FAILURE);
	}

	zsock = zsock_new_dealer(endpoint);
	if (!zsock) {
		fprintf(stderr, "zsock_new_dealer failed: %s\n",
			strerror(errno));
	}
	free(endpoint);

	return zsock;
}

static void write_msg(zmsg_t *msg, FILE *f)
{
	zframe_t *nlm = zmsg_first(msg);
	void *data = zframe_data(nlm);
	size_t size = zframe_size(nlm);
	size_t sts;

	if (nlm == NULL)
		return;

	data = zframe_data(nlm);
	size = zframe_size(nlm);
	sts = fwrite(data, size, 1, f);
	if (sts != 1)
		perror("fwrite()");
}

static int64_t zmsg_popseqno(zmsg_t *msg)
{
	zframe_t *frame = zmsg_pop(msg);
	int64_t seqno = -1;

	if ((frame != NULL) &&
	    (zframe_size(frame) == sizeof(int64_t)))
		memcpy(&seqno, zframe_data(frame), sizeof(int64_t));

	zframe_destroy(&frame);
	return seqno;
}

static int route_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

/*
 * Since the route topic string no longer includes the associated
 * ifindex, try parsing the netlink object for a matching index.
 *
 *  > 0 - Ignore route object
 *  = 0 - Accept route object
 *  < 0 - Not a route object
 */
static int snapshot_ignore_route(zmsg_t *zmsg, uint32_t ifindex)
{
	const struct nlmsghdr *nlh;
	const struct rtmsg *rtm;
	struct nlattr *tb[RTA_MAX+1] = {};

	nlh = (void *)zframe_data(zmsg_first(zmsg));
	if (nlh == NULL)
		return -1;

	switch (nlh->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		break;
	default:
		return -1;
	}

	rtm = mnl_nlmsg_get_payload(nlh);
	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		return -1;
	}

	if (tb[RTA_OIF])
		if (ifindex == mnl_attr_get_u32(tb[RTA_OIF]))
			return 0;

	if (tb[RTA_MULTIPATH]) {
		void *vnhp;

		mnl_attr_for_each_nested(vnhp, tb[RTA_MULTIPATH]) {
			struct rtnexthop *nhp = vnhp;

			if (ifindex == (uint32_t)nhp->rtnh_ifindex)
				return 0;
		}
	}

	return 1;
}

static bool snapshot_ignore(zmsg_t *zmsg, char *topic, uint32_t ifindex,
			    bool *done)
{
	*done = false;

	if (streq(topic, "THATSALLFOLKS!")) {
		*done = true;
		return true;
	}

	if (ifindex != 0) {
		int ignore;
		uint32_t nl_ifindex;

		ignore = snapshot_ignore_route(zmsg, ifindex);
		if ((ignore < 0) &&
		    (sscanf(topic, "%*s %u ", &nl_ifindex) == 1) && 
		    (nl_ifindex == ifindex))
			ignore = 0;

		return (ignore != 0);
	}

	return false;
}

static int snapshot_collect(zsock_t *zsock, FILE *fp, uint32_t ifindex)
{
	zmsg_t *zmsg;
	bool done = false;
	int sts;

	sts = zsock_send(zsock, "s", "SNAPSHOT-DUMP");
	if (sts < 0) {
		perror("zsock_send()");
		return sts;
	}

	while (!done && (zmsg = zmsg_recv(zsock)) != NULL) {
		char *recvdtopic;
		int64_t seqno;

		if (debug > 1)
			zmsg_dump(zmsg);

		recvdtopic = zmsg_popstr(zmsg);
		seqno = zmsg_popseqno(zmsg);

		if (debug == 1)
			printf("[%"PRIi64"] %s\n", seqno, recvdtopic);

		if (!snapshot_ignore(zmsg, recvdtopic, ifindex, &done))
			write_msg(zmsg, fp);

		free(recvdtopic);
		zmsg_destroy(&zmsg);
	}

	return 0;
}

static int snapshot(const char *path, uint32_t ifindex)
{
	zsock_t *zsock = open_controller_dealer();
	FILE *fp = fopen(path, "w");
	int sts = -1;

	if ((zsock != NULL) && (fp != NULL)) {
		if (debug)
			printf("Writing snapshot records to: %s\n\n", path);

		sts = snapshot_collect(zsock, fp, ifindex);
	} else {
		if (fp == NULL)
			perror("fopen()");

		if (zsock == NULL)
			perror("open_controller_dealer()");
	}

	zsock_destroy(&zsock);
	if (fclose(fp) < 0)
		perror("fclose()");

	return sts;
}

static int dump_netlink(int ifindex)
{
	char tmppath[32];
	int sts;

	memset(tmppath, 0, sizeof(tmppath));
	strcpy(tmppath, "/tmp/snapshot-XXXXXX");
	if (mkstemp(tmppath) < 0) {
		perror("mkstemp()");
		return -1;
	}

	sts = snapshot(tmppath, ifindex);

	if (sts == 0) {
		char cmd[1024];

		snprintf(cmd, sizeof(cmd), "ip monitor all file %s", tmppath);
		sts = system(cmd);
		if (sts < 0)
			perror("system()");
	}

	if (unlink(tmppath) < 0)
		perror("unlink()");

	return sts;
}

static int dump_cstore(void)
{
	zsock_t *zsock = open_controller_dealer();
	zmsg_t *zmsg;
	bool done = false;
	int sts;

	if (zsock == NULL) {
		perror("open_controller_dealer()");
		return -1;
	}

	sts = zsock_send(zsock, "s", "CSTORE-DUMP");
	if (sts < 0) {
		perror("zsock_send()");
		return sts;
	}

	while (!done && (zmsg = zmsg_recv(zsock)) != NULL) {
		char *topic;
		char *cmd;
		int64_t seqno;

		if (debug)
			zmsg_dump(zmsg);

		topic = zmsg_popstr(zmsg);
		seqno = zmsg_popseqno(zmsg);
		cmd = zmsg_popstr(zmsg);
		done = streq(topic, "THATSALLFOLKS!");

		/*
		 * Ignore the topic. In theory it is a separate token,
		 * but in practice it is simply the first two field of
		 * the command itself (see
		 * configdb.c:extract_topic()).
		 */
		if (done)
			printf("[%"PRIi64"] %s\n", seqno, topic);
		else
			printf("[%"PRIi64"] %s\n", seqno, cmd);

		free(cmd);
		free(topic);
		zmsg_destroy(&zmsg);
	}

	zsock_destroy(&zsock);

	return 0;
}

static struct option longopts[] = {
	{ "debug",	no_argument,	   NULL, 'd' },
	{ "help",	no_argument,       NULL, 'h' },
	{ "ifindex",    required_argument, NULL, 'i' },
	{ "cstore",     no_argument,       NULL, 'c' },
	{ NULL, 0, NULL, 0 }
};

static void usage(void)
{
	printf("Usage: %s [OPTION...]\n\n"
	       "vPlaned snapshot.\n\n"
	       "-d, --debug       Include topic information\n"
	       "-c, --cstore      Dump the cstore database\n"
	       "-i, --ifindex     Dump specified ifindex only\n"
	       "-h, --help        Display help and exit\n\n",
	       progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	const char *p;
	int32_t ifindex = 0;
	int flag;
	bool cstore = false;
	int sts;

	/* Preserve name of myself. */
	p = strrchr(argv[0], '/');
	progname = (p ? ++p : argv[0]);

	while ((flag = getopt_long(argc, argv, "dci:",
				   longopts, 0)) != EOF) {
		switch (flag) {
		case 'd':
			debug++;
			break;
		case 'c':
			cstore = true;
			break;
		case 'i':
			ifindex = strtol(optarg, NULL, 0);
			if (ifindex <= 0) {
				fprintf(stderr,
					"invalid ifindex value: %i\n", ifindex);
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (cstore) {
		if ((ifindex != 0) && debug)
			printf("ignoring ifindex when collecting cstore "
			       "messages\n\n");

		sts = dump_cstore();
	} else
		sts = dump_netlink(ifindex);

	if (sts < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
