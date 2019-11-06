/*
 * Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012,2014-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Netlink operations on TUN/TAP representation of dataplane interface.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>
#include <linux/rtnetlink.h>

#include <czmq.h>
#include "controller.h"

/* Send request and parse response */
static int mnl_talk(tun_t *nl, struct nlmsghdr *nlh)
{
	unsigned portid = mnl_socket_get_portid(nl);
	uint32_t seq = time(NULL);
	char buf[MNL_SOCKET_BUFFER_SIZE];

	nlh->nlmsg_flags |= NLM_F_ACK;
	nlh->nlmsg_seq = seq;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		err("mnl_socket_sendto failed: %s", strerror(errno));
		return -1;
	}

	int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret < 0) {
		err("mnl_socket_recvfrom failed: %s", strerror(errno));
		return -1;
	}

	return mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
}

/* Initialize netlink socket */
tun_t *tun_init(void)
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl)
		return NULL;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(nl);
		return NULL;
	}
	return nl;
}

void tun_destroy(tun_t *tun)
{
	mnl_socket_close(tun);
}


/* Use netlink OPERSTATE message to bring link up/down
 *  is documented in kernel Documentation/networking/operstates.txt
  */
int tun_set_linkstate(tun_t *nl, unsigned int ifindex, unsigned int state)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct ifinfomsg *ifi;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	mnl_attr_put_u8(nlh, IFLA_OPERSTATE, state);

	return mnl_talk(nl, nlh);
}

/* Delete tunnel device attributes */
int tun_delete(tun_t *nl, unsigned int ifindex)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	dbg("tunnel %u delete", ifindex);

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	struct ifinfomsg *ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));

	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	return mnl_talk(nl, nlh);
}

static int tun_set_flags(tun_t *nl, unsigned int ifindex,
			 unsigned long flags, unsigned long changed)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct ifinfomsg *ifi;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_index = ifindex;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_change = changed;
	ifi->ifi_flags = flags;

	return mnl_talk(nl, nlh);
}

/* Callback (from mnl_cb_run) to get flags */
static int process_nl_get_flags(const struct nlmsghdr *nlh, void *arg)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	unsigned long *flags = arg;

	*flags = ifi->ifi_flags;
	return MNL_CB_OK;
}

/* Get tunnel flags */
static int tun_get_flags(tun_t *nl, unsigned int ifindex,
			 unsigned long *flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t seq = time(NULL);
	unsigned portid = mnl_socket_get_portid(nl);

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);

	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlh->nlmsg_seq = seq;

	struct ifinfomsg *ifi;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_index = ifindex;
	ifi->ifi_family = AF_UNSPEC;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		err("get flags(%u)mnl_socket_sendto failed: %s", ifindex,
		    strerror(errno));
		return -1;
	}
	ssize_t len;
	int ret;

	while ((len = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		ret = mnl_cb_run(buf, len, seq, portid,
				 process_nl_get_flags, flags);
		if (ret < MNL_CB_STOP) {
			err("get flags(%u) error: %s", ifindex,
			    strerror(errno));
			return -1;
		}
		if (ret == MNL_CB_STOP)
			break;
	}
	if (len < 0) {
		err("get flags(%u) recv error: %s", ifindex,
		    strerror(errno));
		return -1;
	}
	return 0;
}

/* Check if  interface is admin up */
bool tun_admin_is_up(tun_t *self, unsigned int ifindex)
{
	unsigned long flags = 0;

	if (tun_get_flags(self, ifindex, &flags) < 0) {
		err("tunnel %u unable to get admin state", ifindex);
		return false;
	}
	dbg("tunnel  %u is admin %s", ifindex, (flags & IFF_UP)?"UP":"DOWN");
	if (flags & IFF_UP)
		return true;

	return false;
}

/* Toggle admin status of tunnel */
void tun_admin_toggle(tun_t *self, unsigned int ifindex)
{
	if (tun_set_flags(self, ifindex, ~IFF_UP, IFF_UP) < 0) {
		dbg("tunnel %u toggle-admin DOWN failed %s", ifindex,
		    strerror(errno));
		return;
	}
	if (tun_set_flags(self, ifindex, IFF_UP, IFF_UP) < 0) {
		dbg("tunnel %u toggle-admin UP failed %s", ifindex,
		    strerror(errno));
	}
	dbg("tunnel %u admin state toggled", ifindex);
}

/* Put the tunnel in dormant mode */
int tun_set_dormant(tun_t *nl, const char *ifname)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct ifinfomsg *ifi;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_flags = 0;

	mnl_attr_put_strz(nlh, IFLA_IFNAME, ifname);

	mnl_attr_put_u8(nlh, IFLA_LINKMODE, IF_LINK_MODE_DORMANT);
	/* Default to no carrier, link up happens later */
	mnl_attr_put_u8(nlh, IFLA_OPERSTATE, IF_OPER_DORMANT);

	return mnl_talk(nl, nlh);
}
