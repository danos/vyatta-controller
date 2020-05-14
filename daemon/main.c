/*
 * Dataplane controller daemon
 *
 * Copyright (c) 2017-2020 AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/genetlink.h>
#include <linux/l2tp.h>
#include <linux/if_team.h>
#include <linux/netconf.h>
#include <linux/if.h>

#include <zmq.h>
#include <czmq.h>
#include <libmnl/libmnl.h>
#include "json.h"
#include <ini.h>

#include "team.h"
#include "controller.h"
#include "mrtstat.h"
#include "parser.h"
#include "vplane.h"
#include "compat.h"
#include "protobuf.h"
#include "configstore.h"
#include "configdb.h"
#include "configcmd.h"

#define NL_MAXMSGS	64
#define NL_MAXMSGSIZE	__nl_maxmsgsize		/* see include/linux/netlink.h */
#define NL_RCVBUFSIZE	(256*1024*1024)
#define ZMQ_IPC_HWM	(0)

#define MNL_CB_VYCONTINUE 9999

static const char *progname;
static const char *pidfile;
static const char *logfile;
static const char *cfgfile = "/etc/vyatta/controller.conf";
static const char *interface_cfg = "/etc/vyatta/interface.conf";
static const char version[] = "vPlane Controller version 1.0";
static uid_t uid;
static gid_t gid;
static bool daemonmode;
static bool kernel_route;
static unsigned int dump_seq;

#define FMLY_L2TP	0
#define FMLY_TEAM	1

static struct {
	int family_id;
	int grp_id;
	bool changed;
} genl_fmly[] = {
	{ .family_id = -1, .grp_id = -1, .changed = false },
	{ .family_id = -1, .grp_id = -1, .changed = false },
};

static const char *team_grp_name = TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME;

/* Communication zmq sockets */
static zsock_t *request_ipc;
static zsock_t *publisher;
static zactor_t *auth_actor;

static uint64_t msg_seqno;

static bool reconfigure_required;

static long __nl_maxmsgsize;

/* Listen for netlink events about interfaces, addresses and routes */
static const unsigned non_route_groups[] = {
       RTNLGRP_LINK,
       RTNLGRP_NOTIFY,
       RTNLGRP_NEIGH,
       RTNLGRP_TC,
       RTNLGRP_IPV4_IFADDR,
       RTNLGRP_IPV4_MROUTE,
       RTNLGRP_IPV4_RULE,
       RTNLGRP_IPV6_IFADDR,
       RTNLGRP_IPV6_MROUTE,
       RTNLGRP_IPV6_IFINFO,
       RTNLGRP_IPV6_PREFIX,
       RTNLGRP_IPV6_RULE,
       RTNLGRP_IPV4_NETCONF,
       RTNLGRP_IPV6_NETCONF,
#ifdef RTNLGRP_MPLS_NETCONF
       RTNLGRP_MPLS_NETCONF,
#endif /* RTNLGRP_MPLS_NETCONF */
};

static const unsigned all_groups[] = {
	RTNLGRP_LINK,
	RTNLGRP_NOTIFY,
	RTNLGRP_NEIGH,
	RTNLGRP_TC,
	RTNLGRP_IPV4_IFADDR,
	RTNLGRP_IPV4_MROUTE,
	RTNLGRP_IPV4_ROUTE,
	RTNLGRP_IPV4_RULE,
	RTNLGRP_IPV6_IFADDR,
	RTNLGRP_IPV6_MROUTE,
	RTNLGRP_IPV6_ROUTE,
	RTNLGRP_IPV6_IFINFO,
	RTNLGRP_IPV6_PREFIX,
	RTNLGRP_IPV6_RULE,
	RTNLGRP_IPV4_NETCONF,
	RTNLGRP_IPV6_NETCONF,
#ifdef RTNLGRP_MPLS_ROUTE
	RTNLGRP_MPLS_ROUTE,
#endif /* RTNLGRP_MPLS_ROUTE */
#ifdef RTNLGRP_MPLS_NETCONF
	RTNLGRP_MPLS_NETCONF,
#endif /* RTNLGRP_MPLS_NETCONF */
};

/* Where should we propagate the message to */
enum propagate_option {
	PROPAGATE_SNAPSHOT = 1,
	PROPAGATE_PUBLISH,
	PROPAGATE_BOTH,
};

static const char *propagate_option_string(enum propagate_option option)
{
	switch (option) {
	case PROPAGATE_SNAPSHOT: return "snap";
	case PROPAGATE_PUBLISH:  return "pub";
	case PROPAGATE_BOTH:     return "snap & pub";
	default:                 return "unknown";
	}
}

/* Convert from list of indices to mask for dump request */
static unsigned rtnl_groupmsk(const unsigned *groups, unsigned size)
{
	unsigned int i, msk = 0;

	for (i = 0; i < size; i++)
		msk |= 1u << (groups[i] - 1);

	return msk;
}

static void nlmsg_log(const nlmsg_t *nmsg, enum propagate_option option,
		      const char *nmsgtype)
{
	char prefix[64];

	snprintf(prefix, sizeof(prefix), "%s %s",
		 propagate_option_string(option), nmsgtype);

	nlmsg_dump(prefix, nmsg);
}

static void __nl_propagate(nlmsg_t *nmsg, enum propagate_option option,
			   const char *nmsgtype)
{
	if (debug)
		nlmsg_log(nmsg, option, nmsgtype);

	if (PROPAGATE_SNAPSHOT == option || PROPAGATE_BOTH == option)
		/* send copy to snapshot service */
		nlmsg_send(nlmsg_copy(nmsg), request_ipc);

	if (PROPAGATE_PUBLISH == option || PROPAGATE_BOTH == option)
		/* and publish original */
		nlmsg_send(nmsg, publisher);
}

void nl_propagate_nlmsg(nlmsg_t *nmsg)
{
	__nl_propagate(nmsg, PROPAGATE_BOTH,
		       nlmsg_type_name_rtnl(nlmsg_data(nmsg)));
}

/* Send topic and netlink message to snapshot service and publish */
static void nl_propagate(const char *topic, const struct nlmsghdr *nlh,
			 const enum propagate_option option,
			 const char *nmsgtype)
{
	nlmsg_t *nmsg;

	nmsg = nlmsg_new(topic, ++msg_seqno, nlh, nlh->nlmsg_len);
	if (!nmsg)
		panic("can't allocate memory for msg");

	__nl_propagate(nmsg, option, nmsgtype);
}

static void monitor_netlink(const struct nlmsghdr *nlh)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFLA_MAX + 1] = { NULL };

	if (nlh->nlmsg_type != RTM_DELLINK)
		return;

	if (mnl_attr_parse(nlh, sizeof(*ifi), link_attr, tb) != MNL_CB_OK)
		return;

	if (!tb[IFLA_IFNAME])
		return;

	const char *ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);

	delete_intf_coll(ifname);

	del_if_stats(ifname);
}

/* Callback (from mnl_cb_run) per netlink message */
static int process_netlink_rtnl(const struct nlmsghdr *nlh, void *arg)
{
	char topic[1024];
	char *ifname = NULL;
	bool publish_intf_cmds = false;
	uint32_t ifindex = 0;

	if (nl_generate_topic(nlh, topic, sizeof(topic), &ifindex) < 0)
		return MNL_CB_OK;	/* unknown type */

	/* Remember new interface to do netconf poll. */
	if (arg && nlh->nlmsg_type == RTM_NEWLINK) {
		const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);

		if ((ifi->ifi_change & IFF_UP) && (ifi->ifi_flags & IFF_UP)) {
			unsigned long if_index = ifi->ifi_index;

			zlist_append(arg, (void *)if_index);
		}

		struct nlattr *tb[IFLA_MAX + 1] = { NULL };

		if (mnl_attr_parse(nlh, sizeof(*ifi), link_attr, tb) ==
		    MNL_CB_OK &&
		    tb[IFLA_IFNAME]) {
			ifname = (char *)mnl_attr_get_str(tb[IFLA_IFNAME]);
			publish_intf_cmds = insert_intf_coll(ifname);
		}
	}

	bool propagate = true;
	bool propagate_pending = false;

	if (ifindex != 0)
		switch (nlh->nlmsg_type) {
		case RTM_NEWLINK:
			propagate_pending = nlmsg_ifindex_add(ifindex, ifname);
			break;
		case RTM_DELLINK:
			nlmsg_ifindex_del(ifindex);
			break;
		default:
			if (!nlmsg_ifindex_lookup(ifindex))
				propagate = false;
			break;
		}

	/*
	 * If we've just acquired a new interface, publish any pending
	 * messages (NEWNETCONF & NEWADDR arrive before the associated
	 * NEWLINK). Alternatively if we have no knowledge of the
	 * associated interface, save the message for later.
	 */
	if (!propagate)
		nlmsg_pending_add(topic, nlh, ifindex);
	else {
		nl_propagate(topic, nlh, PROPAGATE_BOTH,
			     nlmsg_type_name_rtnl(nlh));

		if (propagate_pending)
			nlmsg_pending_propagate(ifindex, &msg_seqno);
	}

	monitor_netlink(nlh);

	/* dispatch commands associated with this interface */
	if (ifname && publish_intf_cmds)
		send_intf_cmds(ifname, &msg_seqno);

	return MNL_CB_OK;
}

/* Callback (from mnl_cb_run) per netlink message
 * Since RTNL and XFRM netlink types overlap this is needed.
 */
static int process_netlink_xfrm(const struct nlmsghdr *nlh,
				void *arg __unused)
{
	char topic[1024];
	bool snapshot;

	if (nl_generate_topic_xfrm(nlh, topic, sizeof(topic), &snapshot) < 0)
		return MNL_CB_OK;	/* unknown type */

	nl_propagate(topic, nlh,
		     snapshot ? PROPAGATE_BOTH : PROPAGATE_PUBLISH,
		     "XFRM");

	return MNL_CB_OK;
}

static int genetlink_attr_family(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int genetlink_attr_mcast_grp(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MCAST_GRP_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int genetlink_find_mcast_grp(struct nlattr *tb_mcast,
				    const char *grpname, int *grp_id)
{
	struct nlattr *mtb[CTRL_ATTR_MCAST_GRP_MAX+1] = {NULL};

	if (mnl_attr_parse_nested(tb_mcast,
				  genetlink_attr_mcast_grp,
				  mtb) != MNL_CB_OK) {
		err("mnl_attr_parse_nested: %s", strerror(errno));
		return MNL_CB_ERROR;
	}

	if (mnl_attr_parse_nested(mtb[CTRL_ATTR_MCAST_GRP_NAME],
				  genetlink_attr_mcast_grp, mtb) != MNL_CB_OK) {
		err("mnl_attr_parse_nested: %s", strerror(errno));
		return MNL_CB_ERROR;
	}

	if (grpname == NULL ||
	    !strcmp(mnl_attr_get_str(mtb[CTRL_ATTR_MCAST_GRP_NAME]), grpname))
		*grp_id = mnl_attr_get_u32(mtb[CTRL_ATTR_MCAST_GRP_ID]);
	else {
		err("unable to find genetlink multicast group");
		return MNL_CB_ERROR;
	}

	return MNL_CB_OK;
}

/* Callback per l2tp get_tunnel message. */
static int process_genetlink_l2tp(const struct nlmsghdr *nlh,
				  void *arg __unused)
{
	char topic[1024];
	int ret;

	ret = nl_generate_topic_l2tp(nlh, topic, sizeof(topic));
	if (ret >= 0)
		nl_propagate(topic, nlh, PROPAGATE_BOTH, "L2TP");

	return ret;
}

/* Callback per team message. */
static int process_genetlink_team(const struct nlmsghdr *nlh,
				  void *arg __unused)
{
	int ret;
	struct team_msg_desc desc;

	memset(&desc, 0, sizeof(desc));

	ret = process_genetlink_teamcmd(nlh, &desc);
	if (ret < 0)
		goto out;

	if (desc.infolist == NULL)
		goto out;

	struct team_option_info *opt;

	for (opt = zlist_first(desc.infolist);
	     opt;
	     opt = zlist_next(desc.infolist))
		nl_propagate(opt->topic, opt->nlh, PROPAGATE_BOTH, "TEAM");

out:
	team_msg_data_free(&desc);
	return ret;
}

/* Callback per genetlink get_family message. */
static int process_genetlink_family(const struct nlmsghdr *nlh,
				    void *arg __unused)
{
	struct genlmsghdr *ghdr = NLMSG_DATA(nlh);
	struct nlattr *tb[CTRL_ATTR_MAX+1] = { NULL };
	const char *family_name;
	const char *group;
	int index;

	if (mnl_attr_parse(nlh, GENL_HDRLEN, genetlink_attr_family, tb)
	    != MNL_CB_OK) {
		notice("unparseable genl family attributes\n");
		return MNL_CB_ERROR;
	}

	if (!tb[CTRL_ATTR_FAMILY_NAME] || !tb[CTRL_ATTR_FAMILY_ID]) {
		notice("can't get family id\n");
		return MNL_CB_ERROR;
	}

	family_name = mnl_attr_get_str(tb[CTRL_ATTR_FAMILY_NAME]);
	if (streq(family_name, TEAM_GENL_NAME)) {
		group = team_grp_name;
		index = FMLY_TEAM;
	} else if (streq(family_name, L2TP_GENL_NAME))  {
		group = NULL;
		index = FMLY_L2TP;
	} else
		return MNL_CB_VYCONTINUE;

	int family_id = -1;
	int grp_id = -1;

	if (ghdr->cmd == CTRL_CMD_NEWFAMILY) {
		if (genl_fmly[index].family_id > 0)
			return MNL_CB_OK;

		family_id = mnl_attr_get_u32(tb[CTRL_ATTR_FAMILY_ID]);
		grp_id = 0;

		if (tb[CTRL_ATTR_MCAST_GROUPS]) {
			if (genetlink_find_mcast_grp(tb[CTRL_ATTR_MCAST_GROUPS],
						     group,
						     &grp_id)
			    != MNL_CB_OK) {
				return MNL_CB_ERROR;
			}
		}
	}

	genl_fmly[index].family_id = family_id;
	genl_fmly[index].grp_id = grp_id;
	genl_fmly[index].changed = true;

	dbg("%s family id %d %d", family_name, family_id, grp_id);

	return MNL_CB_OK;
}

static void l2tp_listener(struct mnl_socket *l2tp_nl)
{
	char rcvbuf[NL_MAXMSGSIZE];
	ssize_t len = mnl_socket_recvfrom(l2tp_nl, rcvbuf, NL_MAXMSGSIZE);

	if (len <= 0) {
		notice("mnl_socket_recvfrom l2tp: %s", strerror(errno));
		return;
	}

	int ret = mnl_cb_run(rcvbuf, len, 0, 0,
			     process_genetlink_l2tp, NULL);

	if (ret < MNL_CB_STOP) {
		notice("error parsing l2tp netlink message : %s",
		       strerror(errno));
		if (debug)
			mnl_nlmsg_fprintf(stdout, rcvbuf, len, len);
	}
}

static void team_listener(struct mnl_socket *team_nl)
{
	char rcvbuf[NL_MAXMSGSIZE];
	ssize_t len = mnl_socket_recvfrom(team_nl, rcvbuf, NL_MAXMSGSIZE);

	if (len <= 0) {
		notice("mnl_socket_recvfrom team: %s", strerror(errno));
		return;
	}

	int ret = mnl_cb_run(rcvbuf, len, 0, 0,
			     process_genetlink_team, NULL);

	if (ret < MNL_CB_STOP) {
		notice("error parsing team netlink message : %s",
		       strerror(errno));
		if (debug)
			mnl_nlmsg_fprintf(stdout, rcvbuf, len, len);
	}
}

/* Callback (from mnl_cb_run) per netlink message
 * Use this function once after the team genetlink family is added to
 * ensure that we haven't missed any team notifications while binding
 * the team netlink socket to the multicast group.  For each team master
 * that we find, ask for it's port list and options.
 */
static int process_netlink_rtnl_teamonly(const struct nlmsghdr *nlh, void *arg)
{
	if (nlh->nlmsg_type != RTM_NEWLINK)
		goto out;

	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);

	if (ifi->ifi_change == 0) {
		unsigned long if_index = ifi->ifi_index;
		struct nlattr *tb[IFLA_MAX + 1] = { NULL };

		if (mnl_attr_parse(nlh, sizeof(struct ifinfomsg), link_attr, tb)
		    != MNL_CB_OK) {
			notice("netlink: can't parse link attributes: %s",
			       strerror(errno));
			return MNL_CB_ERROR;
		}

		if (!tb[IFLA_LINKINFO])
			goto out;

		struct nlattr *linkinfo[IFLA_INFO_MAX+1] = { NULL };

		if (mnl_attr_parse_nested(tb[IFLA_LINKINFO],
					  linkinfo_attr,
					  linkinfo) != MNL_CB_OK) {
			goto out;
		}

		if (!linkinfo[IFLA_INFO_KIND])
			goto out;

		const char *kind = mnl_attr_get_str(linkinfo[IFLA_INFO_KIND]);

		if (strcmp(kind, "team"))
			goto out;

		if (team_query_portlist(arg, genl_fmly[FMLY_TEAM].family_id,
					if_index, 0) < 0) {
			err("team_query_portlist");
			goto out;
		}

		if (team_query_options(arg, genl_fmly[FMLY_TEAM].family_id,
				       if_index, 1) < 0) {
			err("team_query_options");
			goto out;
		}
	}

out:
	return MNL_CB_OK;
}

/* Publish command message to dataplane */
void publish_cmd(const char *topic, uint64_t seqno, const char *line, bool bin)
{
	zmsg_t *msg = zmsg_new();

	if (bin) {
		int bin_len;
		char *line_copy = strdup(line);
		if (!line_copy)
			panic("Memory allocation failure on line copy");

		if (extract_protobuf((char **)&line_copy, &bin_len) != 0) {
			err("Failure to publish binary");
			free(line_copy);
			return;
		}
		zmsg_addstr(msg, PROTOBUF_TOPIC);
		zmsg_addmem(msg, &seqno, sizeof(seqno));
		zmsg_addmem(msg, line_copy, bin_len);
		dbg("Publish binary [%"PRIu64"] '%s', (%d)", seqno,
		    PROTOBUF_TOPIC, bin_len);
		free(line_copy);
	} else {
		zmsg_addstr(msg, topic);
		zmsg_addmem(msg, &seqno, sizeof(seqno));
		zmsg_addstr(msg, line);
		dbg("Publish [%"PRIu64"] '%s', '%s'", seqno, topic, line);
	}
	zmsg_send(&msg, publisher);
}

/* Process configuration requests to controller
 * from local IPC port.
 */
static void process_config(zsock_t *sock, const char *line)
{
	int rc = config_cmd(line);
	const char *reply = rc < 0 ? "ERROR" : "OK";

	/* Send response to client */
	zstr_send(sock, reply);

	/* Need to do this because the dataplane expects to find
	   the command class as the first matching string in the
	   body of the command
	*/
	send_cmds(&msg_seqno);
}

/* Process generated configuration */
int process_gen_config(const char *line)
{
	int rc = config_cmd(line);

	send_cmds(&msg_seqno);

	return rc;
}

static void cmd_help(zsock_t *sock)
{
	zmsg_t *msg = zmsg_new();

	zmsg_addstr(msg, "OK");
	zmsg_addstrf(msg, "%s\n"
		   "Possible commands:\n"
		   "   npf         npf firewall commands\n"
		   "   qos         QoS commands\n"
		   "   l2tpeth     l2tp commands\n"
		   "   ecmp        ecmp mode commands\n",
		   version);
	zmsg_send(&msg, sock);
}

/* Callback that handles commands received on the ipc port
   For these:
     1. Topic string generated
     2. Parse command and get result
     3. Publish changes to dataplane
  */
static void cmd_proxy(zsock_t *sock)
{
	zmsg_t *msg = zmsg_recv(sock);

	if (!msg)
		return;	/* interrupted */

	char *line = zmsg_popstr(msg);
	if (!line)
		goto err;

	dbg("cmd [ %s ]", line);

	if (strcmp(line, "help") == 0)
		cmd_help(sock);
	else
		process_config(sock, line);

	free(line);

 err:
	zmsg_destroy(&msg);
}

/* Send a separate request to get the interface's netconf info. */
static void get_netconf(struct mnl_socket *nl, int ifindex, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	unsigned portid = mnl_socket_get_portid(nl);
	ssize_t len;

	nlh->nlmsg_type = RTM_GETNETCONF;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++dump_seq;

	struct netconfmsg *ncm
		= mnl_nlmsg_put_extra_header(nlh, sizeof(struct netconfmsg));
	ncm->ncm_family = family;
	mnl_attr_put_u32(nlh, NETCONFA_IFINDEX, ifindex);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		panic("mnl_socket_sendto netconf");

	while ((len = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		int ret = mnl_cb_run(buf, len, dump_seq, portid,
				     process_netlink_rtnl, NULL);
		if (ret < MNL_CB_STOP) {
			if (errno != ENOTSUP || debug)
				notice("get_netconf %u/%u failed %s", ifindex,
				       family, strerror(errno));
		}
		if (ret <= MNL_CB_STOP)
			break;
	}

	if (len == -1)
		panic("mnl_socket_recvfrom");
}

/* Request current state from kernel and put in storage and publish */
static void dump_kernel(struct mnl_socket *nl, int family, int type,
			int ifindex, mnl_cb_t callback, void *arg)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct tcmsg *tc;

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = ++dump_seq;

	if (type == RTM_GETLINK ||
	    (family == AF_BRIDGE && type == RTM_GETNEIGH)) {
		struct ifinfomsg *ifi
			= mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
		ifi->ifi_family = family;
	} else if (type == RTM_GETQDISC  || type == RTM_GETCHAIN ||
		   type == RTM_GETTFILTER) {
		tc = mnl_nlmsg_put_extra_header(nlh, sizeof(*tc));
		tc->tcm_family = family;

		if (type == RTM_GETCHAIN || type == RTM_GETTFILTER) {
			tc->tcm_ifindex = ifindex;
			tc->tcm_parent = 0;
			tc->tcm_info = 0;
		}
	} else {
		struct rtgenmsg *rt
			= mnl_nlmsg_put_extra_header(nlh, sizeof(*rt));
		rt->rtgen_family = family;
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		panic("mnl_socket_sendto");

	unsigned portid = mnl_socket_get_portid(nl);

	ssize_t len;
	while ((len = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		int ret = mnl_cb_run(buf, len, dump_seq, portid,
				     callback, arg);
		if (ret < MNL_CB_STOP) {
			notice("dump_kernel cb failed family %d type %d err %s",
			       family, type, strerror(errno));
		}

		if (ret <= MNL_CB_STOP)
			break;
	}

	if (len < 0)
		panic("mnl_socket_recvfrom");
}

static void get_all_netconf(struct mnl_socket *nl, zlist_t *if_list)
{
	/* Note: zlist stores a void *, but since we only need interface
	 * index (and 0 is not a valid ifindex), okay to use a cast
	 * to go from pointer to index.
	 */
	void *key;

	for (key = zlist_first(if_list); key; key = zlist_next(if_list)) {
		unsigned long ifindex = (unsigned long) key;

		get_netconf(nl, ifindex, AF_INET);
		get_netconf(nl, ifindex, AF_INET6);
		get_netconf(nl, ifindex, AF_MPLS);
	}
}

static void get_all_tc(struct mnl_socket *nl, zlist_t *if_list)
{
	/* Note: zlist stores a void *, but since we only need interface
	 * index (and 0 is not a valid ifindex), okay to use a cast
	 * to go from pointer to index.
	 */
	void *key;

	dump_kernel(nl, AF_UNSPEC, RTM_GETQDISC, -1, process_netlink_rtnl,
		    NULL);

	for (key = zlist_first(if_list); key; key = zlist_next(if_list)) {
		unsigned long ifindex = (unsigned long) key;
		dump_kernel(nl, AF_UNSPEC, RTM_GETCHAIN, ifindex,
			    process_netlink_rtnl, NULL);
	}
	for (key = zlist_first(if_list); key; key = zlist_next(if_list)) {
		unsigned long ifindex = (unsigned long) key;
		dump_kernel(nl, AF_UNSPEC, RTM_GETTFILTER, ifindex,
			    process_netlink_rtnl, NULL);
	}
}

static inline unsigned int get_nl_grp(unsigned int group)
{
	if (group > 31)
		return 0;
	else
		return group ? (1 << (group - 1)) : 0;
}


/* Request current state from kernel and put in storage and publish */
static void dump_kernel_xfrm(int type)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	static unsigned int seq;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	unsigned int groups = 0;

	nl = mnl_socket_open(NETLINK_XFRM);
	if (!nl)
		panic("mnl_socket_open");
	groups |= get_nl_grp(XFRMNLGRP_ACQUIRE);
	groups |= get_nl_grp(XFRMNLGRP_EXPIRE);
	groups |= get_nl_grp(XFRMNLGRP_POLICY);
	groups |= get_nl_grp(XFRMNLGRP_SA);

	if (mnl_socket_bind(nl, groups, MNL_SOCKET_AUTOPID) < 0)
		panic("mnl_socket_bind");
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = ++seq;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		panic("mnl_socket_sendto");

	unsigned portid = mnl_socket_get_portid(nl);

	ssize_t len;
	while ((len = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		int ret = mnl_cb_run(buf, len, seq, portid,
				     process_netlink_xfrm, NULL);
		if (ret < MNL_CB_STOP) {
			notice("dump_kernel: error parsing netlink xfrm: %s",
			       strerror(errno));
			if (debug)
				mnl_nlmsg_fprintf(stdout, buf, len, len);
			break;
		}

		if (ret <= MNL_CB_STOP)
			break;
	}

	if (len < 0)
		panic("mnl_socket_recvfrom");

	mnl_socket_close(nl);
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [-V | --version] [-d | --daemon] [-v | --debug]\n"
		"       [[-l | --log_file] LOGFILE]\n"
		"       [[-p | --pid_file] PIDFILE] [[-f | --config_file CFGFILE]\n"
		"       [[-u | --user USER] [[-g | --group] GROUP]\n",
		progname);
	exit(1);
}

static void record_pid(const char *name)
{
	FILE *f = fopen(name, "w");

	if (!f)
		perror(name);
	else {
		fprintf(f, "%d\n", getpid());
		fclose(f);
	}
}

/* Useful when running as daemon, redirect standard out and error to file. */
static void open_logfile(const char *filename)
{
	int fd = open(filename, O_WRONLY|O_APPEND|O_CREAT, 0640);
	if (fd < 0)
		perror(filename);
	else {
		fflush(stdout);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}
}

/* Close and reopen log file if signaled to rotate */
static void logrotate_sig(int signo __unused)
{
	if (logfile)
		open_logfile(logfile);
}

/* Load config file and do sanity checks */
static int parse_cfg_file(void)
{
	return parser_controller_cfg(cfgfile);
}

/* Set permissions on unix domain socket */
void set_perm(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		panic("%s", path);

	if (!S_ISSOCK(st.st_mode))
		panic("%s is not a socket", path);

	/* Make socket accessible from vyatta user */
	if (chmod(path, 0770) < 0)
		panic("chmod %s", path);

	if (chown(path, uid, gid) < 0)
		panic("chown %s", path);

}

static struct option longopts[] = {
	{ "version",	no_argument,	   NULL, 'V' },
	{ "debug",	no_argument,	   NULL, 'v' },
	{ "daemon",	no_argument,	   NULL, 'd' },
	{ "config_file", required_argument, NULL, 'f' },
	{ "pid_file",   required_argument, NULL, 'p' },
	{ "log_file",	required_argument, NULL, 'l' },
	{ "user",	required_argument, NULL, 'u' },
	{ "group",	required_argument, NULL, 'g' },
	{ NULL ,	0,		   NULL, '\0' }
};

static void parse_args(int argc, char **argv)
{
	int opt;

	while ((opt = getopt_long(argc, argv, "Vdvl:u:g:f:p:",
				  longopts, 0)) != -1) {
		switch (opt) {
		case 'v':
			++debug;
			break;
		case 'd':
			daemonmode = true;
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'f':
			cfgfile = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'u': {
			struct passwd *pw = getpwnam(optarg);

			if (!pw) {
				fprintf(stderr, "unknown user '%s'\n", optarg);
				exit(1);
			}
			uid = pw->pw_uid;
			break;
		}
		case 'g': {
			struct group *gr = getgrnam(optarg);
			if (!gr) {
				fprintf(stderr, "unknown group '%s'\n", optarg);
				exit(1);
			}
			gid = gr->gr_gid;
			break;
		}
		case 'V':
			printf("%s\n", version);
			exit(0);

		default:
			fprintf(stderr, "Unknown option -%c\n", opt);
			usage();
		}
	}
}

/* Request current state from kernel */
static void get_kernel(struct mnl_socket *nl)
{
	zlist_t *if_list = zlist_new();

#ifdef RTNLGRP_RTDMN
	/* all VRFs */
	dump_kernel(nl, AF_UNSPEC, RTM_GETRTDMN, process_netlink_rtnl, NULL);
#endif

	/* all interfaces */
	dump_kernel(nl, AF_PACKET, RTM_GETLINK, -1, process_netlink_rtnl, if_list);
	/* all bridges */
	dump_kernel(nl, AF_BRIDGE, RTM_GETLINK, -1, process_netlink_rtnl, if_list);
	get_all_netconf(nl, if_list);
	get_all_tc(nl, if_list);
	zlist_destroy(&if_list);

	/* and addresses */
	dump_kernel(nl, AF_UNSPEC, RTM_GETADDR, -1, process_netlink_rtnl, NULL);

	/* and neighbours */
	dump_kernel(nl, AF_INET, RTM_GETNEIGH, -1, process_netlink_rtnl, NULL);
	dump_kernel(nl, AF_INET6, RTM_GETNEIGH, -1, process_netlink_rtnl, NULL);
	dump_kernel(nl, AF_BRIDGE, RTM_GETNEIGH, -1, process_netlink_rtnl, NULL);

	/* and routes */
	if (kernel_route) {
		dump_kernel(nl, AF_INET, RTM_GETROUTE, -1, process_netlink_rtnl,
			    NULL);
		dump_kernel(nl, AF_INET6, RTM_GETROUTE, -1, process_netlink_rtnl,
			    NULL);
		dump_kernel(nl, AF_MPLS, RTM_GETROUTE, -1, process_netlink_rtnl,
			    NULL);
	}
}

static void netlink_listener(struct mnl_socket *listen_nl,
			     struct mnl_socket *req_nl)
{
	zlist_t *if_list = zlist_new();
	int i;

	if (!if_list)
		panic("zlist_new");

	char rcvbufs[NL_MAXMSGS][NL_MAXMSGSIZE];
	struct mmsghdr msgvec[NL_MAXMSGS];
	struct iovec iovs[NL_MAXMSGS];
	struct sockaddr_nl addr[NL_MAXMSGS];

	for (i = 0; i < NL_MAXMSGS; i++) {
		struct msghdr *msg = &msgvec[i].msg_hdr;
		struct iovec *iov = &iovs[i];

		iov->iov_base = rcvbufs[i];
		iov->iov_len  = NL_MAXMSGSIZE;

		msg->msg_name       = &addr[i];
		msg->msg_namelen    = sizeof(struct sockaddr_nl);
		msg->msg_iov        = iov;
		msg->msg_iovlen     = 1;
		msg->msg_control    = NULL;
		msg->msg_controllen = 0;
		msg->msg_flags      = 0;
	}

	int vlen = recvmmsg(mnl_socket_get_fd(listen_nl),
			    msgvec, NL_MAXMSGS, MSG_WAITFORONE, 0);

	if (vlen < 0) {
		notice("error getting netlink messages: %s", strerror(errno));
		goto out;
	}

	for (i = 0; i < vlen; i++) {
		struct msghdr *msg = &msgvec[i].msg_hdr;
		ssize_t len = msgvec[i].msg_len;
		char *rcvbuf = rcvbufs[i];

		if (msg->msg_flags & MSG_TRUNC) {
			notice("truncated netlink message");
			if (debug)
				mnl_nlmsg_fprintf(stdout, rcvbuf, len, len);
			continue;
		}

		if (msg->msg_namelen != sizeof(struct sockaddr_nl)) {
			notice("invalid netlink message");
			continue;
		}

		int ret = mnl_cb_run(rcvbuf, len, 0, 0,
				     process_netlink_rtnl, if_list);
		if (ret < MNL_CB_STOP) {
			notice("error parsing netlink message: %s",
							strerror(errno));
			if (debug)
				mnl_nlmsg_fprintf(stdout, rcvbuf, len, len);
		}
	}

out:
	get_all_netconf(req_nl, if_list);
	zlist_destroy(&if_list);
}

static void xfrm_listener(struct mnl_socket *xfrm_nl)
{
	char rcvbuf[NL_MAXMSGSIZE];
	ssize_t len = mnl_socket_recvfrom(xfrm_nl, rcvbuf, NL_MAXMSGSIZE);

	if (len <= 0) {
		notice("mnl_socket_recvfrom xfrm: %s", strerror(errno));
		return;
	}

	int ret = mnl_cb_run(rcvbuf, len, 0, 0,
			     process_netlink_xfrm, NULL);

	if (ret < MNL_CB_STOP) {
		notice("error parsing xfrm netlink message : %s",
		       strerror(errno));
		if (debug)
			mnl_nlmsg_fprintf(stdout, rcvbuf, len, len);
	}
}

/* Tell snapshot request thread okay to start taking requests */
static void enable_snapshots(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	const char *topic = "INIT COMPLETE";
	nlmsg_t *nmsg = nlmsg_new(topic, ++msg_seqno, nlh, nlh->nlmsg_len);

	if (!nmsg)
		panic("can't allocate memory for msg");

	if (debug)
		nlmsg_dump("get_kernel", nmsg);

	/* send to snapshot service */
	nlmsg_send(nmsg, request_ipc);
}

/* Initialize sockets and request current policies from kernel */
static struct mnl_socket *xfrm_socket_open(void)
{
	struct mnl_socket *nl;
	unsigned int groups = 0;

	nl = mnl_socket_open(NETLINK_XFRM);
	if (!nl) {
		panic("mnl_socket_open");
		return NULL;
	}

	groups |= get_nl_grp(XFRMNLGRP_ACQUIRE);
	groups |= get_nl_grp(XFRMNLGRP_EXPIRE);
	groups |= get_nl_grp(XFRMNLGRP_POLICY);
	groups |= get_nl_grp(XFRMNLGRP_SA);

	if (mnl_socket_bind(nl, groups, MNL_SOCKET_AUTOPID) < 0)
		panic("mnl_socket_bind");

	/*
	 * Increase the xfrm netlink buffer size to make sure that we do not
	 * drop them on route to the dataplane.
	 */
	int xfrm_fd = mnl_socket_get_fd(nl);
	int xfrm_rcvbufsize = (32 * 1024 * 1024);
	if (setsockopt(xfrm_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                       &xfrm_rcvbufsize, sizeof(xfrm_rcvbufsize)) < 0)
                panic("setsockopt(SO_RCVBUFFORCE)");

	return nl;
}

/* Initialize sockets and request current policies from kernel */
static void
dump_kernel_generic(unsigned int msg_type,
		    unsigned int cmd,
		    unsigned int version,
		    unsigned int flag,
		    int (gen_dump_rcv(const struct nlmsghdr *, void *)))
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	static unsigned int seq;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (!nl)
		panic("mnl_socket_open");

	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = flag;
	nlh->nlmsg_seq = ++seq;

	struct genlmsghdr *genlh =
		mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genlh->cmd = cmd;
	genlh->version = version;

	unsigned portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		panic("mnl_socket_sendto message type %u", msg_type);

	ssize_t len;

	while ((len = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		nlh = (struct nlmsghdr *)buf;

		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			break;

		int ret = mnl_cb_run(buf, len, seq, portid,
				     gen_dump_rcv, NULL);
		if (ret < MNL_CB_STOP) {
			notice("dump_kernel_generic: error: %s",
			       strerror(errno));
			if (debug)
				mnl_nlmsg_fprintf(stdout, buf, len, len);
			break;
		}

		if (ret <= MNL_CB_STOP)
			break;
	}

	if (len < 0)
		panic("mnl_socket_recvfrom");

	mnl_socket_close(nl);
}

/* Handle errors on netlink socket, this usually indicates missed messages */
static void nl_socket_error(const char *name, struct mnl_socket *nl)
{
	int err;
	socklen_t len = sizeof(err);

	if (getsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_ERROR,
		       &err, &len) < 0)
		err("getsockopt(SO_ERROR");
	else
		notice("%s socket error detected: %s\n",
		       name, strerror(err));

}

/* SIGHUP: re-read configuration file
 * TODO: notify peers.
 */
static void reread_config(int signo __unused)
{
	dbg("SIGHUP");
	reconfigure_required = true;
}

/* SIGUSR2: increase debug level */
static void set_debug(int signo __unused)
{
	++debug;
}

static void set_signal(int signo, void (*func)(int))
{
	struct sigaction action;

	action.sa_handler = func;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);

	sigaction(signo, &action, NULL);
}

/* Give the controller a slight boost to run with higher
   priority than BGP, but less than dataplane. */
static void set_priority(void)
{
	struct sched_param sched = {
		.sched_priority = sched_get_priority_max(SCHED_OTHER),
	};

	pthread_setschedparam(pthread_self(), SCHED_OTHER, &sched);
}

static void publisher_close()
{
	if (publisher != NULL) {
		zsock_destroy(&publisher);

		info("publisher closed: %s", parser_endpoint_publish_bound());
		parser_set_endpoint_publish_bound(NULL);
	}
}

static void publisher_open(const char *endpoint)
{
	char *ep;

	/* If only a local controller, only allow connections
	 * over loopback; otherwise allow external connections
	 */
	assert(publisher == NULL);
	publisher = zsock_new_pub(endpoint);
	if (!publisher)
		panic("zsock_new_pub(%s): '%s'", endpoint, strerror(errno));

	ep = zsock_last_endpoint(publisher);
	if (ep == NULL)
		panic("zsock_last_endpoint(): '%s'", strerror(errno));

	parser_set_endpoint_publish_bound(ep);

	if (strncmp(ep, "ipc://", 6) == 0)
		set_perm(ep+6);

	info("publisher ready: %s", ep);
}

static void reconfigure(void)
{
	zmsg_t *msg = zmsg_new();
	int rc = -1;

	info("reconfigure");
	if (msg != NULL) {
		/*
		 * Tell the request thread to re-read the configuration
		 * and then wait for the response (ack).
		 */
		rc = zmsg_addstr(msg, "RECONFIGURE");
		if (rc == 0)
			rc = zmsg_addstr(msg, cfgfile);

		if (rc == 0)
			rc = zmsg_send(&msg, request_ipc);

		if (rc == 0)
			free(zstr_recv(request_ipc));
	}

	if (rc != 0)
		err("reconfigure failed: '%s'", strerror(errno));
}

static void genl_family_registered_l2tp(struct mnl_socket *l2tp_nl)
{
	dump_kernel_generic(genl_fmly[FMLY_L2TP].family_id,
			    L2TP_CMD_TUNNEL_GET,
			    L2TP_GENL_VERSION,
			    (NLM_F_REQUEST | NLM_F_DUMP),
			    process_genetlink_l2tp);

	dump_kernel_generic(genl_fmly[FMLY_L2TP].family_id,
			    L2TP_CMD_SESSION_GET,
			    L2TP_GENL_VERSION,
			    (NLM_F_REQUEST | NLM_F_DUMP),
			    process_genetlink_l2tp);

	unsigned int grp_id = genl_fmly[FMLY_L2TP].grp_id;

	if (mnl_socket_bind(l2tp_nl, 0, MNL_SOCKET_AUTOPID) < 0)
		panic("l2tp mnl_socket_bind: %s", strerror(errno));

	if (mnl_socket_setsockopt(l2tp_nl, NETLINK_ADD_MEMBERSHIP, &grp_id,
				  sizeof(grp_id)) < 0)
		panic("l2tp mnl_socket_setsockopt: %s", strerror(errno));
}

static void genl_family_registered_team(struct mnl_socket *team_nl)
{
	unsigned int grp_id = genl_fmly[FMLY_TEAM].grp_id;

	if (mnl_socket_bind(team_nl, 0, MNL_SOCKET_AUTOPID) < 0)
		panic("team mnl_socket_bind: %s", strerror(errno));

	if (mnl_socket_setsockopt(team_nl, NETLINK_ADD_MEMBERSHIP, &grp_id,
				  sizeof(grp_id)) < 0) {
		panic("team mnl_socket_setsockopt: %s", strerror(errno));
	}

	struct mnl_socket *s = mnl_socket_open(NETLINK_ROUTE);

	if (!s)
		panic("mnl_socket_open");
	dump_kernel(s, AF_PACKET, RTM_GETLINK, -1,
		    process_netlink_rtnl_teamonly, team_nl);
	mnl_socket_close(s);
}

static int process_genetlink_gectrl(const struct nlmsghdr *nlh,
				    void *arg __unused)
{
	struct genlmsghdr *ghdr = NLMSG_DATA(nlh);

	if (ghdr->cmd != CTRL_CMD_NEWFAMILY && ghdr->cmd != CTRL_CMD_DELFAMILY)
		return MNL_CB_OK;

	return process_genetlink_family(nlh, NULL);
}

static void gectrl_listener(struct mnl_socket *gectrl_nl)
{
	char rcvbuf[NL_MAXMSGSIZE];
	ssize_t len = mnl_socket_recvfrom(gectrl_nl, rcvbuf, NL_MAXMSGSIZE);

	if (len <= 0) {
		notice("mnl_socket_recvfrom gectrl: %s", strerror(errno));
		return;
	}

	int ret = mnl_cb_run(rcvbuf, len, 0, 0,
			     process_genetlink_gectrl, NULL);

	if (ret < MNL_CB_STOP) {
		notice("error parsing gectrl netlink message : %s",
		       strerror(errno));
		if (debug)
			mnl_nlmsg_fprintf(stdout, rcvbuf, len, len);
	}
}

/*
 * Receive a message from the request thread.
 *
 * The only one we expect is asking us to insert a snapshot marker into
 * the queue of messages being snapshotted. The only other time a message
 * comes back from the request thread is the ack for a reconfigure but we
 * block waiting for that at the time.
 */
static void request_event(zsock_t *request_ipc)
{
	zmsg_t *msg = zmsg_recv(request_ipc);
	zframe_t *frame;

	if (!msg)
		return;

	frame = zmsg_first(msg);

	if (frame && zframe_streq(frame, "SNAPMARK")) {
		if (zmsg_send(&msg, request_ipc) < 0)
			err("Failed to send snapshot marker back to requestor");
	} else
		err("Unexpected message from requestor");

	zmsg_destroy(&msg);
}

static void setup_kernel_nl_listener(int *fd, struct mnl_socket **soc)
{
	unsigned group_mask;

	/* open netlink listener socket */
	struct mnl_socket *listen_nl = mnl_socket_open(NETLINK_ROUTE);
	if (!listen_nl)
		panic("mnl_socket_open");

	if (!kernel_route)
		group_mask = rtnl_groupmsk(non_route_groups,
					   sizeof(non_route_groups)/
					   sizeof(non_route_groups[0]));
	else
		group_mask = rtnl_groupmsk(all_groups,
					   sizeof(all_groups)/
					   sizeof(all_groups[0]));

	if (mnl_socket_bind(listen_nl, group_mask, MNL_SOCKET_AUTOPID))
		panic("mnl_socket_bind");

	int listen_fd = mnl_socket_get_fd(listen_nl);

	/* increase listen socket buffering */
	int nl_rcvbufsize = NL_RCVBUFSIZE;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVBUFFORCE,
		       &nl_rcvbufsize, sizeof(nl_rcvbufsize)) < 0)
		panic("setsockopt(SO_RCVBUFFORCE)");

#ifdef RTNLGRP_RTDMN
	int grp_val = RTNLGRP_RTDMN;

	/* RTNLGRP_RTDMN is too large to include in mnl_socket_bind mask */
	if (setsockopt(listen_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &grp_val, sizeof(grp_val)) < 0)
		panic("setsockopt(NETLINK_ADD_MEMBERSHIP)");

	int rd_any = RD_ANY;

	if (setsockopt(listen_fd, SOL_SOCKET, SO_RTDOMAIN,
		       &rd_any, sizeof(rd_any)) < 0) {
		if (errno == ENOPROTOOPT)
			err("setsockopt(SO_RTDOMAIN) - listen_fd: ENOPROTOOPT");
		else
			panic("setsockopt(SO_RTDOMAIN) - listen_fd: %s",
			      strerror(errno));
	}
#endif

	*soc = listen_nl;
	*fd = listen_fd;
}

static void get_kernel_route_state(struct mnl_socket **req)
{
	/* open netlink request socket */
	struct mnl_socket *req_nl = mnl_socket_open(NETLINK_ROUTE);
	if (!req_nl)
		panic("mnl_socket_open");

	if (mnl_socket_bind(req_nl, 0, MNL_SOCKET_AUTOPID) < 0)
		panic("mnl_socket_bind");

#ifdef RTNLGRP_RTDMN
	int req_fd = mnl_socket_get_fd(req_nl);
	int rd_any = RD_ANY;

	if (setsockopt(req_fd, SOL_SOCKET, SO_RTDOMAIN,
		       &rd_any, sizeof(rd_any)) < 0) {
		if (errno == ENOPROTOOPT)
			err("setsockopt(SO_RTDOMAIN) - req_fd: ENOPROTOOPT");
		else
			panic("setsockopt(SO_RTDMAIN) - req_fd: %s",
			      strerror(errno));
	}
#endif

	/* Get current interfaces, addresses and routes */
	get_kernel(req_nl);
	*req = req_nl;
}

static zactor_t *setup_authenticator(void)
{
	zactor_t *auth = zactor_new(zauth, NULL);
	if (auth == NULL)
		die("Authentication initialization failed: '%s'\n",
		    strerror(errno));

	if (debug > 1) {
		zstr_sendx(auth, "VERBOSE", NULL);
		zsock_wait(auth);
	}

	zstr_sendx(auth, "CURVE", parser_authentication_path(), NULL);
	zsock_wait(auth);

	return auth;
}

int main(int argc, char **argv)
{
	int fsnotify_fd;
	char *p;

	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	parse_args(argc, argv);

	__nl_maxmsgsize = MIN(sysconf(_SC_PAGESIZE), 8192);
	assert(__nl_maxmsgsize >= 4096);

	udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_fd < 0)
		panic("udp socket");

	vplane_setup();
	igmp_setup();
	nlmsg_setup();

	/* become daemon */
	if (daemonmode && daemon(0, 0) < 0)
		die("daemon failed: %s\n", strerror(errno));

	openlog(progname, LOG_PID, LOG_DAEMON);

	if (pidfile)
		record_pid(pidfile);

	if (logfile) {
		open_logfile(logfile);
	}

	info("%s", version);

	if (parse_cfg_file() < 0)
		exit(EXIT_FAILURE);

	kernel_route = parser_use_kernel_routes();

	read_interface_cfg(interface_cfg);

	zsys_set_ipv6(1);
	zsys_set_sndhwm(ZMQ_IPC_HWM);
	zsys_set_rcvhwm(0);
	zsys_set_auto_use_fd(1);

	if (parser_authentication_enabled()) {
		auth_actor = setup_authenticator();
	}

	/* setup 0mq publish socket */
	publisher_open(parser_endpoint_publish());

	/* Start request handler thread and wait for sync up */
	request_ipc = (zsock_t *)zactor_new(request_thread, NULL);
	if (request_ipc == NULL)
		panic("zactor_new: '%s'", strerror(errno));

	int listen_fd;
	struct mnl_socket *listen_nl;
	struct mnl_socket *req_nl;

	setup_kernel_nl_listener(&listen_fd, &listen_nl);

	/* Need to do this at the moment becaue we have no dump from rib */
	get_kernel_route_state(&req_nl);

	struct mnl_socket *xfrm_nl = xfrm_socket_open();
	if (!xfrm_nl)
		panic("xfrm socket init failure");

	dump_kernel_xfrm(XFRM_MSG_GETPOLICY);

	struct mnl_socket *gectrl_nl = mnl_socket_open(NETLINK_GENERIC);

	if (!gectrl_nl)
		panic("gectrl mnl_socket_open");
	if (mnl_socket_bind(gectrl_nl, (1 << (GENL_ID_CTRL - 1)),
			    MNL_SOCKET_AUTOPID))
		panic("gectrl mnl_socket_bind");

	struct mnl_socket *l2tp_nl = mnl_socket_open(NETLINK_GENERIC);
	if (!l2tp_nl)
		panic("l2tp mnl_socket_open");

	dump_kernel_generic(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			    0x1, (NLM_F_REQUEST | NLM_F_DUMP),
			    process_genetlink_family);

	/* check once to see if l2tp family already registered */
	if (genl_fmly[FMLY_L2TP].changed) {
		genl_family_registered_l2tp(l2tp_nl);
		genl_fmly[FMLY_L2TP].changed = false;
	}

	struct mnl_socket *team_nl = mnl_socket_open(NETLINK_GENERIC);

	if (!team_nl)
		panic("team_nl mnl_socket_open");

	dump_kernel_generic(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			    0x1, (NLM_F_REQUEST | NLM_F_DUMP),
			    process_genetlink_family);

	/* check once to see if team family already registered */
	if (genl_fmly[FMLY_TEAM].changed) {
		genl_family_registered_team(team_nl);
		genl_fmly[FMLY_TEAM].changed = false;
	}

	fsnotify_fd = fsnotify_init();

	/* Tell request thread to accept Sync up messages */
	enable_snapshots();

	/* open local ipc command socket */
	zsock_t *cmd_sock = zsock_new_rep(CMD_IPC);
	if (!cmd_sock)
		panic("zsock_new_rep(%s): '%s'", CMD_IPC, strerror(errno));

	if (strncmp(CMD_IPC, "ipc://", 6) == 0)
		set_perm(CMD_IPC+6);

	set_signal(SIGHUP, reread_config);
	set_signal(SIGUSR1, logrotate_sig);
	set_signal(SIGUSR2, set_debug);

	info("controller ready");
	zmq_pollitem_t items[] = {
		{
			.fd = listen_fd,
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
		{
			.socket = zsock_resolve(cmd_sock),
			.events = ZMQ_POLLIN
		},
		{
			.fd = mnl_socket_get_fd(xfrm_nl),
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
		{
			.fd = mnl_socket_get_fd(l2tp_nl),
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
		{
			.fd = mnl_socket_get_fd(team_nl),
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
		{
			.fd = mnl_socket_get_fd(gectrl_nl),
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
		{
			.fd = fsnotify_fd,
			.events = ZMQ_POLLIN,
		},
		{
			.socket = zsock_resolve(request_ipc),
			.events = ZMQ_POLLIN,
		},
	};

	/* boost priority of daemon */
	set_priority();

	int item_count = sizeof(items)/sizeof(items[0]);

	while (!zsys_interrupted) {
		if (zmq_poll(items, item_count,
			     3000 * ZMQ_POLL_MSEC) < 0) {
			if (errno == EINTR)
				continue;
			err("ZMQ poll failure: '%s'" ,strerror(errno));
			break;
		}

		if (reconfigure_required) {
			char *old_endpoint;
			const char *new_endpoint;

			old_endpoint = strdup(parser_endpoint_publish());
			reconfigure();
			new_endpoint = parser_endpoint_publish();

			if (!auth_actor && parser_authentication_enabled())
				auth_actor = setup_authenticator();
			else if (auth_actor && !parser_authentication_enabled())
				zactor_destroy(&auth_actor);

			if (!streq(old_endpoint, new_endpoint)) {
				publisher_close();
				publisher_open(new_endpoint);
			}
			free(old_endpoint);
			reconfigure_required = false;
		}

		if (items[0].revents & ZMQ_POLLIN)
			netlink_listener(listen_nl, req_nl);

		if (items[0].revents & ZMQ_POLLERR)
			nl_socket_error("listen", listen_nl);

		if (items[1].revents & ZMQ_POLLIN)
			cmd_proxy(cmd_sock);

		if (items[2].revents & ZMQ_POLLIN)
			xfrm_listener(xfrm_nl);

		if (items[2].revents & ZMQ_POLLERR)
			nl_socket_error("xfrm", xfrm_nl);

		if (items[3].revents & ZMQ_POLLIN)
			l2tp_listener(l2tp_nl);

		if (items[3].revents & ZMQ_POLLERR)
			nl_socket_error("l2tp", l2tp_nl);

		if (items[4].revents & ZMQ_POLLIN)
			team_listener(team_nl);

		if (items[4].revents & ZMQ_POLLERR)
			nl_socket_error("team", team_nl);

		if (items[5].revents & ZMQ_POLLIN)
			gectrl_listener(gectrl_nl);

		if (items[5].revents & ZMQ_POLLERR)
			nl_socket_error("gectrl", gectrl_nl);

		if (genl_fmly[FMLY_L2TP].changed) {
			if (genl_fmly[FMLY_L2TP].family_id < 0) {
				mnl_socket_close(l2tp_nl);
				l2tp_nl = mnl_socket_open(NETLINK_GENERIC);
				if (!l2tp_nl)
					panic("l2tp_nl mnl_socket_open");
				items[3].fd = mnl_socket_get_fd(l2tp_nl);
			} else
				genl_family_registered_l2tp(l2tp_nl);
			genl_fmly[FMLY_L2TP].changed = false;
		}

		if (genl_fmly[FMLY_TEAM].changed) {
			if (genl_fmly[FMLY_TEAM].family_id < 0) {
				mnl_socket_close(team_nl);
				team_nl = mnl_socket_open(NETLINK_GENERIC);
				if (!team_nl)
					panic("team_nl mnl_socket_open");
				items[4].fd = mnl_socket_get_fd(team_nl);
			} else
				genl_family_registered_team(team_nl);
			genl_fmly[FMLY_TEAM].changed = false;
		}

		if (items[6].revents & ZMQ_POLLIN)
			fsnotify_handle_events();

		if (items[7].revents & ZMQ_POLLIN)
			request_event(request_ipc);
	}

	zsock_destroy(&cmd_sock);
	publisher_close();
	fsnotify_destroy();
	igmp_teardown();
	mnl_socket_close(listen_nl);
	mnl_socket_close(req_nl);
	mnl_socket_close(xfrm_nl);
	mnl_socket_close(gectrl_nl);
	mnl_socket_close(l2tp_nl);
	mnl_socket_close(team_nl);
	zactor_destroy((zactor_t **)&request_ipc);
	zactor_destroy(&auth_actor);

	interface_cfg_destroy();
	parser_controller_cfg_destroy();
	config_coll_destroy();
	vplane_teardown();
	nlmsg_cleanup();

	info("controller exiting");
	return 0;
}
