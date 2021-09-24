/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 * Copyright (c) 2014-2017 by Brocade Communications Systems, Inc.
 *
 * Code to parse netlink message and generate a topic string
 * This is used for publish-subscribe over Zmq and for key
 * snapshot table.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libmnl/libmnl.h>
#include <linux/xfrm.h>
#include <linux/genetlink.h>
#include <linux/l2tp.h>
#include <linux/netconf.h>
#ifdef RTNLGRP_MPLS_ROUTE
#include <linux/mpls.h>
#endif

#include <czmq.h>

#include "controller.h"
#include "team.h"
#include "compat.h"

/* All zero's in IPv4 or IPv6 */
static const char anyaddr[16];

/* Topic string for link messages
 * Note: trailing space is intentional because dataplane subscribes
 * to prefix.
 *  char filter[] = "link 5 "
 *  zsockopt_set_subscribe(subscriber, filter);
 * and should match "link 5 " and not "link 50 "
 */
static int link_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
		      uint32_t *ifindex)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFLA_MAX + 1] = { NULL };

	if (mnl_attr_parse(nlh, sizeof(*ifi), link_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse link attributes");
		return -1;
	}

	if (!tb[IFLA_IFNAME]) {
		notice("netlink: missing ifname in link msg for ifindex %d",
			ifi->ifi_index);
		return -1;
	}

	if (ifi->ifi_family == AF_BRIDGE) {
		if (!tb[IFLA_MASTER]) {
			notice("netlink: missing master in bridge msg for "
				"ifindex %d", ifi->ifi_index);
			return -1;
		}
		return snprintf(buf, len, "bridge_link %u ", ifi->ifi_index);
	}

	*ifindex = ifi->ifi_index;

	const char *ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);

	if (strncmp(ifname, "vxl", 3) == 0)
		return snprintf(buf, len, "vxlan %u %d ", ifi->ifi_index,
				ifi->ifi_family);

	if (strncmp(ifname, "tun", 3) == 0)
		return snprintf(buf, len, "tunnel %u %d ", ifi->ifi_index,
				ifi->ifi_family);

	/* For nested device types like VLAN, publish with id of parent */
	if (tb[IFLA_LINK]) {
		uint32_t iflink = mnl_attr_get_u32(tb[IFLA_LINK]);
		if (iflink)
			return snprintf(buf, len, "link %u ifindex %u %d ",
					iflink, ifi->ifi_index,
					ifi->ifi_family);
	}

	return snprintf(buf, len, "link %u %d ", ifi->ifi_index, ifi->ifi_family);
}

/* Kernel scope id to string */
static char *addr_scope(int id)
{
	static char buf[64];

	switch (id) {
	case 0:
		return "global";
	case 255:
		return "nowhere";
	case 254:
		return "host";
	case 253:
		return "link";
	case 200:
		return "site";
	default:
		snprintf(buf, sizeof(buf), "%d", id);
		return buf;
	}
}

/* Call back from libmnl to store attribute */
static int addr_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	unsigned int type = mnl_attr_get_type(attr);

	if (type <= IFA_MAX)
		tb[type] = attr;

	return MNL_CB_OK;
}

/*
 * Format up a topic string in format similar to 'ip address'
 * to describe address.
 */
static int address_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
			 uint32_t *ifindex)
{
	const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFA_MAX + 1] = { NULL };
	void *addr;
	char b1[INET6_ADDRSTRLEN];

	if (!(ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6
	      || ifa->ifa_family == AF_UNSPEC)) {
		info("netlink: ignore address family %u", ifa->ifa_family);
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*ifa), addr_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse address attributes");
		return -1;
	}

	if (tb[IFA_ADDRESS])
		addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
	else if (tb[IFA_MULTICAST])
		addr = mnl_attr_get_payload(tb[IFA_MULTICAST]);
	else {
		notice("missing address in netlink message");
		return -1;
	}

	char addrstr[64];

	if (ifa->ifa_family == AF_UNSPEC) {
		strcpy(addrstr, "ether ");
		ether_ntoa_r(addr, &addrstr[6]);
	} else
		snprintf(addrstr, sizeof(addrstr), "inet %s/%d",
			 inet_ntop(ifa->ifa_family, addr, b1, sizeof(b1)),
			 ifa->ifa_prefixlen);

	*ifindex = ifa->ifa_index;

	return snprintf(buf, len,
			"address %u %s scope %s",
			ifa->ifa_index,
			addrstr, addr_scope(ifa->ifa_scope));
}

/* Callback to store route attributes */
static int route_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	unsigned int type = mnl_attr_get_type(attr);

	if (type <= RTA_MAX)
		tb[type] = attr;
	return MNL_CB_OK;
}

const char *nl_route_type(unsigned int type)
{
	static char buf[64];

	switch (type) {
	case RTN_UNSPEC:
		return "unspec";
	case RTN_UNICAST:
		return "unicast";
	case RTN_LOCAL:
		return "local";
	case RTN_BROADCAST:
		return "broadcast";
	case RTN_ANYCAST:
		return "anycast";
	case RTN_MULTICAST:
		return "multicast";
	case RTN_BLACKHOLE:
		return "blackhole";
	case RTN_UNREACHABLE:
		return "unreachable";
	case RTN_PROHIBIT:
		return "prohibit";
	case RTN_THROW:
		return "throw";
	case RTN_NAT:
		return "nat";
	case RTN_XRESOLVE:
		return "xresolve";
	default:
		snprintf(buf, sizeof(buf), "%u", type);
		return buf;
	}
}

#ifdef RTNLGRP_MPLS_ROUTE
static inline uint32_t mpls_ls_get_label(uint32_t ls)
{
	return (ntohl(ls) & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
}

static int mplsroute_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
			   const struct rtmsg *rtm)
{
	struct nlattr *tb[RTA_MAX+1] = { NULL };
	uint32_t in_label;

	if (debug)
		notice("netlink: mpls route %s\n",
		       nlh->nlmsg_type == RTM_NEWROUTE ? "new" : "delete");

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		notice(
			"netlink: mplsroute_topic can't parse address attributes");
		return -1;
	}

	if (tb[RTA_DST])
		in_label = mnl_attr_get_u32(tb[RTA_DST]);
	else {
		notice("netlink: missing required RTA_DST attribute");
		return -1;
	}

	return snprintf(buf, len, "route-mpls %u",
			mpls_ls_get_label(in_label));
}
#endif /* RTNLGRP_MPLS_ROUTE */

static const char *mroute_ntop(int af, const void *src,
			       char *dst, socklen_t size)
{
	switch (af) {
	case RTNL_FAMILY_IPMR:
		return inet_ntop(AF_INET, src, dst, size);
		break;

	case RTNL_FAMILY_IP6MR:
		return inet_ntop(AF_INET6, src, dst, size);
		break;

	default:
		notice("netlink: multicast: bad family %d", af);
	}
	return NULL;
}

static int mroute_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
			const struct rtmsg *rtm)
{
	struct nlattr *tb[RTA_MAX+1] = { NULL };
	int iifindex = 0, oifindex = 0;
	const void *mcastgrp, *origin;
	char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN];
	uint32_t table = rtm->rtm_table;
	const char *mcastgrp_str;
	const char *origin_str;

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		notice("netlink: mroute_topic can't parse address attributes");
		return -1;
	}

	if (tb[RTA_TABLE])
		table = mnl_attr_get_u32(tb[RTA_TABLE]);

	if (table == RT_TABLE_LOCAL) {
		notice("netlink: mroute_topic RT_TABLE_LOCAL");
		return -1;
	}

	if (tb[RTA_DST])
		mcastgrp = mnl_attr_get_payload(tb[RTA_DST]);
	else
		mcastgrp = anyaddr;

	if (tb[RTA_SRC])
		origin = mnl_attr_get_payload(tb[RTA_SRC]);
	else
		origin = anyaddr;

	if (tb[RTA_IIF])
		iifindex = mnl_attr_get_u32(tb[RTA_IIF]);

	if (tb[RTA_OIF])
		oifindex = mnl_attr_get_u32(tb[RTA_OIF]);

	mcastgrp_str = mroute_ntop(rtm->rtm_family, mcastgrp, b1, sizeof(b1));
	if (!mcastgrp_str)
		mcastgrp_str = "";

	origin_str = mroute_ntop(rtm->rtm_family, origin, b2, sizeof(b2));
	if (!origin_str)
		origin_str = "";

	if (!iifindex && (nlh->nlmsg_type == RTM_NEWROUTE)) {
		/*
		 * An unresolved multicast route will be received as RTM_NEWROUTE but with
		 * an RTA_IIF iifindex of zero. Later, if it is resolved, we will receive a
		 * further RTM_NEWROUTE but with a valid non zero iifindex. However, both
		 * messages have been saved to the snapshot. Hence, on replay, even if the
		 * multicast route has been deleted, we will recreate the unresolved route.
		 * Either we remove this unresolved route from the snapshot when we receive
		 * an update, or we just ignore it. As I don't think the dataplane cares
		 * about unresolved routes, as there is nothing to forward, I think we can
		 * just ignore the unresolved message.
		 */
		dbg("ignore mroute table %d iifindex %d oifindex %d %s %s/%u %s/%u",
				table, iifindex, oifindex, nl_route_type(rtm->rtm_type),
				mcastgrp_str, rtm->rtm_dst_len, origin_str, rtm->rtm_src_len);
		return -1;
	}

	dbg("mroute %s table %d iifindex %d oifindex %d %s %s/%u %s/%u",
			nlh->nlmsg_type == RTM_NEWROUTE ? "new" : "delete",
			table, iifindex, oifindex, nl_route_type(rtm->rtm_type),
			mcastgrp_str, rtm->rtm_dst_len, origin_str, rtm->rtm_src_len);

	return snprintf(buf, len, "route %d %d %s %s/%u %s/%u",
									iifindex, oifindex, nl_route_type(rtm->rtm_type),
									mcastgrp_str, rtm->rtm_dst_len,
									origin_str, rtm->rtm_src_len);
}

static int route_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[RTA_MAX + 1] = { NULL };
	const void *dest;
	char b1[INET6_ADDRSTRLEN];
	uint32_t table = rtm->rtm_table;

#ifdef RTNLGRP_MPLS_ROUTE
	if (rtm->rtm_family == AF_MPLS)
		return mplsroute_topic(nlh, buf, len, rtm);
#endif /* RTNLGRP_MPLS_ROUTE */

	if (rtm->rtm_type == RTN_MULTICAST)
		return mroute_topic(nlh, buf, len, rtm);

	/* Ignore cached host routes */
	if (rtm->rtm_flags & RTM_F_CLONED) {
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse address attributes");
		return -1;
	}

	if (tb[RTA_TABLE])
		table = mnl_attr_get_u32(tb[RTA_TABLE]);

	if (table == RT_TABLE_LOCAL && rtm->rtm_type == RTN_BROADCAST) {
		dbg("netlink: ignore local broadcast route");
		return -1;
	}

	if (tb[RTA_DST])
		dest = mnl_attr_get_payload(tb[RTA_DST]);
	else
		dest = anyaddr;

#ifdef RTNLGRP_RTDMN
	unsigned rd_id = RD_DEFAULT;
	if (tb[RTA_RTG_DOMAIN])
		rd_id = mnl_attr_get_u32(tb[RTA_RTG_DOMAIN]);

	return snprintf(buf, len,
			"route %s/%u %u %u %u",
			inet_ntop(rtm->rtm_family, dest, b1, sizeof(b1)),
			rtm->rtm_dst_len,
			rtm->rtm_scope,
			table,
			rd_id);
#else
	return snprintf(buf, len,
			"route %s/%u %u %u",
			inet_ntop(rtm->rtm_family, dest, b1, sizeof(b1)),
			rtm->rtm_dst_len,
			rtm->rtm_scope,
			table);

#endif
}

/* Call back from libmnl to validate netlink message */
static int neigh_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int neigh_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
		       uint32_t *ifindex)
{
	const struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[NDA_MAX + 1] = { NULL };
	const void *dst;
	char b1[INET6_ADDRSTRLEN];

	if (!(ndm->ndm_family == AF_INET
	      || ndm->ndm_family == AF_INET6 || ndm->ndm_family == AF_BRIDGE)) {
		info("netlink: ignore neighbor family %d", ndm->ndm_family);
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*ndm), neigh_attr, tb) != MNL_CB_OK) {
		notice("netlink: can't parse neigh attributes");
		return -1;
	}

	if (ndm->ndm_family == AF_BRIDGE && tb[NDA_LLADDR])
		dst = mnl_attr_get_payload(tb[NDA_LLADDR]);
	else if (ndm->ndm_family != AF_BRIDGE && tb[NDA_DST])
		dst = mnl_attr_get_payload(tb[NDA_DST]);
	else
		dst = anyaddr;

	const char *addr;
	if (ndm->ndm_family == AF_BRIDGE) {
		strcpy(b1, "ether ");
		ether_ntoa_r(dst, &b1[6]);
		addr = b1;
	} else {
		addr = inet_ntop(ndm->ndm_family, dst, b1, sizeof(b1));
	}

	*ifindex = ndm->ndm_ifindex;
	return snprintf(buf, len,
			"neigh %d %s",
			ndm->ndm_ifindex, addr);
}

/* Call back from libmnl to validate netlink message */
static int netconf_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NETCONFA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int netconf_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
			 uint32_t *ifindexp)
{
	const struct netconfmsg *ncm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[NETCONFA_MAX + 1] = { NULL };
	int32_t ifindex;

	/* Ignore families that we don't care about */
	switch (ncm->ncm_family) {
	case AF_INET6:
		break;
	case AF_INET:
		fsnotify_add_redirects_watchers();
		break;
	case AF_MPLS:
		fsnotify_add_mpls_watchers();
		break;

	case RTNL_FAMILY_IPMR:
	case RTNL_FAMILY_IP6MR:
		break;

	default:
		return -1;
	}

	if (mnl_attr_parse(nlh, sizeof(*ncm), netconf_attr, tb) != MNL_CB_OK) {
		notice("netconf: can't parse netconf attributes");
		return -1;
	}

	if (!tb[NETCONFA_IFINDEX]) {
		notice("netconf: missing ifindex");
		return -1;
	}

	ifindex = (int)mnl_attr_get_u32(tb[NETCONFA_IFINDEX]);
	if (ifindex == NETCONFA_IFINDEX_ALL ||
	    ifindex == NETCONFA_IFINDEX_DEFAULT) {
		if (!tb[NETCONFA_MC_FORWARDING]) {
			dbg("netconf: ifindex %d is global: ignored", ifindex);
			return -1;
		}
	}

	*ifindexp = ifindex;
	return snprintf(buf, len, "netconf %d %d", ifindex, ncm->ncm_family);
}

/* Call back from libmnl to validate netlink message */
static int xfrm_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, XFRMA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int l2tp_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, L2TP_ATTR_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static const struct xfrm_userpolicy_info *
xfrm_nl_policy_decode(const struct nlmsghdr *nlh)
{
	const struct xfrm_userpolicy_id *pol_id;
	const struct xfrm_user_polexpire *pol_expire;
	const struct xfrm_userpolicy_info *pol_info;
	struct nlattr *tb[XFRMA_MAX+1] = { NULL };

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_DELPOLICY:
		pol_id = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*pol_id),
				   xfrm_attr, tb) != MNL_CB_OK) {
			notice("xfrm: can't parse attributes to delpolicy");
			return NULL;
		}

		if (!tb[XFRMA_POLICY]) {
			notice("xfrm: missing policy in delpolicy");
			return NULL;
		}
		pol_info = mnl_attr_get_payload(tb[XFRMA_POLICY]);
		break;

	case XFRM_MSG_POLEXPIRE:
		pol_expire = mnl_nlmsg_get_payload(nlh);
		pol_info = &pol_expire->pol;

		if (mnl_attr_parse(nlh, sizeof(*pol_expire),
				   xfrm_attr, tb) != MNL_CB_OK) {
			notice("xfrm: can't parse attributes to polexpire");
			return NULL;
		}
		break;

	case XFRM_MSG_NEWPOLICY: /* fall through */
	case XFRM_MSG_UPDPOLICY:
		pol_info = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*pol_info),
				   xfrm_attr, tb) != MNL_CB_OK) {
			notice("xfrm: can't parse attributes to newpolicy");
			return NULL;
		}
		break;

	default:
		notice("xfrm: unexpected netlink policy msg %u",
		       nlh->nlmsg_type);
		return NULL;
	}

	return pol_info;
}

static int xfrm_policy_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct xfrm_userpolicy_info *usr_policy;
	char srcip_str[INET6_ADDRSTRLEN];
	char dstip_str[INET6_ADDRSTRLEN];

	usr_policy = xfrm_nl_policy_decode(nlh);
	if (!usr_policy)
		return -1;

	inet_ntop(usr_policy->sel.family, &usr_policy->sel.saddr,
		  srcip_str, sizeof(srcip_str));
	inet_ntop(usr_policy->sel.family, &usr_policy->sel.daddr,
		  dstip_str, sizeof(dstip_str));

	return snprintf(buf, len-1,
			"xfrm dir %d s_ip:%s "
			"d_ip:%s s_port %-5d d_port %-5d "
			"proto %-3d action %d", usr_policy->dir,
			srcip_str,
			dstip_str,
			usr_policy->sel.sport, usr_policy->sel.dport,
			usr_policy->sel.proto, usr_policy->action);
}

static const char *xfrm_tunnel_mode_str(uint8_t mode)
{
	switch (mode) {
	case XFRM_MODE_TRANSPORT:
		return "transport";
	case XFRM_MODE_TUNNEL:
		return "tunnel";
	default:
		return "unknown";
	}
}

static void get_mark_value_and_mask(struct nlattr **tb,
				    uint32_t *mark_value, uint32_t *mark_mask)
{
	struct xfrm_mark *xmark;

	if (tb[XFRMA_MARK]) {
		xmark = mnl_attr_get_payload(tb[XFRMA_MARK]);
		*mark_value = xmark->v;
		*mark_mask = xmark->m;
	} else {
		*mark_value = 0;
		*mark_mask = 0;
	}
}

static int xfrm_sa_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct xfrm_usersa_info *sa_info;
	const struct xfrm_user_expire *expire;
	const struct xfrm_usersa_id *sa_id;
	uint32_t mark_value, mark_mask;
	const size_t payload_size = mnl_nlmsg_get_payload_len(nlh);
	struct nlattr *tb[XFRMA_MAX+1] = { NULL };
	char dstip_str[INET6_ADDRSTRLEN];
	char srcip_str[INET6_ADDRSTRLEN];

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_UPDSA:
		if (payload_size < sizeof(*sa_info)) {
			notice("xfrm: too short for NEW SA");
			return -1;
		}
		sa_info = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_info),
				   xfrm_attr, tb) != MNL_CB_OK) {
			notice("xfrm: can't parse attributes to NEW SA");
			return -1;
		}
		inet_ntop(sa_info->family, &sa_info->saddr,
			  srcip_str, sizeof(srcip_str));
		get_mark_value_and_mask(tb, &mark_value, &mark_mask);
		return snprintf(buf, len - 1,
				"saxfrm %s SPI %.8x src %s mode %s "
				"Mark 0x%x Mask 0x%x",
				(XFRM_MSG_NEWSA == nlh->nlmsg_type) ? "NEWSA" : "UPDSA",
				sa_info->id.spi, srcip_str,
				xfrm_tunnel_mode_str(sa_info->mode),
				mark_value, mark_mask);
	case XFRM_MSG_DELSA:
		if (payload_size < sizeof(*sa_id)) {
			notice("xfrm: too short for DEL SA ID");
			return -1;
		}
		sa_id = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_id),
				   xfrm_attr, tb)  != MNL_CB_OK) {
			notice("xfrm: can't parse attributes to DEL SA");
			return -1;
		}
		get_mark_value_and_mask(tb, &mark_value, &mark_mask);
		inet_ntop(sa_id->family, &sa_id->daddr,
			  dstip_str, sizeof(dstip_str));
		return snprintf(buf, len - 1,
				"saxfrm DEL SA dst %s SPI %.8x Mark 0x%x Mask 0x%x",
				dstip_str, sa_id->spi,
				mark_value, mark_mask);
	case XFRM_MSG_EXPIRE:
		if (payload_size < sizeof(*expire)) {
			notice("xfrm: too short for EXPIRE");
			return -1;
		}
		expire = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*expire),
				   xfrm_attr, tb) != MNL_CB_OK) {
			notice("xfrm: can't parse attributes of EXPIRE");
			return -1;
		}
		get_mark_value_and_mask(tb, &mark_value, &mark_mask);
		inet_ntop(expire->state.family, &expire->state.saddr,
			  srcip_str, sizeof(srcip_str));
		return snprintf(buf, len - 1,
				"saxfrm EXPIRE SPI %.8x src %s mode %s Mark 0x%x Mask 0x%x",
				expire->state.id.spi, srcip_str,
				xfrm_tunnel_mode_str(expire->state.mode),
				mark_value, mark_mask);

	default:
		notice("xfrm: unexpected netlink SA msg %u",
		       nlh->nlmsg_type);
		return -1;
	}
}

static int l2tp_tunnel_topic(const struct nlmsghdr *nlh,
			     char *buf, size_t len)
{
	struct nlattr *tb[L2TP_ATTR_MAX+1] = { NULL };
	int ret;

	ret = mnl_attr_parse(nlh, GENL_HDRLEN, l2tp_attr, tb);
	if (ret != MNL_CB_OK) {
		notice("unparseable genl tunnel attributes\n");
		return ret;
	}

	return snprintf(buf, len-1,
			"l2tp_tunnel conn_id %d",
			mnl_attr_get_u32(tb[L2TP_ATTR_CONN_ID]));
}

static int l2tp_session_topic(const struct nlmsghdr *nlh,
			     char *buf, size_t len)
{
	struct nlattr *tb[L2TP_ATTR_MAX+1] = { NULL };
	int ret;

	ret = mnl_attr_parse(nlh, GENL_HDRLEN, l2tp_attr, tb);
	if (ret != MNL_CB_OK) {
		notice("unparseable genl session attributes\n");
		return ret;
	}

	return snprintf(buf, len-1,
			"l2tp_session ifname %s session_id %d",
			mnl_attr_get_str(tb[L2TP_ATTR_IFNAME]),
			mnl_attr_get_u32(tb[L2TP_ATTR_SESSION_ID]));
}

#ifdef RTNLGRP_RTDMN
static int vrf_topic(const struct nlmsghdr *nlh,
			     char *buf, size_t len)
{
	const struct rtdmn_msg *rtdmn_msg = mnl_nlmsg_get_payload(nlh);
	rd_id_t rd_id = rtdmn_msg->rd_id;

	if (rd_id == 0)	{
		notice("vrf: invalid vrf id\n");
		return -1;
	}

	return snprintf(buf, len, "vrf %d", rd_id);
}
#endif

static int tc_msg_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, TCA_MAX) < 0)
		return MNL_CB_OK;

	if (type == TCA_KIND) {
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			err("invalid tc kind string %d: %s\n", type,
			    strerror(errno));
			return MNL_CB_ERROR;
		}
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int qdisc_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
		       uint32_t *ifindex)
{
	const struct tcmsg *tc = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[TCA_MAX + 1] = { NULL };
	const char *kind;

	if (mnl_attr_parse(nlh, sizeof(*tc), tc_msg_attr, tb) != MNL_CB_OK) {
		notice("qdisc: can't parse qdisc attributes");
		return -1;
	}

	if  (tb[TCA_KIND]) {
		kind = mnl_attr_get_str(tb[TCA_KIND]);
	} else {
		err("qdisc: can't parse kind attributes");
		return -1;
	}

	*ifindex = tc->tcm_ifindex;
	return snprintf(buf, len, "tc_qdisc %u %x %x %s", tc->tcm_ifindex,
			tc->tcm_handle, tc->tcm_parent, kind);
}

static int filter_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
			uint32_t *ifindex)
{
	const struct tcmsg *tc = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[TCA_MAX + 1] = { NULL };
	uint32_t chain_id;

	if (mnl_attr_parse(nlh, sizeof(*tc), tc_msg_attr, tb) != MNL_CB_OK) {
		notice("filter: can't parse filter attributes");
		return -1;
	}

	if  (tb[TCA_CHAIN]) {
		chain_id = mnl_attr_get_u32(tb[TCA_CHAIN]);
	} else {
		err("filter: can't parse chain attributes");
		return -1;
	}

	*ifindex = tc->tcm_ifindex;
	return snprintf(buf, len, "tc_filter %u %x %x %x ", tc->tcm_ifindex,
			tc->tcm_parent, chain_id, tc->tcm_info);
 }

static int chain_topic(const struct nlmsghdr *nlh, char *buf, size_t len,
		       uint32_t *ifindex)
{
	const struct tcmsg *tc = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[TCA_MAX + 1] = { NULL };
	uint32_t chain_id;

	if (mnl_attr_parse(nlh, sizeof(*tc), tc_msg_attr, tb) != MNL_CB_OK) {
		notice("filter: can't parse attributes");
		return -1;
	}

	if  (tb[TCA_CHAIN]) {
		chain_id = mnl_attr_get_u32(tb[TCA_CHAIN]);
	} else {
		err("filter: can't parse chain attributes");
		return -1;
	}

	*ifindex = tc->tcm_ifindex;
	return snprintf(buf, len, "tc_chain %u %x %x %x", tc->tcm_ifindex,
			tc->tcm_parent, chain_id, tc->tcm_handle);
}

/* Generate a topic string to be sent by as subject
 * 0mq uses strings as pub/sub filtering.
 */
int nl_generate_topic(const struct nlmsghdr *nlh, char *buf, size_t buflen,
		      uint32_t *ifindex)
{
	*ifindex = 0;

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		return link_topic(nlh, buf, buflen, ifindex);

	case RTM_NEWADDR:
	case RTM_DELADDR:
		return address_topic(nlh, buf, buflen, ifindex);

	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		return route_topic(nlh, buf, buflen);

	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		return neigh_topic(nlh, buf, buflen, ifindex);

	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		return netconf_topic(nlh, buf, buflen, ifindex);

#ifdef RTNLGRP_RTDMN
	case RTM_NEWRTDMN:
	case RTM_DELRTDMN:
		return vrf_topic(nlh, buf, buflen);
#endif
	case RTM_NEWQDISC:
	case RTM_DELQDISC:
		return qdisc_topic(nlh, buf, buflen, ifindex);

	case RTM_NEWTFILTER:
	case RTM_DELTFILTER:
		return filter_topic(nlh, buf, buflen, ifindex);

	case RTM_NEWCHAIN:
	case RTM_DELCHAIN:
		return chain_topic(nlh, buf, buflen, ifindex);

	default:
		info("unknown expected type %d", nlh->nlmsg_type);
		return -1;
	}
}

/* Generate a topic string to be sent by as subject
 * 0mq uses strings as pub/sub filtering.
 */
int nl_generate_topic_xfrm(const struct nlmsghdr *nlh, char *buf, size_t buflen,
			   bool *snapshot)
{
	*snapshot = false;
	switch (nlh->nlmsg_type) {

	case XFRM_MSG_NEWPOLICY: /* fall through */
	case XFRM_MSG_DELPOLICY: /* fall through */
	case XFRM_MSG_UPDPOLICY: /* fall through */
	case XFRM_MSG_POLEXPIRE:
		*snapshot = true;
		return xfrm_policy_topic(nlh, buf, buflen);
	case XFRM_MSG_NEWSA: /* fall through */
	case XFRM_MSG_UPDSA: /* fall through */
	case XFRM_MSG_DELSA: /* fall through */
	case XFRM_MSG_EXPIRE:
		return xfrm_sa_topic(nlh, buf, buflen);
	default:
		info("unknown expected type %d", nlh->nlmsg_type);
	}
	return -1;
}

/* Generate a topic string to be sent by as subject
 * 0mq uses strings as pub/sub filtering.
 */
int nl_generate_topic_l2tp(const struct nlmsghdr *nlh, char *buf, size_t buflen)
{
	struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);
	int ret = MNL_CB_OK;

	switch (genlhdr->cmd) {
	case L2TP_CMD_TUNNEL_GET:
	case L2TP_CMD_TUNNEL_CREATE:
	case L2TP_CMD_TUNNEL_MODIFY:
	case L2TP_CMD_TUNNEL_DELETE:
	       ret = l2tp_tunnel_topic(nlh, buf, buflen);
	       break;
	case L2TP_CMD_SESSION_GET:
	case L2TP_CMD_SESSION_CREATE:
	case L2TP_CMD_SESSION_DELETE:
	case L2TP_CMD_SESSION_MODIFY:
		ret = l2tp_session_topic(nlh, buf, buflen);
		break;
	default:
		info("unknown l2tp cmd %d", genlhdr->cmd);
		ret = -1;
		break;
	}
	return ret;
}
