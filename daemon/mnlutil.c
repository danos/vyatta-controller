/*
 * MNL (netlink) utility functions
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>

#include <czmq.h>
#include "controller.h"

int link_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_MTU:
	case IFLA_LINK:
	case IFLA_MASTER:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			notice("link attribute %d not u32", type);
			return MNL_CB_ERROR;
		}
		break;

	case IFLA_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			notice("link ifname not a valid string");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int linkinfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
		return MNL_CB_OK;

	if (type == IFLA_INFO_KIND) {
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			err("invalid link info kind %d: %s\n", type,
			    strerror(errno));
			return MNL_CB_ERROR;
		}
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

const char *nlmsg_type_name_rtnl(const struct nlmsghdr *nlh)
{
	static char buf[32];

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:	return "NEWLINK";
	case RTM_DELLINK:	return "DELLINK";
	case RTM_GETLINK:	return "GETLINK";
	case RTM_SETLINK:	return "SETLINK";
	case RTM_NEWADDR:	return "NEWADDR";
	case RTM_DELADDR:	return "DELADDR";
	case RTM_GETADDR:	return "GETADDR";
	case RTM_NEWROUTE:	return "NEWROUTE";
	case RTM_DELROUTE:	return "DELROUTE";
	case RTM_GETROUTE:	return "GETROUTE";
	case RTM_NEWNEIGH:	return "NEWNEIGH";
	case RTM_DELNEIGH:	return "DELNEIGH";
	case RTM_GETNEIGH:	return "GETNEIGH";
	case RTM_NEWRULE:	return "NEWRULE";
	case RTM_DELRULE:	return "DELRULE";
	case RTM_GETRULE:	return "GETRULE";
	case RTM_NEWQDISC:	return "NEWQDISC";
	case RTM_DELQDISC:	return "DELQDISC";
	case RTM_GETQDISC:	return "GETQDISC";
	case RTM_NEWTCLASS:	return "NEWTCLASS";
	case RTM_DELTCLASS:	return "DELTCLASS";
	case RTM_GETTCLASS:	return "GETTCLASS";
	case RTM_NEWTFILTER:	return "NEWTFILTER";
	case RTM_DELTFILTER:	return "DELTFILTER";
	case RTM_GETTFILTER:	return "GETTFILTER";
	case RTM_NEWACTION:	return "NEWACTION";
	case RTM_DELACTION:	return "DELACTION";
	case RTM_GETACTION:	return "GETACTION";
	case RTM_NEWPREFIX:	return "NEWPREFIX";
	case RTM_GETMULTICAST:	return "GETMULTICAST";
	case RTM_GETANYCAST:	return "GETANYCAST";
	case RTM_NEWNEIGHTBL:	return "NEWNEIGHTBL";
	case RTM_GETNEIGHTBL:	return "GETNEIGHTBL";
	case RTM_SETNEIGHTBL:	return "SETNEIGHTBL";
	case RTM_NEWNDUSEROPT:	return "NEWNDUSEROPT";
	case RTM_NEWADDRLABEL:	return "NEWADDRLABEL";
	case RTM_DELADDRLABEL:	return "DELADDRLABEL";
	case RTM_GETADDRLABEL:	return "GETADDRLABEL";
	case RTM_GETDCB:	return "GETDCB";
	case RTM_SETDCB:	return "SETDCB";
	case RTM_NEWNETCONF:    return "NEWNETCONF";
	case RTM_DELNETCONF:    return "DELNETCONF";
	case RTM_GETNETCONF:    return "GETNETCONF";
	case RTM_NEWMDB:        return "NEWMDB";
	case RTM_DELMDB:        return "DELMDB";
	case RTM_GETMDB:        return "GETMDB";
#ifdef RTNLGRP_RTDMN
	case RTM_NEWRTDMN:      return "NEWRTDMN";
	case RTM_DELRTDMN:      return "DELRTDMN";
#endif
	case RTM_NEWCHAIN:        return "NEWCHAIN";
	case RTM_DELCHAIN:        return "DELCHAIN";
	default:
		break;
	}

	snprintf(buf, sizeof(buf), "RTNL %u", nlh->nlmsg_type);
	return buf;
}
