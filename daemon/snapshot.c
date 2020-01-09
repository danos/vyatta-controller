/*
 * Track netlink messages, maintaining current state
 * of interfaces, addresses and routes
 *
 * Copyright (c) 2017-2020 AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include <string.h>
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
#include <linux/genetlink.h>
#include <linux/xfrm.h>
#include <linux/l2tp.h>
#include <linux/if_team.h>
#include <linux/netconf.h>

#include <libmnl/libmnl.h>

#include <czmq.h>

#include "controller.h"
#include "team.h"

#define TC_FILTER_TOPIC_MAX 128
#define TC_FILTER_SHORT_KEY 64

typedef int (snapshot_callback) (
    const char *key, void *item, void *argument);

struct _snapshot {
	uint64_t last_seqno;

#ifdef RTNLGRP_RTDMN
	zhash_t *vrf;
#endif
	zhash_t *link;
	zhash_t *vlan;
	zhash_t *bridge_link;
	zhash_t *address;
	zhash_t *route;
	zhash_t *neighbour;
	zhash_t *netconf;
	zhash_t *xfrm;
	zhash_t *l2tp_tunnel;
	zhash_t *l2tp_session;
	zhash_t *slave_link;
	zhash_t *team_select;
	zhash_t *team_mode;
	zhash_t *team_recipe;
	zhash_t *team_port;
	zhash_t *team_activeport;
	zhash_t *vrf_master;
	zhash_t *qdisc;
	zhash_t *filter;
	zhash_t *chain;
};

uint64_t snapshot_seqno(const snapshot_t *self)
{
	return self->last_seqno;
}

void snapshot_destroy(snapshot_t **selfp)
{
	snapshot_t *self = *selfp;

	if (self) {
#ifdef RTNLGRP_RTDMN
		zhash_destroy(&self->vrf);
#endif
		zhash_destroy(&self->link);
		zhash_destroy(&self->vlan);
		zhash_destroy(&self->bridge_link);
		zhash_destroy(&self->address);
		zhash_destroy(&self->route);
		zhash_destroy(&self->neighbour);
		zhash_destroy(&self->netconf);
		zhash_destroy(&self->xfrm);
		zhash_destroy(&self->l2tp_tunnel);
		zhash_destroy(&self->l2tp_session);
		zhash_destroy(&self->slave_link);
		zhash_destroy(&self->team_select);
		zhash_destroy(&self->team_mode);
		zhash_destroy(&self->team_recipe);
		zhash_destroy(&self->team_port);
		zhash_destroy(&self->team_activeport);
		zhash_destroy(&self->vrf_master);
		zhash_destroy(&self->qdisc);
		zhash_destroy(&self->filter);
		zhash_destroy(&self->chain);
		free(self);
		*selfp = NULL;
	}
}

snapshot_t *snapshot_new(void)
{
	snapshot_t *self = zmalloc(sizeof(snapshot_t));

	if (self) {
		self->last_seqno = 0;
#ifdef RTNLGRP_RTDMN
		self->vrf = zhash_new();
#endif
		self->link = zhash_new();
		self->vlan = zhash_new();
		self->bridge_link = zhash_new();
		self->address = zhash_new();
		self->route = zhash_new();
		self->neighbour = zhash_new();
		self->netconf = zhash_new();
		self->xfrm = zhash_new();
		self->l2tp_tunnel = zhash_new();
		self->l2tp_session = zhash_new();
		self->slave_link = zhash_new();
		self->team_select = zhash_new();
		self->team_mode = zhash_new();
		self->team_recipe = zhash_new();
		self->team_port = zhash_new();
		self->team_activeport = zhash_new();
		self->vrf_master = zhash_new();
		self->qdisc = zhash_new();
		self->filter = zhash_new();
		self->chain = zhash_new();

		if (!self->link || !self->vlan || !self->bridge_link ||
		    !self->address || !self->route || !self->neighbour ||
		    !self->netconf || !self->xfrm || !self->l2tp_tunnel ||
		    !self->l2tp_session || !self->slave_link ||
		    !self->team_select || !self->team_mode ||
		    !self->team_recipe || !self->team_port ||
		    !self->team_activeport || !self->vrf_master ||
#ifdef RTNLGRP_RTDMN
		    !self->vrf ||
#endif
		    !self->qdisc || !self->filter || !self->chain)
			snapshot_destroy(&self);
	}

	return self;
}

static void free_nmsg(void *arg)
{
	nlmsg_t *nmsg = arg;
	if (debug > 1)
		nlmsg_dump("free", nmsg);
	nlmsg_free(nmsg);
}

static int is_vlan(const char *key)
{
	return strstr(key, "ifindex") != NULL;
}

static int is_vxlan(const char *key)
{
	return strstr(key, "vxlan") != NULL;
}

static int is_bridge_link(const char *key)
{
	return strstr(key, "bridge_link") != NULL;
}

static int is_xfrm_msg(const char *key)
{
	return strstr(key, "xfrm") != NULL;
}

static int is_l2tp_msg(const char *key)
{
	return strstr(key, "l2tp") != NULL;
}

static int is_team_msg(const char *key)
{
	return strstr(key, "team") != NULL;
}

static int is_vrf_master(const struct nlmsghdr *nlh)
{
	struct nlattr *tb[IFLA_MAX+1] = { NULL };
	struct nlattr *linkinfo[IFLA_INFO_MAX+1] = { NULL };
	int ret;

	ret = mnl_attr_parse(nlh, sizeof(struct ifinfomsg), link_attr, tb);
	if (ret != MNL_CB_OK)
		return 0;

	if (!tb[IFLA_LINKINFO])
		return 0;

	if (mnl_attr_parse_nested(tb[IFLA_LINKINFO],
				  linkinfo_attr, linkinfo) != MNL_CB_OK)
		return 0;

	if (linkinfo[IFLA_INFO_KIND]) {
		if (!strncmp(mnl_attr_get_str(linkinfo[IFLA_INFO_KIND]),
			     "vrf", 3))
			return 1;
	}

	return 0;
}

static int is_slave(const struct nlmsghdr *nlh)
{
	struct nlattr *tb[IFLA_MAX+1] = { NULL };
	struct nlattr *linkinfo[IFLA_INFO_MAX+1] = { NULL };
	int ret;

	ret = mnl_attr_parse(nlh, sizeof(struct ifinfomsg), link_attr, tb);
	if (ret != MNL_CB_OK)
		return 0;

	if (tb[IFLA_MASTER]) {
		if (!tb[IFLA_LINKINFO])
			return 0;

		if (mnl_attr_parse_nested(tb[IFLA_LINKINFO],
					  linkinfo_attr, linkinfo) != MNL_CB_OK)
			return 0;

		if (linkinfo[IFLA_INFO_SLAVE_KIND])
			if (!strncmp(mnl_attr_get_str(
				linkinfo[IFLA_INFO_SLAVE_KIND]), "team", 4) ||
			    !strncmp(mnl_attr_get_str(
				linkinfo[IFLA_INFO_SLAVE_KIND]), "bridge", 6))
				return 1;
	}

	return 0;
}

static int is_team_master(const struct nlmsghdr *nlh)
{
	struct nlattr *tb[IFLA_MAX+1] = { NULL };
	struct nlattr *linkinfo[IFLA_INFO_MAX+1] = { NULL };
	int ret;

	ret = mnl_attr_parse(nlh, sizeof(struct ifinfomsg), link_attr, tb);
	if (ret != MNL_CB_OK)
		return 0;

	if (!tb[IFLA_LINKINFO])
		return 0;

	if (mnl_attr_parse_nested(tb[IFLA_LINKINFO],
				  linkinfo_attr, linkinfo) != MNL_CB_OK)
		return 0;

	if (linkinfo[IFLA_INFO_KIND]) {
		if (!strncmp(mnl_attr_get_str(linkinfo[IFLA_INFO_KIND]),
			     "team", 4))
			return 1;
	}

	return 0;
}

static void delete_dependent_team_port_entries(snapshot_t *self,
					       const char *key)
{
	uint32_t ifindex;
	uint32_t port_ifindex;
	char del_key[256];

	if (sscanf(key, "%*s %u %*s %u", &ifindex, &port_ifindex) != 2)
		return;

	snprintf(del_key, sizeof(del_key), "team %u select %u", ifindex,
		 port_ifindex);
	zhash_delete(self->team_select, del_key);
}

static void delete_dependent_team_entries(snapshot_t *self, const char *key)
{
	uint32_t ifindex;
	char del_key[256];
	zlist_t *keys;
	const char *topic;

	if (sscanf(key, "%*s %u", &ifindex) != 1)
		return;

	snprintf(del_key, sizeof(del_key), "team %u select", ifindex);
	keys = zhash_keys(self->team_select);
	for (topic = zlist_first(keys); topic; topic = zlist_next(keys)) {
		if (!strncmp(topic, del_key, strlen(del_key)))
			zhash_delete(self->team_select, topic);
	}
	zlist_destroy(&keys);

	snprintf(del_key, sizeof(del_key), "team %u hash", ifindex);
	zhash_delete(self->team_recipe, del_key);

	snprintf(del_key, sizeof(del_key), "team %u mode", ifindex);
	zhash_delete(self->team_mode, del_key);

	snprintf(del_key, sizeof(del_key), "team %u port", ifindex);
	keys = zhash_keys(self->team_port);
	for (topic = zlist_first(keys); topic; topic = zlist_next(keys)) {
		if (!strncmp(topic, del_key, strlen(del_key)))
			zhash_delete(self->team_port, topic);
	}
	zlist_destroy(&keys);

	snprintf(del_key, sizeof(del_key), "team %u activeport", ifindex);
	zhash_delete(self->team_activeport, del_key);
}

static void snapshot_handle_xfrm_msg(snapshot_t *self, nlmsg_t *nmsg)
{
	const char *key = nlmsg_key(nmsg);
	const struct nlmsghdr *nlh = nlmsg_data(nmsg);
	switch (nlh->nlmsg_type) {
	case XFRM_MSG_NEWPOLICY:
		if (is_xfrm_msg(key)) {
			zhash_update(self->xfrm, key, nmsg);
			zhash_freefn(self->xfrm, key, free_nmsg);
			nmsg = NULL;
		}
		break;
	case XFRM_MSG_DELPOLICY:
		if (is_xfrm_msg(key))
			zhash_delete(self->xfrm, key);
		break;
	case XFRM_MSG_UPDPOLICY:
		if (is_xfrm_msg(key)) {
			zhash_update(self->xfrm, key, nmsg);
			zhash_freefn(self->xfrm, key, free_nmsg);
			nmsg = NULL;
		}
		break;
	case XFRM_MSG_POLEXPIRE:
		if (is_xfrm_msg(key))
			zhash_delete(self->xfrm, key);
		break;
	default:
		err("ignoring unknown XFRM Policy message");
		break;
	}

	if (nmsg)
		nlmsg_free(nmsg);
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

static void
route_debug(const struct nlmsghdr *nlh, const char *rkey, const char *action)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[RTA_MAX+1] = {};
	char oiflist[128];

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK) {
		err("route_debug: cannot parse address attributes ('%s')", rkey);
		return;
	}

	snprintf(oiflist, sizeof(oiflist), "N/A");
	if (tb[RTA_OIF])
		snprintf(oiflist, sizeof(oiflist), "%d",
			 mnl_attr_get_u32(tb[RTA_OIF]));
	else if (tb[RTA_MULTIPATH]) {
		void *vnhp;
		char *sep = "";
		char *p;
		size_t w, l;

		p = oiflist;
		l = sizeof(oiflist);
		mnl_attr_for_each_nested(vnhp, tb[RTA_MULTIPATH]) {
			struct rtnexthop *nhp = vnhp;

			w = snprintf(p, l, "%s%d", sep, nhp->rtnh_ifindex);
			sep = ",";
			p += w;
			l -= w;
		}
	}

	dbg("route %s: %s %s '%s'", action, oiflist,
	    nl_route_type(rtm->rtm_type), rkey);
}

static void
route_delroute(snapshot_t *snap, nlmsg_t *nmsg, const struct nlmsghdr *nlh,
	       const char *rkey)
{
	if (debug)
		route_debug(nlh, rkey, "DELETE");

	zhash_delete(snap->route, rkey);
	if (nmsg != NULL)
		nlmsg_free(nmsg);
}

static void
route_newroute(snapshot_t *snap, nlmsg_t *nmsg, const struct nlmsghdr *nlh,
	       const char *rkey)
{
	if (nlh->nlmsg_flags & NLM_F_REPLACE) {
		struct nlmsghdr *__nlh = (struct nlmsghdr *) nlh;

		/* clear flag, won't need for replay */
		__nlh->nlmsg_flags &= ~NLM_F_REPLACE;
	}

	if (debug)
		route_debug(nlh, rkey, "UPDATE");

	zhash_update(snap->route, rkey, nmsg);
	zhash_freefn(snap->route, rkey, free_nmsg);
}

typedef struct {
	snapshot_t *self;
	int ifindex;
} route_link_args_t;

/* Handle link up transition
 * with IPv4 ECMP routes come back from the dead.
 */
static int route_link_up(const char *key __unused, void *item, void *args)
{
	route_link_args_t *ra = args;
	const struct nlmsghdr *nlh = nlmsg_data(item);
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[RTA_MAX+1] = {};
	void *vnhp;

	if (rtm->rtm_family != AF_INET)
		return MNL_CB_OK;

	/*
	 * The RIB takes care of inserting & removing unicast routes on
	 * link UP/DOWN.
	 */
	if (rtm->rtm_type == RTN_UNICAST)
		return MNL_CB_OK;

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK)
		return MNL_CB_OK;

	dbg("route link %d UP %s '%s'", ra->ifindex,
	    nl_route_type(rtm->rtm_type), key);

	if (tb[RTA_MULTIPATH]) {
		mnl_attr_for_each_nested(vnhp, tb[RTA_MULTIPATH]) {
			struct rtnexthop *nhp = vnhp;

			if (nhp->rtnh_ifindex == ra->ifindex)
				nhp->rtnh_flags &= ~RTNH_F_DEAD;
		}
	}

	return MNL_CB_OK;
}

/* Handle link down transition
 * with IPv4 routes may get silently deleted.
 */
static int route_link_down(const char *key, void *item, void *args)
{
	route_link_args_t *ra = args;
	nlmsg_t *nmsg = item;
	const struct nlmsghdr *nlh = nlmsg_data(nmsg);
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[RTA_MAX+1] = {};
	void *vnhp;

	if (rtm->rtm_family != AF_INET)
		return MNL_CB_OK;

	/*
	 * Ignore attempts to delete local (IPv4) interface addresses
	 */
	if (rtm->rtm_type == RTN_LOCAL)
		return MNL_CB_OK;

	if (rtm->rtm_type == RTN_UNICAST)
		return MNL_CB_OK;

	if (mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb) != MNL_CB_OK)
		return MNL_CB_OK;

	dbg("route link %d DOWN %s '%s'", ra->ifindex,
	    nl_route_type(rtm->rtm_type), key);

	if (tb[RTA_OIF]) {
		int oif = mnl_attr_get_u32(tb[RTA_OIF]);
		if (oif == ra->ifindex) {
			route_delroute(ra->self, NULL, nlh, key);
			return MNL_CB_OK;
		}
	}

	if (tb[RTA_MULTIPATH]) {
		unsigned hops_up = 0;

		mnl_attr_for_each_nested(vnhp, tb[RTA_MULTIPATH]) {
			struct rtnexthop *nhp = vnhp;

			if (nhp->rtnh_ifindex == ra->ifindex)
				nhp->rtnh_flags &= ~RTNH_F_DEAD;
			else
				++hops_up;
		}
		if (hops_up == 0)
			route_delroute(ra->self, NULL, nlh, key);
	}

	return MNL_CB_OK;
}

static void snapshot_ifn_iterator(zhash_t *zh, snapshot_callback *callback,
				  void *arg, int ifindex,
				  bool hash_holds_list)
{
	zlist_t *keys = zhash_keys(zh);
	const char *topic;

	/* run through all the topics in the zhash */
	for (topic = zlist_first(keys); topic; topic = zlist_next(keys)) {
		/* was an index to match supplied? */
		if (ifindex > 0) {
			int nlmsg_ifindex;

			/* ignore topic if it does not include the index */
			if (!(sscanf(topic, "%*s %d ", &nlmsg_ifindex) == 1 &&
			      nlmsg_ifindex == ifindex))
				continue;
		}

		if (hash_holds_list) {
			zlistx_t *list = zhash_lookup(zh, topic);
			nlmsg_t *nlmsg;

			for (nlmsg = zlistx_first(list);
			     nlmsg != NULL;
			     nlmsg = zlistx_next(list))
				callback(topic, nlmsg, arg);
		} else {
			nlmsg_t *nlmsg = zhash_lookup(zh, topic);

			callback(topic, nlmsg, arg);
		}
	}

	zlist_destroy(&keys);
}

static void snapshot_iterator(zhash_t *zh, snapshot_callback *callback,
			      void *arg, bool hash_holds_list)
{
	snapshot_ifn_iterator(zh, callback, arg, -1, hash_holds_list);
}

/* Need to update snapshot route table so that on restart
 * so that stale IPv4 routes are not replayed.
 *
 * NOTE: only used to process non-unicast (Multicast?) routes. For
 * unicast routes the RIB takes care of link transitions. The above
 * topic scan will fail as the unicast topic no longer includes the OIF.
 */
static void handle_link_transistion(snapshot_t *self,
				    const struct nlmsghdr *nlh)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	route_link_args_t args = { self, ifi->ifi_index };

	if (ifi->ifi_family != AF_UNSPEC)
		return;

	if (ifi->ifi_flags & IFF_UP)
		snapshot_ifn_iterator(self->route, route_link_up, &args,
				      ifi->ifi_index, false);
	else
		snapshot_ifn_iterator(self->route, route_link_down, &args,
				      ifi->ifi_index, false);
}

static int list_comparator(const void *nmsg_item1, const void *nmsg_item2)
{
	const struct nlmsghdr *nlh_item1 = nlmsg_data(nmsg_item1);
	const struct nlmsghdr *nlh_item2 = nlmsg_data(nmsg_item2);

	const struct ifinfomsg *ifi_item1 = mnl_nlmsg_get_payload(nlh_item1);
	const struct ifinfomsg *ifi_item2 = mnl_nlmsg_get_payload(nlh_item2);

	return ifi_item1->ifi_family - ifi_item2->ifi_family;
}

static void list_entry_destroy(void **p)
{
	free_nmsg(*p);
	*p = NULL;
}

static void hash_entry_destroy(void *p)
{
	zlistx_t *list = p;

	zlistx_destroy(&list);
}

static void update_with_newlink(zhash_t *hash, const char *key, nlmsg_t *nmsg)
{
	zlistx_t *list = zhash_lookup(hash, key);

	if (!list) {
		list = zlistx_new();
		if (!list)
			return;

		zlistx_set_destructor(list, list_entry_destroy);
		zlistx_set_comparator(list, list_comparator);

		zhash_insert(hash, key, list);
		zhash_freefn(hash, key, hash_entry_destroy);
	}

	/* is there an entry with matching ifi_family? */
	void *item = zlistx_find(list, nmsg);

	if (item)
		zlistx_delete(list, item);

	zlistx_insert(list, nmsg, true);
}

static int netconf_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NETCONFA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
update_netconf(zhash_t *hash, const char *key, nlmsg_t *nmsg)
{
	nlmsg_t *exist_nmsg = zhash_lookup(hash, key);

	if (exist_nmsg) {
		const struct nlmsghdr *update_nlh = nlmsg_data(nmsg);
		const struct netconfmsg *update_ncm = mnl_nlmsg_get_payload(
			update_nlh);
		struct nlattr *exist_tb[NETCONFA_MAX + 1] = { NULL };
		struct nlattr *tb[NETCONFA_MAX + 1] = { NULL };
		int i;

		if (mnl_attr_parse(nlmsg_data(exist_nmsg), sizeof(struct netconfmsg),
				   netconf_attr, exist_tb) != MNL_CB_OK) {
			notice("netconf: can't parse exist netconf attributes");
			return;
		}
		if (mnl_attr_parse(nlmsg_data(nmsg), sizeof(struct netconfmsg),
				   netconf_attr, tb) != MNL_CB_OK) {
			notice("netconf: can't parse new netconf attributes");
			return;
		}

		char buf[MNL_SOCKET_BUFFER_SIZE];
		struct nlmsghdr *new_nlh = mnl_nlmsg_put_header(buf);
		new_nlh->nlmsg_type = update_nlh->nlmsg_type;
		new_nlh->nlmsg_flags = update_nlh->nlmsg_flags;
		new_nlh->nlmsg_seq = update_nlh->nlmsg_seq;

		struct netconfmsg *ncm =
			mnl_nlmsg_put_extra_header(
				new_nlh, sizeof(struct netconfmsg));
		*ncm = *update_ncm;

		for (i = 0; i <= NETCONFA_MAX; i++) {
			/*
			 * If attribute not set in this message, inherit
			 * existing value.
			 */
			if (!tb[i])
				tb[i] = exist_tb[i];
			if (tb[i]) {
				mnl_attr_put(
					new_nlh, i,
					mnl_attr_get_payload_len(tb[i]),
					mnl_attr_get_payload(tb[i]));
			}
		}

		nlmsg_t *new_nmsg;

		new_nmsg = nlmsg_new(key, nlmsg_seqno(nmsg), new_nlh,
				     new_nlh->nlmsg_len);
		if (!new_nmsg)
			panic("can't allocate memory for msg");
		free_nmsg(nmsg);
		nmsg = new_nmsg;
		/*
		 * Update key to new memory location since old memory
		 * freed by free_nmsg.
		 */
		key = nlmsg_key(nmsg);
	}

	zhash_update(hash, key, nmsg);
	zhash_freefn(hash, key, free_nmsg);
}

static void
update_qdisc(snapshot_t *snap, nlmsg_t *nmsg, const struct nlmsghdr *nlh,
	     const char *key)
{
	if (nlh->nlmsg_flags & NLM_F_REPLACE) {
		struct nlmsghdr *__nlh = (struct nlmsghdr *) nlh;

		/* clear flag, won't need for replay */
		__nlh->nlmsg_flags &= ~NLM_F_REPLACE;
	}

	zhash_update(snap->qdisc, key, nmsg);
	zhash_freefn(snap->qdisc, key, free_nmsg);
}

static void
del_qdisc(snapshot_t *snap, nlmsg_t *nmsg, const char *key)
{
	zhash_delete(snap->qdisc, key);
	if (nmsg != NULL)
		nlmsg_free(nmsg);
}

static int filter_list_comparator(const void *nmsg_item1,
				  const void *nmsg_item2)
{
	const char *key1 = nlmsg_key(nmsg_item1);
	const char *key2 = nlmsg_key(nmsg_item2);

	return strncmp(key1, key2, TC_FILTER_TOPIC_MAX);
}

static zlistx_t *filter_list_head_alloc(snapshot_t *snap, const char *short_key)
{
	zlistx_t *list;

	list = zlistx_new();
	if (!list) {
		err("Failed to create list for %s\n", short_key);
		return NULL;
	}

	zlistx_set_destructor(list, list_entry_destroy);
	zlistx_set_comparator(list, filter_list_comparator);

	zhash_insert(snap->filter, short_key, list);
	zhash_freefn(snap->filter, short_key, hash_entry_destroy);

	return list;
}

static zlistx_t *filter_list_head(snapshot_t *snap, const char *key,
				   char *short_key)
{
	zlistx_t *list = NULL;
	uint32_t chain_id, parent;
	int ifindex;

	/* The key to a list head is first three parameters of the topic
	 * string. This is also the same key that is used for the tc chain
	 * objects, enabling the corresponding  list head to be located.
	 */
	if (sscanf(key, "%*s %u %x %x ", &ifindex, &parent,
		   &chain_id) != 3) {
		err("Filter: scan fail\n");
		return NULL;
	}

	snprintf(short_key, TC_FILTER_SHORT_KEY, "filter %u %x %x\n",
		 ifindex, parent, chain_id);

	list = zhash_lookup(snap->filter, short_key);

	return list;
}

static void
update_filter(snapshot_t *snap, nlmsg_t *nmsg,
	      const struct nlmsghdr *nlh,
	      const char *key)
{
	char short_key[TC_FILTER_SHORT_KEY];
	zlistx_t *list = filter_list_head(snap, key, short_key);

	if (!list) {
		list = filter_list_head_alloc(snap, short_key);
		if (!list)
			return;
	}

	void *item = zlistx_find(list, nmsg);

	if (item)
		zlistx_delete(list, item);

	zlistx_insert(list, nmsg, true);

	if (nlh->nlmsg_flags & NLM_F_REPLACE) {
		struct nlmsghdr *__nlh = (struct nlmsghdr *) nlh;

		/* clear flag, won't need for replay */
		__nlh->nlmsg_flags &= ~NLM_F_REPLACE;
	}
}

static void
del_filter(snapshot_t *snap, nlmsg_t *nmsg, const char *key)
{
	char short_key[TC_FILTER_SHORT_KEY];
	void *handle;
	zlistx_t *list = filter_list_head(snap, key, short_key);

	if (!list)
		goto out;

	handle = zlistx_find(list, (void *)nmsg);
	if (handle)
		zlistx_delete(list, handle);
	else
		info("%s not found for delete\n", key);

	if (zlistx_size(list) < 1)
		zhash_delete(snap->filter, short_key);
out:
	if (nmsg != NULL)
		nlmsg_free(nmsg);
}

static void
update_chain(snapshot_t *snap, nlmsg_t *nmsg, const struct nlmsghdr *nlh,
	     const char *key)
{
	if (nlh->nlmsg_flags & NLM_F_REPLACE) {
		struct nlmsghdr *__nlh = (struct nlmsghdr *) nlh;

		/* clear flag, won't need for replay */
		__nlh->nlmsg_flags &= ~NLM_F_REPLACE;
	}


	zhash_update(snap->chain, key, nmsg);
	zhash_freefn(snap->chain, key, free_nmsg);
}

static void
del_chain(snapshot_t *snap, nlmsg_t *nmsg, const char *key)
{
	char short_key[TC_FILTER_SHORT_KEY];
	zlistx_t *list = filter_list_head(snap, key, short_key);

	 /* Deleting a chain is a implicit delete of all the filters
	 * attatached to the chain. So find the list of filters that are
	 * attached to the chain and delete them. The list head is keyed
	 * by the same values as the chain entry being deleted.
	 */
	if (list) {
		info("Destroying Chain %s\n", short_key);
		zlistx_purge(list);
		zhash_delete(snap->filter, short_key);
	}

	zhash_delete(snap->chain, key);

	if (nmsg != NULL)
		nlmsg_free(nmsg);
}

static void snapshot_handle_non_xfrm_msg(snapshot_t *self, nlmsg_t *nmsg)
{
	const char *key = nlmsg_key(nmsg);
	const struct nlmsghdr *nlh = nlmsg_data(nmsg);

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
		handle_link_transistion(self, nlh);

		/* Only keep last link message for each AF */
		if (is_vlan(key) || is_vxlan(key)) {
			update_with_newlink(self->vlan, key, nmsg);
		} else if (is_bridge_link(key)) {
			/* these are all AF_BRIDGE - see link_topic() */
			zhash_update(self->bridge_link, key, nmsg);
			zhash_freefn(self->bridge_link, key, free_nmsg);
		} else if (is_slave(nlh)) {
			update_with_newlink(self->slave_link, key, nmsg);
			zhash_delete(self->link, key);
		} else if (is_vrf_master(nlh)) {
			update_with_newlink(self->vrf_master, key, nmsg);
			zhash_delete(self->link, key);
		} else {
			update_with_newlink(self->link, key, nmsg);
			zhash_delete(self->slave_link, key);
		}
		break;

	case RTM_DELLINK:
		if (is_vlan(key) || is_vxlan(key))
			zhash_delete(self->vlan, key);
		else if (is_bridge_link(key))
			zhash_delete(self->bridge_link, key);
		else if (is_slave(nlh))
			zhash_delete(self->slave_link, key);
		else if (is_vrf_master(nlh))
			zhash_delete(self->vrf_master, key);
		else {
			if (is_team_master(nlh))
				delete_dependent_team_entries(self, key);
			zhash_delete(self->link, key);
			/*
			 * The interface may have previously been a
			 * slave, but there may have been no
			 * intermediate update that removed the master
			 * from the device so also check the
			 * slave_link table.
			 */
			zhash_delete(self->slave_link, key);
		}

		nlmsg_free(nmsg);
		break;

	case RTM_NEWADDR:
		zhash_update(self->address, key, nmsg);
		zhash_freefn(self->address, key, free_nmsg);
		break;
	case RTM_DELADDR:
		zhash_delete(self->address, key);
		nlmsg_free(nmsg);
		break;

	case RTM_NEWROUTE:
		route_newroute(self, nmsg, nlh, key);
		break;
	case RTM_DELROUTE:
		route_delroute(self, nmsg, nlh, key);
		break;

	case RTM_NEWNEIGH:
		zhash_update(self->neighbour, key, nmsg);
		zhash_freefn(self->neighbour, key, free_nmsg);
		break;

	case RTM_DELNEIGH:
		zhash_delete(self->neighbour, key);
		nlmsg_free(nmsg);
		break;

	case RTM_NEWNETCONF:
		update_netconf(self->netconf, key, nmsg);
		break;

	case RTM_DELNETCONF:
		zhash_delete(self->netconf, key);
		nlmsg_free(nmsg);
		break;

#ifdef RTNLGRP_RTDMN
	case RTM_NEWRTDMN:
		zhash_update(self->vrf, key, nmsg);
		zhash_freefn(self->vrf, key, free_nmsg);
		break;
	case RTM_DELRTDMN:
		zhash_delete(self->vrf, key);
		nlmsg_free(nmsg);
		break;
#endif

	case RTM_NEWQDISC:
		update_qdisc(self, nmsg, nlh, key);
		break;

	case RTM_DELQDISC:
		del_qdisc(self, nmsg, key);
		break;

	case RTM_NEWTFILTER:
		update_filter(self, nmsg, nlh, key);
		break;

	case RTM_DELTFILTER:
		del_filter(self, nmsg, key);
		break;

	case RTM_NEWCHAIN:
		update_chain(self, nmsg, nlh, key);
		break;

	case RTM_DELCHAIN:
		del_chain(self, nmsg, key);
		break;

	default:
		info("unknown message type %d", nlh->nlmsg_type);
		nlmsg_free(nmsg);
	}
}

static void snapshot_handle_l2tp_msg(snapshot_t *self, nlmsg_t *nmsg)
{
	const char *key = nlmsg_key(nmsg);
	const struct nlmsghdr *nlh = nlmsg_data(nmsg);
	const struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);

	switch (genlhdr->cmd) {
	case L2TP_CMD_TUNNEL_GET:
	case L2TP_CMD_TUNNEL_CREATE:
	case L2TP_CMD_TUNNEL_MODIFY:
		if (is_l2tp_msg(key)) {
			zhash_update(self->l2tp_tunnel, key, nmsg);
			zhash_freefn(self->l2tp_tunnel, key, free_nmsg);
		}
		break;
	case L2TP_CMD_SESSION_GET:
	case L2TP_CMD_SESSION_CREATE:
	case L2TP_CMD_SESSION_MODIFY:
		if (is_l2tp_msg(key)) {
			zhash_update(self->l2tp_session, key, nmsg);
			zhash_freefn(self->l2tp_session, key, free_nmsg);
		}
		break;
	case L2TP_CMD_TUNNEL_DELETE:
		if (is_l2tp_msg(key))
			zhash_delete(self->l2tp_tunnel, key);
		break;
	case L2TP_CMD_SESSION_DELETE:
		if (is_l2tp_msg(key))
			zhash_delete(self->l2tp_session, key);
		break;
	default:
		err("ignoring unknown L2TP message");
		break;
	}
}

static void snapshot_handle_team_msg(snapshot_t *self, nlmsg_t *nmsg)
{
	const char *key = nlmsg_key(nmsg);
	const struct nlmsghdr *nlh = nlmsg_data(nmsg);
	struct team_msg_desc desc;

	int err;

	memset(&desc, 0, sizeof(desc));

	err = process_genetlink_teamcmd(nlh, &desc);
	if (err == MNL_CB_ERROR)
		return;

	/* There should be only one option/port per message at this point */
	if (desc.cmd == TEAM_CMD_OPTIONS_GET) {
		struct team_option_info *opt = zlist_first(desc.infolist);

		if (!strcmp(opt->name, "enabled")) {
			zhash_update(self->team_select, key, nmsg);
			zhash_freefn(self->team_select, key, free_nmsg);
		} else if (!strcmp(opt->name, "mode")) {
			zhash_update(self->team_mode, key, nmsg);
			zhash_freefn(self->team_mode, key, free_nmsg);
		} else if (!strcmp(opt->name, "bpf_hash_func")) {
			zhash_update(self->team_recipe, key, nmsg);
			zhash_freefn(self->team_recipe, key, free_nmsg);
		} else if (!strcmp(opt->name, "activeport")) {
			zhash_update(self->team_activeport, key, nmsg);
			zhash_freefn(self->team_activeport, key, free_nmsg);
		}
	} else if (desc.cmd == TEAM_CMD_PORT_LIST_GET) {
		struct team_port_info *opt = zlist_first(desc.infolist);

		if (opt->removed) {
			zhash_delete(self->team_port, key);
			delete_dependent_team_port_entries(self, key);
		} else {
			zhash_update(self->team_port, key, nmsg);
			zhash_freefn(self->team_port, key, free_nmsg);
		}
	}

	team_msg_data_free(&desc);
}

/*
 * Message (over pipe) from publisher thread.
 * If the key is "INIT COMPLETE" then return 1.
 * The request thread will begin receiving
 * requests from dataplanes.
 *
 */
int snapshot_update(snapshot_t *self, nlmsg_t *nmsg)
{
	const char *key = nlmsg_key(nmsg);

	if (strncmp(key, "INIT COMPLETE", 13) == 0) {
		nlmsg_free(nmsg);
		return 1;
	}

	if (debug > 1)
		nlmsg_dump("store", nmsg);

	self->last_seqno = nlmsg_seqno(nmsg);

	/* TODO: use RTM_FAM() to make this table driven */
	if (strstr(key, "xfrm") != NULL)
		snapshot_handle_xfrm_msg(self, nmsg);
	else if (strstr(key, "l2tp") != NULL)
		snapshot_handle_l2tp_msg(self, nmsg);
	else if (is_team_msg(key))
		snapshot_handle_team_msg(self, nmsg);
	else
		snapshot_handle_non_xfrm_msg(self, nmsg);
	return 0;
}

typedef struct {
	void     *socket;	/* socket to send to */
	zframe_t *client;	/* identity of client requesting */
} target_t;

/* Callback from iterator to send stored data */
static int send_nmsg(const char *key __unused, void *data, void *arg)
{
	target_t *target = arg;
	nlmsg_t *nmsg = NULL;

	if (zframe_send(&target->client, target->socket,
			ZFRAME_MORE + ZFRAME_REUSE)) {
		err("zframe_send snapshot envelope failed: %s",
		    strerror(errno));
		return 1;
	}

	nmsg = data;
	if (debug)
		nlmsg_dump("send", nmsg);
	nlmsg_send(nlmsg_copy(nmsg), target->socket);
	return 0;
}

/* Callback from iterator to send stored data */
static int send_nmsg_xfrm(const char *key __unused, void *data, void *arg)
{
	target_t *target = arg;
	nlmsg_t *nmsg = NULL;

	if (zframe_send(&target->client, target->socket,
			ZFRAME_MORE + ZFRAME_REUSE)) {
		err("zframe_send snapshot envelope failed: %s",
		    strerror(errno));
		return 1;
	}

	nmsg = data;
	if (debug)
		nlmsg_dump("send", nmsg);
	nlmsg_send(nlmsg_copy(nmsg), target->socket);
	return 0;
}

/* Callback from iterator to send stored data */
static int send_nmsg_l2tp(const char *key __unused, void *data, void *arg)
{
	target_t *target = arg;
	nlmsg_t *nmsg = NULL;

	if (zframe_send(&target->client, target->socket,
			ZFRAME_MORE + ZFRAME_REUSE)) {
		err("zframe_send snapshot envelope failed: %s",
		    strerror(errno));
		return 1;
	}

	nmsg = data;
	if (debug)
		nlmsg_dump("send", nmsg);
	nlmsg_send(nlmsg_copy(nmsg), target->socket);
	return 0;
}

/* Dump current contents of link, address, route and neighbour tables. */
void snapshot_send(snapshot_t *self, void *socket, zframe_t *to)
{
	target_t target = { socket, to };

#ifdef RTNLGRP_RTDMN
	snapshot_iterator(self->vrf, send_nmsg, &target, false);
#endif
	snapshot_iterator(self->vrf_master, send_nmsg, &target, true);
	snapshot_iterator(self->link, send_nmsg, &target, true);
	snapshot_iterator(self->team_mode, send_nmsg, &target, false);
	snapshot_iterator(self->team_recipe, send_nmsg, &target, false);
	snapshot_iterator(self->team_port, send_nmsg, &target, false);
	snapshot_iterator(self->slave_link, send_nmsg, &target, true);
	snapshot_iterator(self->vlan, send_nmsg, &target, true);
	snapshot_iterator(self->bridge_link, send_nmsg, &target, false);
	snapshot_iterator(self->address, send_nmsg, &target, false);
	snapshot_iterator(self->route, send_nmsg, &target, false);
	snapshot_iterator(self->neighbour, send_nmsg, &target, false);
	snapshot_iterator(self->netconf, send_nmsg, &target, false);
	snapshot_iterator(self->xfrm, send_nmsg_xfrm, &target, false);
	snapshot_iterator(self->l2tp_tunnel, send_nmsg_l2tp, &target, false);
	snapshot_iterator(self->l2tp_session, send_nmsg_l2tp, &target, false);
	snapshot_iterator(self->team_select, send_nmsg, &target, false);
	snapshot_iterator(self->team_activeport, send_nmsg, &target, false);
	snapshot_iterator(self->qdisc, send_nmsg, &target, false);
	snapshot_iterator(self->filter, send_nmsg, &target, true);
	snapshot_iterator(self->chain, send_nmsg, &target, false);
}
