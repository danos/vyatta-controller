/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <sys/time.h>

#include <czmq.h>
#include "stubs.h"
#include "cpputest_comparators.h"

extern "C" {

#include "controller.h"
#include "CppUTestExt/MockSupport_c.h"

#include <libmnl/libmnl.h>

#ifndef RD_DEFAULT
#define RD_DEFAULT 1
#endif

#ifndef RTA_RTG_DOMAIN
#define RTA_RTG_DOMAIN 32
#endif

#define S_TOPIC_BUFSIZ 128

void team_msg_data_free(struct team_msg_desc *desc)
{
	CPPUTEST_STUB_RET;
}

int process_genetlink_teamcmd(const struct nlmsghdr *nlh,
			      struct team_msg_desc *desc)
{
	CPPUTEST_STUB_RET_VAL(-1);
}

void fsnotify_add_mpls_watchers(void)
{
	CPPUTEST_STUB_RET;
}

void fsnotify_add_redirects_watchers(void)
{
	CPPUTEST_STUB_RET;
}

}

struct s_prefix {
	struct ip_addr addr;
	uint8_t len;
};

struct s_nexthop {
	uint32_t nh_ifindex;
	struct ip_addr nh_addr;
};

#define S_MAX_NHS 32

struct s_route {
	struct s_prefix prefix;
	uint32_t vrf_id;
	uint32_t tableid;
	uint32_t scope;
	int nh_cnt;
	struct s_nexthop nh[S_MAX_NHS];
};

static uint32_t snap_sessionid = htonl(0x1);
static zframe_t *snap_client;
static zsock_t *snap_write;
static zsock_t *snap_read;
static uint64_t snap_seqno;

static int snap_update(snapshot_t *snap, const char *topic,
		       const struct nlmsghdr *nlh)
{
	nlmsg_t *nmsg;

	nmsg = nlmsg_new(topic, ++snap_seqno, nlh, nlh->nlmsg_len);
	CHECK(nmsg != NULL);
	return snapshot_update(snap, nmsg);
}

static void snap_complete(snapshot_t *snap)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);

	CHECK(snap_update(snap, "INIT COMPLETE", nlh) == 1);
}

static void snap_end(snapshot_t *snap)
{
	const char *topic = "THATSALLFOLKS!";
	nlmsg_t *nmsg = nlmsg_new(topic, ++snap_seqno, "", 0);

	CHECK(nmsg != NULL);
	zframe_send(&snap_client, snap_write, ZFRAME_MORE+ZFRAME_REUSE);
	nlmsg_send(nmsg, snap_write);
}

static void snap_collect_free(void *m)
{
	zmsg_t *msg = (zmsg_t *)m;

	zmsg_destroy(&msg);
}

static int snap_collect(snapshot_t *snap, zlist_t *msgs)
{
	zmsg_t *msg;
	int done = 0;

	CHECK(snap != NULL);
	CHECK(msgs != NULL);

	/*
	 * Get the snapshot module to issue all known entries
	 */
	snapshot_send(snap, snap_write, snap_client);
	snap_end(snap);

	/*
	 * Now read each message. Each message consists of:
	 *
	 *  - a 0MQ client ID (session ID)
	 *  - the topic as derived from the netlink message
	 *  - the message sequence number
	 *  - the netlink data
	 *
	 * The session ID is discarded and the "raw" message is appended
	 * to the supplied list.
	 */
	while (!done && (msg = zmsg_recv(snap_read)) != NULL) {
		zframe_t *fr;

//		zmsg_dump(msg);
		fr = zmsg_pop(msg);
		CHECK(fr != NULL);
		CHECK(zframe_eq(fr, snap_client));
		zframe_destroy(&fr);

		fr = zmsg_first(msg);
		if (!zframe_streq(fr, "THATSALLFOLKS!")) {
			zlist_append(msgs, msg);
			zlist_freefn(msgs, msg, snap_collect_free, true);
		} else {
			done = 1;
			zmsg_destroy(&msg);
		}
	}

	return zlist_size(msgs);
}

/*
 * Search the list of netlink messages and ensure that the supplied
 * topic is present. Then remove and destroy the message.
 */
static int snap_check_msg(zlist_t *list, const char *topic)
{
	void *nlmsg;
	int found = 0;

	for (nlmsg = zlist_first(list);
	     nlmsg != NULL;
	     nlmsg = zlist_next(list)) {
		zframe_t *fr;

		fr = zmsg_first((zmsg_t *)nlmsg);
		if (zframe_streq(fr, topic)) {
			found++;
			zlist_remove(list, nlmsg);
		}
	}

	return found;
}

static void route_init(struct s_route *route)
{
	memset(route, 0, sizeof(*route));
	route->vrf_id = RD_DEFAULT;
	route->tableid = RT_TABLE_MAIN;
	route->scope = RT_SCOPE_UNIVERSE;
}

static bool route_addr(const char *s, struct ip_addr *addr)
{
	if (inet_pton(AF_INET, s, &addr->ip.v4) == 1) {
		addr->af = AF_INET;
		return true;
	}

	if (inet_pton(AF_INET6, s, &addr->ip.v6) == 1) {
		addr->af = AF_INET6;
		return true;
	}

	addr->af = AF_UNSPEC;
	return false;
}

static uint8_t route_addr_size(const struct ip_addr *addr)
{
	switch (addr->af) {
	case AF_INET:
		return sizeof(addr->ip.v4.s_addr);
	case AF_INET6:
		return sizeof(addr->ip.v6);
	default:
		return 0;
	}
}

static void route_prefix(struct s_route *route, const char *s, int len)
{
	CHECK(route_addr(s, &route->prefix.addr));
	route->prefix.len = len;
}

static void route_nexthop(struct s_route *route, const char *s, int ifindex)
{
	struct s_nexthop *nh;

	nh = &route->nh[route->nh_cnt];
	nh->nh_ifindex = ifindex;
	CHECK(route_addr(s, &nh->nh_addr));
	route->nh_cnt++;
}

static void route_netlink_mpath(struct s_route *route, struct nlmsghdr *nlh)
{
	struct s_nexthop *nh;
	struct rtnexthop *rtnh;
	int i;

	for (i = 0; i < route->nh_cnt; i++) {
		nh = &route->nh[i];

		/*
		 * For now only support nexthop's for the same AF
		 */
		CHECK(route->prefix.addr.af == nh->nh_addr.af);

		rtnh = (struct rtnexthop *)
			mnl_nlmsg_get_payload_tail(nlh);
		nlh->nlmsg_len += MNL_ALIGN(sizeof(*rtnh));
		memset(rtnh, 0, sizeof(*rtnh));
		rtnh->rtnh_ifindex = nh->nh_ifindex;
		mnl_attr_put_u32(nlh, RTA_OIF, nh->nh_ifindex);
		mnl_attr_put(nlh, RTA_GATEWAY, route_addr_size(&nh->nh_addr),
			     &nh->nh_addr.ip);
		rtnh->rtnh_len = ((char *)mnl_nlmsg_get_payload_tail(
					  nlh) - (char *)rtnh);
	}
}

static struct nlmsghdr *
route_netlink(struct s_route *route, int type, bool replace,
	      char *nlhbuf, size_t nlhbufsz)
{
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	memset(nlhbuf, 0, nlhbufsz);
	nlh = mnl_nlmsg_put_header(nlhbuf);

	switch (type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		nlh->nlmsg_type = type;
		break;
	default:
		CHECK_TEXT(0, "unexpected NL type");
		return NULL;
	}

	nlh->nlmsg_flags = NLM_F_ACK;
	if (replace)
		nlh->nlmsg_flags |= NLM_F_REPLACE;

	rtm = (struct rtmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
	rtm->rtm_family = route->prefix.addr.af;
	rtm->rtm_dst_len = route->prefix.len;
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0;
	rtm->rtm_table = route->tableid;
	rtm->rtm_protocol = RTPROT_UNSPEC;
	rtm->rtm_scope = route->scope;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_flags = 0;

	/*
	 * RTA_UNSPEC,
	 * RTA_DST,
	 *  ---- RTA_SRC,
	 *  ---- RTA_IIF,
	 * RTA_OIF,      (depending on route type)
	 * RTA_GATEWAY,  (depending on route type)
	 *  ---- RTA_PRIORITY,
	 *  ---- RTA_PREFSRC,
	 *  ---- RTA_METRICS,
	 *  ---- RTA_MULTIPATH,
	 *  ---- RTA_PROTOINFO, // no longer used
	 *  ---- RTA_FLOW,
	 *  ---- RTA_CACHEINFO,
	 *  ---- RTA_SESSION, // no longer used
	 *  ---- RTA_MP_ALGO, // no longer used
	 * RTA_ENCAP_TYPE, (if outlabels present)
	 * RTA_ENCAP,    (if outlabels present)
	 * RTA_TABLE,
	 *  ---- RTA_MARK,
	 *  ---- RTA_MFC_STATS,
	 */
	mnl_attr_put(nlh, RTA_DST,
		     route_addr_size(&route->prefix.addr),
		     &route->prefix.addr.ip);

	mnl_attr_put_u32(nlh, RTA_TABLE, route->tableid);
	if (route->vrf_id != RD_DEFAULT)
		mnl_attr_put_u32(nlh, RTA_RTG_DOMAIN, route->vrf_id);

	if ((route->nh_cnt > 1) && (route->prefix.addr.af == AF_INET)) {
		struct nlattr *mpath_start;

		mpath_start = mnl_attr_nest_start(nlh, RTA_MULTIPATH);
		route_netlink_mpath(route, nlh);
		mnl_attr_nest_end(nlh, mpath_start);
	} else {
		struct s_nexthop *nh;

		nh = &route->nh[0];
		if (nh->nh_ifindex)
			mnl_attr_put_u32(nlh, RTA_OIF, nh->nh_ifindex);

		if (route->prefix.addr.af == nh->nh_addr.af)
			mnl_attr_put(nlh, RTA_GATEWAY, route_addr_size(&nh->nh_addr),
				     &nh->nh_addr.ip);
	}

	return nlh;
}

TEST_GROUP(snapshot)
{
	void setup(void) {
		int portno;

		mock().disable();
		snap_seqno = 0;
		snap_client = zframe_new(&snap_sessionid,
					 sizeof(snap_sessionid));
		snap_write = zsock_new(ZMQ_PUSH);
		snap_read = zsock_new(ZMQ_PULL);

		CHECK(snap_client != NULL);
		CHECK(snap_write != NULL);
		CHECK(snap_read != NULL);

		portno = zsock_bind(snap_write, "tcp://127.0.0.1:*");
		CHECK(portno > 0);
		CHECK(zsock_connect(snap_read, "tcp://127.0.0.1:%d", portno) == 0);

		mock().enable();
	}

	void teardown(void) {
		mock().checkExpectations();
		mock().clear();
		mock().removeAllComparatorsAndCopiers();
		mock().disable();
		snap_seqno = 0;
		zsock_destroy(&snap_read);
		zsock_destroy(&snap_write);
		zframe_destroy(&snap_client);
		debug = 0;
		mock().enable();
	}
};

TEST(snapshot, create_delete)
{
	snapshot_t *snap = NULL;

	snapshot_destroy(&snap);
	snap = snapshot_new();
	CHECK(snap != NULL);
	snapshot_destroy(&snap);
	CHECK(snap == NULL);
}

TEST(snapshot, route_create_delete)
{
	snapshot_t *snap = NULL;
	struct s_route r1;
	char topic[S_TOPIC_BUFSIZ];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	zlist_t *zmsgs = zlist_new();

	snap = snapshot_new();
	CHECK(snap != NULL);
	snap_complete(snap);

	route_init(&r1);
	route_prefix(&r1, "192.168.1.0", 24);
	route_nexthop(&r1, "192.168.1.1", 10);
	nlh = route_netlink(&r1, RTM_NEWROUTE, false, buf, sizeof(buf));

	CHECK(nlh != NULL);
	CHECK(nl_generate_topic(nlh, topic, sizeof(topic)) >= 0);
	CHECK(snap_update(snap, topic, nlh) == 0);

	CHECK(snap_collect(snap, zmsgs) == 1);

	CHECK(snap_check_msg(zmsgs, topic) == 1);

	CHECK(zlist_size(zmsgs) == 0);

	r1.nh_cnt = 0;
	route_nexthop(&r1, "192.168.2.1", 10);
	nlh = route_netlink(&r1, RTM_NEWROUTE, true, buf, sizeof(buf));
	CHECK(nlh != NULL);
	CHECK(nl_generate_topic(nlh, topic, sizeof(topic)) >= 0);
	CHECK(snap_update(snap, topic, nlh) == 0);

	CHECK(snap_collect(snap, zmsgs) == 1);

	CHECK(snap_check_msg(zmsgs, topic) == 1);

	nlh = route_netlink(&r1, RTM_DELROUTE, false, buf, sizeof(buf));
	CHECK(nlh != NULL);
	CHECK(nl_generate_topic(nlh, topic, sizeof(topic)) >= 0);

	CHECK(snap_update(snap, topic, nlh) == 0);

	CHECK(snap_collect(snap, zmsgs) == 0);

	zlist_destroy(&zmsgs);
	snapshot_destroy(&snap);
	CHECK(snap == NULL);
}

TEST(snapshot, ifindex)
{
	snapshot_t *snap = NULL;
	struct s_route r1;
	char topic1[S_TOPIC_BUFSIZ];
	char topic2[S_TOPIC_BUFSIZ];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	zlist_t *zmsgs = zlist_new();

	snap = snapshot_new();
	CHECK(snap != NULL);
	snap_complete(snap);

	route_init(&r1);
	route_prefix(&r1, "192.168.1.0", 24);
	route_nexthop(&r1, "192.168.1.1", 10);
	nlh = route_netlink(&r1, RTM_NEWROUTE, false, buf, sizeof(buf));
	CHECK(nlh != NULL);
	CHECK(nl_generate_topic(nlh, topic1, sizeof(topic1)) >= 0);
	CHECK(snap_update(snap, topic1, nlh) == 0);

	route_init(&r1);
	route_prefix(&r1, "192.168.2.0", 24);
	route_nexthop(&r1, "192.168.2.1", 11);
	nlh = route_netlink(&r1, RTM_NEWROUTE, false, buf, sizeof(buf));
	CHECK(nlh != NULL);
	CHECK(nl_generate_topic(nlh, topic2, sizeof(topic2)) >= 0);
	CHECK(snap_update(snap, topic2, nlh) == 0);

	/*
	 * Make sure we get all (both) updates
	 */
	CHECK(snap_collect(snap, zmsgs) == 2);
	CHECK(snap_check_msg(zmsgs, topic1) == 1);
	CHECK(snap_check_msg(zmsgs, topic2) == 1);

	zlist_destroy(&zmsgs);
	snapshot_destroy(&snap);
	CHECK(snap == NULL);
}
