/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <string.h>
#include <czmq.h>
#include <linux/rtnetlink.h>

#include "stubs.h"
#include "cpputest_comparators.h"

extern "C" {

#include "controller.h"
#include "CppUTestExt/MockSupport_c.h"

struct mynlmsg {
	struct nlmsghdr *nlh;
	char *topic;
	uint32_t ifindex;
};

void fsnotify_add_mpls_watchers(void)
{
	CPPUTEST_STUB_RET;
}

void fsnotify_add_redirects_watchers(void)
{
	CPPUTEST_STUB_RET;
}

static struct mynlmsg *mynlmsg_alloc(int nlmsg_type, uint32_t ifindex, int id)
{
	struct mynlmsg *msg = (struct mynlmsg *)calloc(1, sizeof(*msg));
	struct nlmsghdr *nlh;
	struct nlmsghdr _nlh;
	char buf[1024];
	size_t sz;

	if (msg == NULL)
		return NULL;

	_nlh.nlmsg_type = nlmsg_type;
	snprintf(buf, sizeof(buf), "%s %d %d",
		 nlmsg_type_name_rtnl(&_nlh),
		 ifindex, id);
	msg->topic = strdup(buf);
	msg->ifindex = ifindex;
	snprintf(buf, sizeof(buf), "netlink data %s", msg->topic);

	sz = NLMSG_LENGTH(strlen(buf)) + 1;
	nlh = (struct nlmsghdr *)malloc(sz);
	memset(nlh, 0, sz);
	nlh->nlmsg_len = sz;
	nlh->nlmsg_type = nlmsg_type;
	memcpy(NLMSG_DATA(nlh), buf, strlen(buf)+1);
	msg->nlh = nlh;
	return msg;
}

static void mynlmsg_free(struct mynlmsg **msgp)
{
	struct mynlmsg *msg = *msgp;

	*msgp = NULL;
	free(msg->topic);
	free(msg->nlh);
	msg->ifindex = -1;
	free(msg);
}

static nlmsg_t *find_nlmsg(const struct mynlmsg *msg, zlist_t *list)
{
	nlmsg_t *nlmsg;

	for (nlmsg = (nlmsg_t *)zlist_first(list);
	     nlmsg != NULL;
	     nlmsg = (nlmsg_t *)zlist_next(list)) {
		if ((strcmp(msg->topic, nlmsg_key(nlmsg)) == 0) &&
		    (memcmp(msg->nlh,
			    nlmsg_data(nlmsg),
			    msg->nlh->nlmsg_len) == 0))
		    return nlmsg;
	}

	return NULL;
}

static zlist_t *propagate_list;

void nl_propagate_nlmsg(nlmsg_t *nmsg)
{
	CHECK(zlist_append(propagate_list, nmsg) == 0);
}

}

static uint64_t msg_seqno;

TEST_GROUP(nlmsg)
{
	void setup(void) {
		mock().disable();
		msg_seqno = 0;
		debug = 1;
		propagate_list = zlist_new();
		nlmsg_setup();
		mock().enable();
	}

	void teardown(void) {
		mock().checkExpectations();
		mock().clear();
		mock().removeAllComparatorsAndCopiers();
		mock().disable();
		msg_seqno = 0;
		debug = 0;
		nlmsg_cleanup();
		zlist_destroy(&propagate_list);
		mock().enable();
	}
};

TEST(nlmsg, create_delete)
{
	const char *topic = "link 99 0";
	const char *data = "netlink message data";
	nlmsg_t *msg1;
	nlmsg_t *msg2;

	msg1 = nlmsg_new(topic, ++msg_seqno, data, strlen(data)+1);
	CHECK(msg1 != NULL);
	CHECK(nlmsg_seqno(msg1) == msg_seqno);
	CHECK(strcmp(nlmsg_key(msg1), topic) == 0);
	CHECK(strcmp((const char *)nlmsg_data(msg1), data) == 0);
	nlmsg_free(msg1);

	msg1 = nlmsg_new(topic, ++msg_seqno, data, strlen(data)+1);
	CHECK(msg1 != NULL);
	CHECK(nlmsg_seqno(msg1) == msg_seqno);

	msg2 = nlmsg_copy(msg1);
	CHECK(msg2 != NULL);
	CHECK(nlmsg_seqno(msg2) == msg_seqno);
	CHECK(strcmp(nlmsg_key(msg2), topic) == 0);
	CHECK(strcmp((const char *)nlmsg_data(msg2), data) == 0);

	nlmsg_free(msg1);
	CHECK(strcmp(nlmsg_key(msg2), topic) == 0);
	nlmsg_free(msg2);
}

TEST(nlmsg, ifindex)
{
	uint32_t ifidxs[] = {0, 99, 10, 3, 1234567, 2, 1, 0};
	uint32_t *ifindex;

	CHECK(zhashx_size(nlmsg_ifindex_hash()) == 0);

	CHECK(!nlmsg_ifindex_lookup(1));
	nlmsg_ifindex_del(1);

	ifindex = &ifidxs[1];
	while (*ifindex != 0) {
		char buf[32];

		snprintf(buf, sizeof(buf), "port-%u", *ifindex);
		CHECK(nlmsg_ifindex_add(*ifindex, buf));
		CHECK(!nlmsg_ifindex_add(*ifindex, buf));
		ifindex++;
	}

	ifindex = &ifidxs[1];
	while (*ifindex != 0) {
		CHECK(nlmsg_ifindex_lookup(*ifindex));
		ifindex++;
	}

	ifindex--;
	while(*ifindex != 0) {
		nlmsg_ifindex_del(*ifindex);
		CHECK(!nlmsg_ifindex_lookup(*ifindex));
		ifindex--;
	}

	CHECK(zhashx_size(nlmsg_ifindex_hash()) == 0);
}

TEST(nlmsg, pending)
{
	zlist_t *msglist = zlist_new();
	uint32_t ifindex1 = 10;
	struct mynlmsg *msg;
	size_t count = 4;

	zlist_append(msglist,
		     mynlmsg_alloc(RTM_NEWNETCONF, ifindex1, 1));
	zlist_append(msglist,
		     mynlmsg_alloc(RTM_NEWNETCONF, ifindex1, 2));
	zlist_append(msglist,
		     mynlmsg_alloc(RTM_NEWADDR, ifindex1, 3));
	zlist_append(msglist,
		     mynlmsg_alloc(RTM_NEWADDR, ifindex1, 4));

	CHECK(zlist_size(msglist) == count);

	/*
	 * Add the netlink messages to the pending list - simulate the
	 * arrival of NETCONF & ADDR messages before the associated
	 * NEWLINK message.
	 */
	for (msg = (struct mynlmsg *)zlist_first(msglist);
	     msg != NULL;
	     msg = (struct mynlmsg *)zlist_next(msglist)) {
		nlmsg_pending_add(msg->topic, msg->nlh, msg->ifindex);
	}

	CHECK(zlist_size(nlmsg_pending_list()) == count);

	for (msg = (struct mynlmsg *)zlist_first(msglist);
	     msg != NULL;
	     msg = (struct mynlmsg *)zlist_next(msglist)) {
		nlmsg_t *nlmsg;

		nlmsg = find_nlmsg(msg, nlmsg_pending_list());
		CHECK(nlmsg != NULL);
	}

	/*
	 * Unexpected arrival of a DELLINK message, ensure the pending
	 * messages are purged.
	 */
	nlmsg_ifindex_del(ifindex1);
	CHECK(zlist_size(nlmsg_pending_list()) == 0);

	for (msg = (struct mynlmsg *)zlist_first(msglist);
	     msg != NULL;
	     msg = (struct mynlmsg *)zlist_next(msglist)) {
		nlmsg_pending_add(msg->topic, msg->nlh, msg->ifindex);
	}

	/*
	 * Simulate the arrival of the corresponding NEWLINK
	 */
	nlmsg_pending_propagate(ifindex1, &msg_seqno);
	CHECK(zlist_size(nlmsg_pending_list()) == 0);
	CHECK(zlist_size(propagate_list) == count);

	/*
	 * Have all the messages been "published"?
	 */
	for (msg = (struct mynlmsg *)zlist_first(msglist);
	     msg != NULL;
	     msg = (struct mynlmsg *)zlist_next(msglist)) {
		nlmsg_t *nlmsg;

		nlmsg = find_nlmsg(msg, propagate_list);
		CHECK(nlmsg != NULL);
		zlist_remove(propagate_list, nlmsg);
		nlmsg_free(nlmsg);
	}

	CHECK(zlist_size(propagate_list) == 0);

	while ((msg = (struct mynlmsg *)zlist_pop(msglist)) != NULL)
	       mynlmsg_free(&msg);

	CHECK(zlist_size(msglist) == 0);
	zlist_destroy(&msglist);
}
