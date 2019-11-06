/*
 * Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
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
#include <linux/if.h>

#include "cpputest_comparators.h"

extern "C" {

#include "vplane.h"
#include "CppUTestExt/MockSupport_c.h"

#define VCOUNT 7
static struct {
	const vplane_t *vp;
	const char *uuid;
	const char *ip;
	zframe_t *session;
} vplanes [VCOUNT];

int port_state_change(const vplane_t *vp, uint32_t port, uint32_t ifindex,
		      uint32_t operstate)
{
	return 0;
}

int zmsg_popu32(zmsg_t *msg, uint32_t *p)
{
	return 0;
}

}

TEST_GROUP(vplane)
{
	AddrComparator ipComparator;

	void setup(void) {
		mock().installComparator("struct ip_addr", ipComparator);
		vplane_setup();
		if (vplanes[0].uuid == NULL) {
			char buf[INET6_ADDRSTRLEN];
			int i;

			for (i = 0; i < VCOUNT; i++) {
				uint32_t sid;

				snprintf(buf, sizeof(buf), "10.%d.1.1", i);
				vplanes[i].vp = NULL;
				zuuid_t *zuuid = zuuid_new();
				vplanes[i].uuid = strdup(zuuid_str(zuuid));
				vplanes[i].ip = strdup(buf);
				sid = htonl(i+1);
				vplanes[i].session = zframe_new(&sid, sizeof(sid));
				zuuid_destroy(&zuuid);
			}
		}
	}

	void teardown(void) {
		mock().checkExpectations();
		mock().clear();
		mock().removeAllComparatorsAndCopiers();

		mock().disable();
		vplane_disconnect_all();
		vplane_teardown();
		int i;
		for (i = 0; i < VCOUNT; i++) {
			free((char *)vplanes[i].uuid);
			vplanes[i].uuid = NULL;
			free((char *)vplanes[i].ip);
			vplanes[i].ip = NULL;
			zframe_destroy(&vplanes[i].session);
		}
		mock().enable();
	}
};

TEST(vplane, setup)
{
	vplane_tick();
	vplane_cfg_begin();
	vplane_cfg_end();

	CHECK(vplane_findbyuuid(NULL) == NULL);
	CHECK(vplane_findbysession(NULL) == NULL);
	CHECK(vplane_get_id(NULL) == -1);
	CHECK(vplane_get_uuid(NULL) == NULL);
	CHECK(vplane_get_control(NULL) == NULL);
	CHECK(vplane_set_control(NULL, NULL) < 0);

	mock().expectNCalls(3, "logit")
		.withParameter("level", LOG_ERR);

	CHECK(vplane_iface_get_ifname(NULL, 0) == NULL);
	CHECK(vplane_iface_get_ifindex(NULL, 0) == 0);
	CHECK(vplane_iface_set_state(NULL, 0, IF_OPER_UP) < 0);
}

TEST(vplane, configure)
{
	int i;

	mock().disable();

	/*
	 * Generate the configured vplanes
	 */
	vplane_cfg_begin();
	for (i = 0; i < VCOUNT; i++) {
		CHECK(vplane_cfg_set_attribute(i+1, "uuid", vplanes[i].uuid) == PARSE_OK);
		CHECK(vplane_cfg_set_attribute(i+1, "ip", vplanes[i].ip) == PARSE_OK);
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == NULL);
	}

	/*
	 * Commit the configuration
	 */
	vplane_cfg_end();

	for (i = 0; i < VCOUNT; i++) {
		vplanes[i].vp = vplane_findbyuuid(vplanes[i].uuid);
		CHECK(vplanes[i].vp != NULL);
		CHECK(vplane_get_id(vplanes[i].vp) == i+1);
	}

	/*
	 * Cleanup by generating & committing an "empty" configuration &
	 * running the timer to purge dead entries.
	 */
	vplane_cfg_begin();
	vplane_cfg_end();
	vplane_tick();

	for (i = 0; i < VCOUNT; i++)
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == NULL);

	/*
	 * Now generate a configuration but report a parser error
	 */
	vplane_cfg_begin();
	for (i = 0; i < VCOUNT; i++) {
		CHECK(vplane_cfg_set_attribute(i+1, "uuid", vplanes[i].uuid) == PARSE_OK);
		CHECK(vplane_cfg_set_attribute(i+1, "ip", vplanes[i].ip) == PARSE_OK);
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == NULL);
	}
	vplane_cfg_failed();

	for (i = 0; i < VCOUNT; i++) {
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == NULL);
	}

	mock().enable();
}

TEST(vplane, update)
{
	int i, j;

	mock().disable();

	vplane_cfg_begin();
	for (i = 0; i < VCOUNT; i++) {
		CHECK(vplane_cfg_set_attribute(i+1, "uuid", vplanes[i].uuid) == PARSE_OK);
		CHECK(vplane_cfg_set_attribute(i+1, "ip", vplanes[i].ip) == PARSE_OK);
		vplane_test_set_timeout(i+1, 1);
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == NULL);
	}
	vplane_cfg_end();

	/*
	 * Check and connect the vplanes
	 */
	for (i = 0; i < VCOUNT; i++) {
		vplane_t *vp;

		vp = vplane_findbyuuid(vplanes[i].uuid);
		CHECK(vp != NULL);
		vplanes[i].vp = vp;
		CHECK(vplane_get_id(vp) == i+1);
		CHECK(0 == vplane_connect(vp, vplanes[i].session));
		CHECK(vplane_is_connected(vp));
	}

	/*
	 * Now generate a new configuration consisting of the first few
	 * entries, essentially merge some of the vplanes and
	 * un-configure the rest.
	 */
	vplane_cfg_begin();
	for (i = 0; i < VCOUNT/2; i++) {
		CHECK(vplane_cfg_set_attribute(i+1, "uuid", vplanes[i].uuid) == PARSE_OK);
		CHECK(vplane_cfg_set_attribute(i+1, "ip", vplanes[i].ip) == PARSE_OK);
		vplane_test_set_timeout(i+1, 10);
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == vplanes[i].vp);
	}
	vplane_cfg_end();

	/*
	 * Remove the "old" vplane instances.
	 */
	for (j = i; j < VCOUNT; j++) {
		CHECK(!vplane_is_connected(vplanes[j].vp));
		vplanes[j].vp = NULL;
	}

	/*
	 * Simulate the reception of a "hello" message, even for vplanes
	 * that have been eliminated from the configuration.
	 */
	for (i = 0; i < VCOUNT; i++)
		vplane_keepalive(vplane_findbysession(vplanes[i].session),
				 "hello", -1);

	/*
	 * Tick the clock so as to expire & delete the old vplanes
	 */
	zclock_sleep(2);
	vplane_tick();

	/*
	 * Ensure the new vplanes are still connected and that the old
	 * vplanes have been deleted.
	 */
	for (i = 0; i < VCOUNT; i++) {
#if defined(LOGIT)
		printf("vplane %d %p %p\n", i+1,
		       vplane_findbyuuid(vplanes[i].uuid),
		       vplanes[i].vp);
#endif

		CHECK(vplanes[i].vp == vplane_findbysession(vplanes[i].session));
		CHECK(vplanes[i].vp == vplane_findbyuuid(vplanes[i].uuid));
	}

	mock().enable();
}

TEST(vplane, errors)
{
	mock().expectNCalls(1, "logit")
		.withParameter("level", LOG_ERR);

	vplane_cfg_begin();

	CHECK(vplane_cfg_set_attribute(4, "timeout", "1") == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(4, "uuid", vplanes[3].uuid) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(4, "ip", "10.1.1") == PARSE_ERR);
	CHECK(vplane_findbyuuid(vplanes[4].uuid) == NULL);
	vplane_cfg_end();

	mock().expectNCalls(2, "logit")
		.withParameter("level", LOG_ERR);

	CHECK(vplane_cfg_set_attribute(1, "timeout", "1") == PARSE_ERR);
	CHECK(vplane_cfg_set_attribute(1, "uuid", vplanes[0].uuid) == PARSE_ERR);

	CHECK(vplane_connect(NULL, vplanes[2].session) < 0);
	CHECK(vplane_findbysession(vplanes[2].session) == NULL);
}

TEST(vplane, connect)
{
	const vplane_t *vp;
	int i;
	char buf[16];

	mock().disable();

	vplane_cfg_begin();
	for (i = 0; i < VCOUNT; i++) {
		snprintf(buf, sizeof(buf), "%d", i);
		CHECK(vplane_cfg_set_attribute(i+1, "uuid", vplanes[i].uuid) == PARSE_OK);
		CHECK(vplane_cfg_set_attribute(i+1, "ip", vplanes[i].ip) == PARSE_OK);
		/*
		 * Use test interface to set a short (millisecond)
		 * timeout value
		 */
		vplane_test_set_timeout(i+1, i);
		CHECK(vplane_findbyuuid(vplanes[i].uuid) == NULL);
	}
	vplane_cfg_end();

	for (i = 0; i < VCOUNT; i++) {
		vplane_t *vp;

		vp = vplane_findbyuuid(vplanes[i].uuid);
		CHECK(vp != NULL);
		CHECK(vplane_connect(vp, vplanes[i].session) == 0);
		vplanes[i].vp = vp;
	}

	for (i = 0; i < VCOUNT; i++) {
		const vplane_t *vp2;

		vp = vplane_findbysession(vplanes[i].session);
		vp2 = vplane_findbyuuid(vplanes[i].uuid);
		CHECK(vp != NULL);
		CHECK(vp == vp2);
		CHECK(vplane_is_connected(vp));
	}

	/*
	 * Tick the clock 2 milliseconds, i.e. expire the first two sessions
	 */
	zclock_sleep(2);
	vplane_tick();

	CHECK(vplane_findbysession(vplanes[0].session) == NULL);
	CHECK(vplane_findbysession(vplanes[1].session) == NULL);
	CHECK(vplane_findbysession(vplanes[VCOUNT-1].session) != NULL);
	zclock_sleep(VCOUNT);
	vplane_tick();
	for (i = 0; i < VCOUNT; i++) {
		CHECK(vplane_findbysession(vplanes[0].session) == NULL);
		CHECK(!vplane_is_connected(vp));
	}
}

TEST(vplane, interface)
{
	const char *addrstr = "10.1.1.1";
	vplane_t *vp;
	int idx = 0;

	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(idx+1, "uuid", vplanes[idx].uuid) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(idx+1, "ip", addrstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(vplanes[idx].uuid);
	CHECK(vp != NULL);
	CHECK(vplane_connect(vp, vplanes[idx].session) == 0);

	CHECK(vplane_iface_add(vp, 1, 1001, "s1") == 0);
	CHECK(vplane_iface_get_ifindex(vp, 1) == 1001);
	CHECK(streq("s1", vplane_iface_get_ifname(vp, 1)));

	CHECK(vplane_iface_set_state(vp, 1, IF_OPER_DOWN) == 0);
	CHECK(vplane_iface_set_state(vp, 1, IF_OPER_UP) == 0);

	vplane_iface_del(vp, 1);

	CHECK(vplane_iface_add(vp, 2, 1002, "s2") == 0);
	CHECK(vplane_iface_get_ifindex(vp, 2) == 1002);
	CHECK(streq("s2", vplane_iface_get_ifname(vp, 2)));

	CHECK(vplane_iface_add(vp, 2, 1003, "s2") == 0);
	CHECK(vplane_iface_get_ifindex(vp, 2) == 1003);
	CHECK(streq("s2", vplane_iface_get_ifname(vp, 2)));

	vplane_iface_del(vp, 2);

	mock().expectNCalls(1, "logit")
		.withParameter("level", LOG_ERR);
	CHECK(vplane_iface_set_state(vp, 1, IF_OPER_DOWN) < 0);

	mock().expectNCalls(2, "logit")
		.withParameter("level", LOG_ERR);
	CHECK(vplane_iface_add(vp, 256, 1001, "s1") < 0);
	CHECK(vplane_iface_get_ifindex(vp, 256) == 0);
}

TEST(vplane, address)
{
	const char *v4addrstr = "11.1.1.1";
	const char *v6addrstr = "2011::1";
	struct ip_addr addr;
	vplane_t *vp;

	addr.af = AF_INET;
	CHECK(inet_pton(AF_INET, v4addrstr, &addr.ip) == 1);

	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(3, "uuid", vplanes[2].uuid) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(3, "ip", v4addrstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(vplanes[2].uuid);
	CHECK(vp != NULL);
	CHECK(!vplane_is_local(vp));
	CHECK(3 == vplane_get_id(vp));

	/*
	 * So that's created a vplane with a particular IPv4 address,
	 * now re-configure that vplane with a V6 address.
	 */
	vplane_t *oldvp = vp;

	addr.af = AF_INET6;
	CHECK(inet_pton(AF_INET6, v6addrstr, &addr.ip) == 1);

	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(3, "uuid", vplanes[2].uuid) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(3, "ip", v6addrstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(vplanes[2].uuid);
	CHECK(vp != NULL);
	CHECK(vp == oldvp);
	CHECK(!vplane_is_local(vp));
	CHECK(3 == vplane_get_id(vp));
}

TEST(vplane, identifier)
{
	const char *v4addrstr = "11.1.1.1";
	struct ip_addr addr;
	vplane_t *vp;

	addr.af = AF_INET;
	CHECK(inet_pton(AF_INET, v4addrstr, &addr.ip) == 1);

	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(1, "uuid", vplanes[2].uuid) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(1, "ip", v4addrstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(vplanes[2].uuid);
	CHECK(vp != NULL);
	CHECK(!vplane_is_local(vp));
	CHECK(1 == vplane_get_id(vp));

	/*
	 * Having defined the vplane instance, keep the UUID & address,
	 * but change the index. The equivalent of "moving" a dataplane
	 * configuration (dp1 -> dp101).
	 */
	vplane_t *oldvp = vp;

	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(101, "uuid", vplanes[2].uuid) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(101, "ip", v4addrstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(vplanes[2].uuid);
	CHECK(vp != NULL);
	CHECK(vp == oldvp);
	CHECK(!vplane_is_local(vp));
	CHECK(101 == vplane_get_id(vp));
}

TEST(vplane, local)
{
	const char *addrstr = "127.0.0.1";
	const char *uuidstr = "00000000-0000-0000-0000-000000000000";
	struct ip_addr addr;
	vplane_t *vp;

	addr.af = AF_INET;
	CHECK(inet_pton(AF_INET, addrstr, &addr.ip) == 1);

	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(0, "ip", addrstr) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(0, "uuid", uuidstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(uuidstr);
	CHECK(vp != NULL);
	CHECK(0 == vplane_get_id(vp));
	CHECK(vplane_is_local(vp));

	CHECK(vplane_local_connect(vp, vplanes[0].session) == 0);
	CHECK(vplane_is_connected(vp));
}
