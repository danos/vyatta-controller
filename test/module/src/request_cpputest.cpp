/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Unit test module for exercising request & associated response
 * messages - "MYPORT", LINKDOWN, LINKUP.
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
#include <netinet/ether.h>

#include "stubs.h"
#include "cpputest_comparators.h"

extern "C" {

#include <czmq.h>
#include "controller.h"
#include "vplane.h"
#include "CppUTestExt/MockSupport_c.h"

#define VCOUNT 1
static struct {
	const char *uuid;
	const char *ip;
	uint32_t sessionid;
} vplanes [VCOUNT];

struct _snapshot {
	int dummy;
};

static const char *default_endpoint = "tcp://127.0.0.1:5924";

/*
 * Much of the request module references functions that are either not
 * interesting (part of the thread initialisation logic) or are
 * functions that are not being tested at this point - statistics,
 * snapshot. These functions are simply stubbed (rather than mocked).
 */

void set_perm(const char *path)
{
	CPPUTEST_STUB_RET;
}

nlmsg_t *nlmsg_new(const char *str, uint64_t seqno,
		   const void *data, size_t len)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

void nlmsg_dump(const char *prefix, const nlmsg_t *self)
{
	CPPUTEST_STUB_RET;
}

int nlmsg_send(nlmsg_t *self, zsock_t *socket)

{
	CPPUTEST_STUB_RET_VAL(0);
}

nlmsg_t *nlmsg_recv(const char *topic, zmsg_t *msg)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

void config_send(zsock_t *socket, zframe_t * to)

{
	CPPUTEST_STUB_RET;
}

void port_init(void)
{
	CPPUTEST_STUB_RET;
}

void port_destroy(void)
{
	CPPUTEST_STUB_RET;
}

int parser_controller_cfg(const char *fname)
{
	CHECK(fname != NULL);
	return 0;
}

int port_offline(int32_t port, uint32_t ifindex, const char *name,
		 const struct ip_addr *raddr, int32_t count)
{
	return 0;
}

int mcast_close_stats_socket(uint32_t vrf_id, uint32_t af)
{
	return 0;
}

/*
 * The following are the "interesting", and consequently mocked,
 * function invoked by the message handlers under test.
 */

int port_create(const vplane_t *vp, uint32_t port, const char *ifname,
		const struct ether_addr *eth, const char *driver,
		const char *bus, unsigned int if_flags, unsigned int mtu,
		uint32_t *ifindex)
{
	uint32_t ifidx;

	ifidx = mock_c()->getData("ifidx").value.intValue;
	*ifindex = ifidx;
	return mock_c()->actualCall("port_create")
		->withPointerParameters("vp", (void *)vp)
		->withIntParameters("port", port)
		->withStringParameters("ifname", ifname)
		->withPointerParameters("eth", (void *)eth)
		->withStringParameters("driver", driver)
		->withStringParameters("bus", bus)
		->withIntParameters("if_flags", if_flags)
		->withIntParameters("mtu", mtu)
		->withPointerParameters("ifindex", (void *)ifindex)
		->returnValue().value.intValue;
}

int port_delete(const vplane_t *vp, uint32_t port, uint32_t ifindex)
{
	return mock_c()->actualCall("port_delete")
		->withPointerParameters("vp", (void *)vp)
		->withIntParameters("port", port)
		->withIntParameters("ifindex", ifindex)
		->returnValue().value.intValue;
}

int port_state_change(const vplane_t *vp, uint32_t port, uint32_t ifindex,
		      uint32_t operstate)
{
	return mock_c()->actualCall("port_state_change")
		->withPointerParameters("vp", (void *)vp)
		->withIntParameters("port", port)
		->withIntParameters("ifindex", ifindex)
		->withIntParameters("operstate", operstate)
		->returnValue().value.intValue;
}

int port_set_stats(const char *ifname, zframe_t *data, bool aggregate, int dp_id)
{
	return mock_c()->actualCall("port_set_stats")
		->withStringParameters("ifname", ifname)
		->withPointerParameters("data", (void *)data)
		->withBoolParameters("aggregate", aggregate)
		->withIntParameters("dp_id", dp_id)
		->returnValue().value.intValue;
}

int port_set_speed(const char *ifname, unsigned speed, unsigned duplex,
		   uint32_t advertised, bool preserve)
{
	return mock_c()->actualCall("port_set_speed")
		->withStringParameters("ifname", ifname)
		->withIntParameters("speed", speed)
		->withIntParameters("duplex", duplex)
		->withIntParameters("advertised", advertised)
		->withIntParameters("preserve", preserve)
		->returnValue().value.intValue;
}

int set_sg_count(struct sioc_sg_req *sgreq)
{
	return mock_c()->actualCall("set_sg_count")
		->withPointerParameters("sgreq", (void *)sgreq)
		->returnValue().value.intValue;
}

int set_sg6_count(struct sioc_sg_req6 *sgreq)
{
	return mock_c()->actualCall("set_sg6_count")
		->withPointerParameters("sgreq", (void *)sgreq)
		->returnValue().value.intValue;
}

/*
 * Rather than attempt to use a socket and have the functions under test
 * issue a "real" send, just mock the send function and save the message
 * for later verification.
 */
static zmsg_t *replymsg;

int zmsg_send(zmsg_t **m, void *dest)
{
	int rc;

	mock_c()->actualCall("zmsg_send")
		->withPointerParameters("m", (void *)m)
		->withPointerParameters("dest", dest);

	rc = mock_c()->returnValue().value.intValue;
	if (rc == 0) {
		replymsg = *m;
		*m = NULL;
	} else {
		replymsg = NULL;
		zmsg_destroy(m);
	}

	return rc;
}


const char *get_name_by_pcislot(int slot, int func)
{
	return NULL;
}

const char *get_name_by_pciaddr(const char *pci_addr)
{
	return NULL;
}

const char *get_name_by_mac(const char *mac)
{
	return NULL;
}

const char *get_name_by_fwidx(int fwidx)
{
	return NULL;
}

const char *get_name_by_port(int port)
{
	return NULL;
}

}

static zmsg_t *test_send_request(zmsg_t *msg)
{
	replymsg = NULL;

#if defined(LOGIT)
	zmsg_dump(msg);
#endif

	request_test_msg(NULL, msg, NULL);

#if defined(LOGIT)
	if (replymsg != NULL)
		zmsg_dump(replymsg);
#endif

	return replymsg;
}

TEST_GROUP(request)
{
	AddrComparator ipComparator;

	void setup(void) {
		int i;

		mock().installComparator("struct ip_addr *",
					 ipComparator);

		if (vplanes[0].uuid == NULL) {
			char buf[INET6_ADDRSTRLEN];

			for (i = 0; i < VCOUNT; i++) {
				snprintf(buf, sizeof(buf), "10.%d.1.1", i);
				zuuid_t *zuuid = zuuid_new();
				vplanes[i].uuid = strdup(zuuid_str(zuuid));
				vplanes[i].ip = strdup(buf);
				vplanes[i].sessionid = htonl(i+1);
				zuuid_destroy(&zuuid);
			}
		}
		mock().disable();
		vplane_setup();
		vplane_cfg_begin();
		for (i = 0; i < VCOUNT; i++) {
			CHECK(vplane_cfg_set_attribute(
				      i+1, "uuid",
				      vplanes[i].uuid) == PARSE_OK);
			CHECK(vplane_cfg_set_attribute(
				      i+1, "ip", vplanes[i].ip) == PARSE_OK);
		}
		vplane_cfg_end();
		mock().enable();
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
		}
		mock().enable();
	}
};

static zmsg_t *test_build_connect(uint32_t sid, uint32_t version,
				  const char *uuid)
{
	zmsg_t *msg;

	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &sid, sizeof(sid)) == 0);
	CHECK(zmsg_addstr(msg, "CONNECT") == 0);
	CHECK(zmsg_addmem(msg, &version, sizeof(version)) == 0);
	CHECK(zmsg_addstr(msg, uuid) == 0);
	CHECK(zmsg_addstr(msg, "tcp://10.1.1.1:5907") == 0);
	return msg;
}

static void test_check_port_reply(zmsg_t *reply, uint32_t sid, bool ok,
				  uint64_t seqno, uint32_t ifindex)
{
	zframe_t *fr;

	CHECK(reply != NULL);
	fr = zmsg_first(reply);
	CHECK(zframe_size(fr) == sizeof(sid));
	CHECK(memcmp(zframe_data(fr), &sid, sizeof(sid)) == 0);
	fr = zmsg_next(reply);
	if (!ok) {
		char *errmsg = zframe_strdup(fr);
		CHECK(strncmp(errmsg, "FAIL", strlen("FAIL")) == 0);
		free(errmsg);
	} else {
		CHECK(zframe_streq(fr, "OK"));
		fr = zmsg_next(reply);
		CHECK(zframe_size(fr) == sizeof(seqno));
		CHECK(memcmp(zframe_data(fr), &seqno, sizeof(seqno)) == 0);
		fr = zmsg_next(reply);
		CHECK(zframe_size(fr) == sizeof(ifindex));
		CHECK(memcmp(zframe_data(fr), &ifindex, sizeof(ifindex)) == 0);
	}
}

static zmsg_t *test_build_port(int dpid, uint32_t sid, uint64_t seqno,
			       uint32_t ifno, struct ip_addr raddr, bool add,
			       uint32_t ifindex, char *ifname)
{
	zmsg_t *msg;

	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &sid, sizeof(sid)) == 0);
	if (add) {
		char json[BUFSIZ];
		struct ether_addr ethaddr = { 0 };

		CHECK(zmsg_addstr(msg, "NEWPORT") == 0);
		CHECK(zmsg_addmem(msg, &seqno, sizeof(seqno)) == 0);
		CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);
		snprintf(json, sizeof(json),
			 "{ \"port\":%u, \"mac\":\"%s\", \"name\":\"test%u\", "
			 "\"driver\":\"test\", \"pci-address\":\"0000:00:01.0\" }",
			 ifno, ether_ntoa(&ethaddr), ifno
			 );
		CHECK(zmsg_addstr(msg, json) == 0);
	} else {
		CHECK(zmsg_addstr(msg, "DELPORT") == 0);
		CHECK(zmsg_addmem(msg, &seqno, sizeof(seqno)) == 0);
		CHECK(zmsg_addmem(msg, &ifno, sizeof(ifno)) == 0);
		CHECK(zmsg_addmem(msg, &ifindex, sizeof(ifindex)) == 0);
		CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);
	}

	if (ifname != NULL) {
		snprintf(ifname, IFNAMSIZ, "dp%dp0s1", dpid);
	}
	return msg;
}

typedef struct _if_data {
	const char *driver;
	const char *ifname_fmt_str;
	const char *json_fmt_str;
} ifdata;

ifdata if_test_params[] = {
	{ "net_netvsc", "dp%us%u", "\"name\":\"test\", \"slot\":%u" },
	{ "rte_bond_pmd", "dp%ubond%u", "\"name\":\"dp0bond%u\"" },
	{ "rte_vhost_pmd", "dp%uvhost%u", "\"name\":\"vhost%u\"" },
	{ NULL, NULL, NULL }
};

TEST(request, funny_if_types)
{
	zmsg_t *msg;
	char json[BUFSIZ * 2];
	char json2[BUFSIZ];
	struct ether_addr ethaddr = { 0 };
	int id = 0;
	uint32_t sessionid = vplanes[id].sessionid;
	uint64_t seqno = 1;
	uint32_t ifno = 2;
	uint32_t slot = 3;
	int ifindex = 4;
	uint32_t index;
	char ifname[IFNAMSIZ];
	struct ip_addr raddr;
	zmsg_t *reply;
	vplane_t *vp;

	raddr.ip.v4.s_addr = inet_addr(vplanes[id].ip);
	raddr.af = AF_INET;

	index = 0;
	while (if_test_params[index].driver != NULL) {
		vp = vplane_findbyuuid(vplanes[id].uuid);
		CHECK(vp != NULL);

		msg = zmsg_new();
		CHECK(msg != NULL);
		CHECK(zmsg_addmem(msg, &sessionid, sizeof(sessionid)) == 0);
		CHECK(zmsg_addstr(msg, "NEWPORT") == 0);
		CHECK(zmsg_addmem(msg, &seqno, sizeof(seqno)) == 0);
		CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);
		snprintf(json2, sizeof(json2), 
			 if_test_params[index].json_fmt_str, slot);
		snprintf(json, sizeof(json),
			 "{ \"port\":%u, "
			 "  \"mac\":\"%s\", "
			 "  \"driver\":\"%s\", "
			 "  %s }",
			 ifno, ether_ntoa(&ethaddr), 
			 if_test_params[index].driver,
			 json2
			 );
		CHECK(zmsg_addstr(msg, json) == 0);
		CHECK(vplane_connect(vp, zmsg_first(msg)) == 0);

		// Workout the expected ifname
		snprintf(ifname, IFNAMSIZ, 
			 if_test_params[index].ifname_fmt_str, 
			 vplane_get_id(vp), slot);

		mock().setData("ifidx", ifindex);
		mock().expectOneCall("port_create")
			.withParameter("ifname", ifname)
			.withParameter("driver", if_test_params[index].driver)
			.ignoreOtherParameters()
			.andReturnValue(0);
		mock().expectOneCall("zmsg_send")
			.ignoreOtherParameters()
			.andReturnValue(0);
		reply = test_send_request(msg);
		zmsg_destroy(&msg);
		test_check_port_reply(reply, sessionid, true, seqno, ifindex);
		zmsg_destroy(&reply);

		// Now tidy up this port so we can try another
		seqno++;
		msg = test_build_port(id+1, sessionid, seqno, ifno, raddr,
				      false, ifindex, NULL);

		mock().expectOneCall("port_delete")
			.withParameter("ifindex", (int)ifindex)
			.ignoreOtherParameters()
			.andReturnValue(0);
		mock().expectOneCall("zmsg_send")
			.ignoreOtherParameters()
			.andReturnValue(0);

		reply = test_send_request(msg);
		zmsg_destroy(&msg);
		test_check_port_reply(reply, sessionid, true, seqno, 0);
		zmsg_destroy(&reply);

		ifno++;
		slot++;
		ifindex++;
		index++;
        }
}

TEST(request, ports)
{
	zmsg_t *msg;
	int id = 0;
	uint32_t sessionid = vplanes[id].sessionid;
	uint64_t seqno = 1;
	uint32_t ifno = 3;
	struct ip_addr raddr;
	char ifname[IFNAMSIZ];
	int ifindex = 99;
	zmsg_t *reply;
	vplane_t *vp;

	raddr.ip.v4.s_addr = inet_addr(vplanes[id].ip);
	raddr.af = AF_INET;
	vp = vplane_findbyuuid(vplanes[id].uuid);
	CHECK(vp != NULL);
	msg = test_build_port(id+1, sessionid, seqno, ifno, raddr, true,
			      0, ifname);

	CHECK(vplane_connect(vp, zmsg_first(msg)) == 0);

	mock().setData("ifidx", ifindex);
	mock().expectOneCall("port_create")
		.withParameter("ifname", ifname)
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	test_check_port_reply(reply, sessionid, true, seqno, ifindex);
	zmsg_destroy(&reply);

	seqno++;
	msg = test_build_port(id+1, sessionid, seqno, ifno, raddr, false,
			      ifindex, NULL);

	mock().expectOneCall("port_delete")
		.withParameter("ifindex", (int)ifindex)
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	test_check_port_reply(reply, sessionid, true, seqno, 0);
	zmsg_destroy(&reply);
}

TEST(request, link)
{
	int id = 0;
	zmsg_t *msg;
	uint32_t sessionid = vplanes[id].sessionid;
	uint32_t ifno = 4;
	const char *name = "s4";
	struct ip_addr raddr;
	uint64_t speed = 100;
	uint64_t advertised = 0;
	char stats[32];
	int ifindex = 99;
	char ifname[IFNAMSIZ];
	zmsg_t *reply;
	vplane_t *vp;

	raddr.ip.v4.s_addr = inet_addr(vplanes[id].ip);
	raddr.af = AF_INET;
	vp = vplane_findbyuuid(vplanes[id].uuid);
	CHECK(vp != NULL);
	memset(&stats, '\0', sizeof(stats));
	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &sessionid, sizeof(sessionid)) == 0);
	CHECK(zmsg_addstr(msg, "LINKUP") == 0);
	CHECK(zmsg_addmem(msg, &ifno, sizeof(ifno)) == 0);
	CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);
	CHECK(zmsg_addmem(msg, &speed, sizeof(speed)) == 0);
	CHECK(zmsg_addstr(msg, "half") == 0);
	CHECK(zmsg_addmem(msg, &stats, sizeof(stats)) == 0);
	CHECK(zmsg_addmem(msg, &advertised, sizeof(advertised)) == 0);

	CHECK(vplane_connect(vp, zmsg_first(msg)) == 0);

	snprintf(ifname, sizeof(ifname), "dp%d%s", (id+1), name);

	mock().expectOneCall("port_state_change")
		.withParameter("ifindex", ifindex)
		.withParameter("operstate", IF_OPER_UP)
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectOneCall("port_set_speed")
		.withParameter("ifname", ifname)
		.withParameter("speed", (int)speed)
		.withParameter("duplex", DUPLEX_HALF)
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectOneCall("port_set_stats")
		.withParameter("ifname", ifname)
		.ignoreOtherParameters()
		.andReturnValue(0);

	CHECK(vplane_iface_add(vp, ifno, ifindex, ifname) == 0);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	CHECK(reply == NULL);

	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &sessionid, sizeof(sessionid)) == 0);
	CHECK(zmsg_addstr(msg, "LINKDOWN") == 0);
	CHECK(zmsg_addmem(msg, &ifno, sizeof(ifno)) == 0);
	CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);

	mock().expectOneCall("port_state_change")
		.withParameter("ifindex", ifindex)
		.withParameter("operstate", IF_OPER_DORMANT)
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectOneCall("port_set_speed")
		.withParameter("ifname", ifname)
		.withParameter("speed", (int)-1)
		.withParameter("duplex", DUPLEX_UNKNOWN)
		.ignoreOtherParameters()
		.andReturnValue(0);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	CHECK(reply == NULL);
}

TEST(request, errors)
{
	int id = 0;
	zmsg_t *msg;
	uint32_t sessionid = vplanes[id].sessionid;
	uint64_t seqno = 0;
	uint32_t ifno;
	struct ip_addr raddr;
	char ifname[IFNAMSIZ];
	zmsg_t *reply;
	zframe_t *fr;
	vplane_t *vp;

	raddr.ip.v4.s_addr = inet_addr(vplanes[id].ip);
	raddr.af = AF_INET;
	ifno = MAX_PORTS - 1;
	vp = vplane_findbyuuid(vplanes[id].uuid);
	CHECK(vp != NULL);

	/*
	 * Issue port create message, but fail the actual (tunnel)
	 * create operation.
	 */
	msg = test_build_port(id+1, sessionid, seqno, ifno, raddr, true,
			      0, ifname);

	CHECK(vplane_connect(vp, zmsg_first(msg)) == 0);

	mock().setData("ifidx", 0);
	mock().expectOneCall("port_create")
		.withParameter("ifname", ifname)
		.ignoreOtherParameters()
		.andReturnValue(-1);
	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	test_check_port_reply(reply, sessionid, false, seqno, 0);
	zmsg_destroy(&reply);

	/*
	 * Issue a LINKDOWN message but with an invalid interface
	 * number.
	 */
	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &sessionid, sizeof(sessionid)) == 0);
	CHECK(zmsg_addstr(msg, "LINKDOWN") == 0);
	ifno = MAX_PORTS + 1;
	CHECK(zmsg_addmem(msg, &ifno, sizeof(ifno)) == 0);
	CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);

	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);
	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	CHECK(reply != NULL);

	fr = zmsg_first(reply);
	CHECK(zframe_size(fr) == sizeof(sessionid));
	CHECK(memcmp(zframe_data(fr), &sessionid, sizeof(sessionid)) == 0);
	fr = zmsg_next(reply);
	CHECK(zframe_streq(fr, "BADLINKPORT"));
	zmsg_destroy(&reply);

	/*
	 * Issue an invalid message
	 */
	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &sessionid, sizeof(sessionid)) == 0);
	CHECK(zmsg_addstr(msg, "WHATSUPDOC") == 0);
	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	CHECK(reply == NULL);

	/*
	 * Send a connect with an unknown UUID
	 */
	msg = test_build_connect(sessionid, 0, "123456");

	mock().expectNCalls(1, "logit")
		.withParameter("level", LOG_ERR);
	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	CHECK(reply == NULL);

	/*
	 * Build a valid connect, but fail the 0MQ send operation.
	 */
	msg = test_build_connect(sessionid, 0, vplanes[0].uuid);

	mock().expectNCalls(1, "logit")
		.withParameter("level", LOG_ERR);
	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(-1);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	CHECK(reply == NULL);

	/*
	 * Issue a LINKDOWN on an un-connected session
	 */
	uint32_t junksid = 9999;

	msg = zmsg_new();
	CHECK(msg != NULL);
	CHECK(zmsg_addmem(msg, &junksid, sizeof(junksid)) == 0);
	CHECK(zmsg_addstr(msg, "LINKDOWN") == 0);
	ifno = 1;
	CHECK(zmsg_addmem(msg, &ifno, sizeof(ifno)) == 0);
	CHECK(zmsg_addmem(msg, &raddr, sizeof(raddr)) == 0);

	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectNCalls(1, "logit")
		.withParameter("level", LOG_ERR);
	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	/*
	 * Normally we wouldn't expect any sort of response (its a
	 * random message on an un-connected session), but at present
	 * the handler issues a "FAIL" in order to force a reset by the
	 * vplane (see request.c).
	 */
	CHECK(reply != NULL);
	zmsg_destroy(&reply);
}

static void test_check_connect_reply(zmsg_t *reply, bool accept, uint32_t sid,
				     const char *uuid, uint16_t id)
{
	zframe_t *fr;
	zframe_t *topic;

	CHECK(reply != NULL);
	if (!accept) {
		CHECK(zmsg_size(reply) == 3);
	} else {
		CHECK(zmsg_size(reply) == 4);
	}

	fr = zmsg_first(reply);
	CHECK(zframe_size(fr) == sizeof(sid));
	CHECK(memcmp(zframe_data(fr), &sid, sizeof(sid)) == 0);
	topic = zmsg_next(reply);
	fr = zmsg_next(reply);
	CHECK(topic != NULL);
	CHECK(fr != NULL);
	CHECK(zframe_streq(fr, uuid));
	if (!accept) {
		CHECK(zframe_streq(topic, "REJECT"));
	} else {
		CHECK(zframe_streq(topic, "ACCEPT"));
		fr = zmsg_next(reply);
		CHECK(zframe_size(fr) == sizeof(id));
		CHECK(memcmp(zframe_data(fr), &id, sizeof(id)) == 0);
	}
}

TEST(request, connect)
{
	int id = 0;
	uint32_t sessionid = vplanes[id].sessionid;
	zmsg_t *msg;
	zmsg_t *accept;
	uint32_t version = 0;
	const char *uuid = vplanes[id].uuid;

	msg = test_build_connect(sessionid, version, uuid);

	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	accept = test_send_request(msg);
	CHECK(accept != NULL);
	zmsg_destroy(&msg);
	test_check_connect_reply(accept, true, sessionid, uuid, (id+1));
	zmsg_destroy(&accept);

	/*
	 * Invalid version, expect a reject in response.
	 */
	msg = test_build_connect(sessionid, 99, uuid);

	mock().expectNCalls(1, "logit")
		.withParameter("level", LOG_ERR);
	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	accept = test_send_request(msg);
	CHECK(accept != NULL);
	zmsg_destroy(&msg);
	test_check_connect_reply(accept, false, sessionid, uuid, (id+1));
	zmsg_destroy(&accept);

	/*
	 * Issue a second connect request
	 */
	msg = test_build_connect(sessionid, version, uuid);

	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	accept = test_send_request(msg);
	CHECK(accept != NULL);
	zmsg_destroy(&msg);
	test_check_connect_reply(accept, true, sessionid, uuid, (id+1));
	zmsg_destroy(&accept);
}

TEST(request, local)
{
	const char *addrstr = "127.0.0.1";
	const char *uuidstr = "00000000-0000-0000-0000-000000000000";
	struct ip_addr raddr;
	vplane_t *vp;
	zmsg_t *msg;
	uint64_t seqno = 1;
	uint32_t ifno = 3;
	int ifindex = 199;
	char ifname[IFNAMSIZ];
	zmsg_t *reply;

	CHECK(inet_pton(AF_INET, addrstr, &raddr.ip) == 1);
	raddr.af = AF_INET;
	mock().disable();
	vplane_cfg_begin();
	CHECK(vplane_cfg_set_attribute(0, "ip", addrstr) == PARSE_OK);
	CHECK(vplane_cfg_set_attribute(0, "uuid", uuidstr) == PARSE_OK);
	vplane_cfg_end();

	vp = vplane_findbyuuid(uuidstr);
	CHECK(vp != NULL);
	CHECK(0 == vplane_get_id(vp));
	CHECK(vplane_is_local(vp));
	mock().enable();

	/*
	 * Issue a NEWPORT and ensure that the vplane is marked as
	 * connected. That is, simulate request/vplane processing on VR.
	 */
	msg = test_build_port(0, 2, seqno, ifno, raddr, true,
			      0, ifname);

	CHECK(vplane_connect(vp, zmsg_first(msg)) == 0);

	mock().setData("ifidx", ifindex);
	mock().expectOneCall("port_create")
		.withParameter("ifname", ifname)
		.ignoreOtherParameters()
		.andReturnValue(0);
	mock().expectOneCall("zmsg_send")
		.ignoreOtherParameters()
		.andReturnValue(0);

	reply = test_send_request(msg);
	zmsg_destroy(&msg);
	test_check_port_reply(reply, 2, true, seqno, ifindex);
	zmsg_destroy(&reply);
	CHECK(vplane_is_connected(vp));
}

TEST(request, reconfigure)
{
	zmsg_t *msg = zmsg_new();
	zsock_t *input = NULL;
	zsock_t *output = NULL;
	zloop_t *loop = NULL;
	zsock_t *sock1 = NULL;
	zsock_t *sock2 = NULL;
	char *done;

	CHECK(msg != NULL);
	input = zsock_new_pair(">inproc://reconfigure.test");
	CHECK(input != NULL);
	output = zsock_new_pair("@inproc://reconfigure.test");
	CHECK(output != NULL);
	loop = zloop_new();
	CHECK(loop != NULL);
	zloop_set_verbose(loop, 1);

	mock().expectNCalls(2, "logit")
		.withParameter("level", LOG_ERR);
	sock1 = request_test_reconfigure(loop, msg, output, NULL);
	CHECK(sock1 == NULL);
	done = zstr_recv(input);
	CHECK(done != NULL);
	free(done);

	CHECK(zmsg_addstr(msg, "test") == 0);
	mock().expectOneCall("parser_endpoint_request")
		.andReturnValue("");
	mock().expectOneCall("parser_endpoint_request")
		.andReturnValue(default_endpoint);
	sock1 = request_test_reconfigure(loop, msg, output, sock1);
	CHECK(sock1 != NULL);
	done = zstr_recv(input);
	CHECK(done != NULL);
	free(done);

	/*
	 * Both calls to parser_endpoint_request() yield the same
	 * result, ensure we get the same socket.
	 */
	CHECK(zmsg_addstr(msg, "test") == 0);
	mock().expectNCalls(2, "parser_endpoint_request")
		.andReturnValue(default_endpoint);
	sock2 = request_test_reconfigure(loop, msg, output, sock1);
	CHECK(sock2 != NULL);
	CHECK(sock2 == sock1);
	done = zstr_recv(input);
	CHECK(done != NULL);
	free(done);

	CHECK(zmsg_addstr(msg, "test") == 0);

	mock().expectNCalls(1, "parser_endpoint_request")
		.andReturnValue(default_endpoint);
	mock().expectNCalls(1, "parser_endpoint_request")
		.andReturnValue("tcp://99.99.99.99:1234");
	mock().expectOneCall("__panic")
		.withParameter("funcname", "process_reconfigure");
	try {
		sock1 = request_test_reconfigure(loop, msg, output, sock2);
	} catch (const char *who) {
		STRCMP_EQUAL("__panic", who);
		sock1 = NULL;
	}
	CHECK(sock1 == NULL);

	zsock_destroy(&input);
	zsock_destroy(&output);
	zsock_destroy(&sock1);
	zloop_destroy(&loop);
	zmsg_destroy(&msg);
}
