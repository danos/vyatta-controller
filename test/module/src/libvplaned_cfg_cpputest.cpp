/*
 * Copyright (c) 2018-2019, 2021 AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include <czmq.h>
#include "cpputest_comparators.h"
#include "json.h"

extern "C" {

#include "vplaned.h"
#include "CppUTestExt/MockSupport_c.h"

}

#define VPD_TIMEOUT 50

static char vpd_sock_path[PATH_MAX];
static int vpd_sock_path_instance;
static zsock_t *vpd_sock_server;

static const char *vpd_config =
"{\"controller\": {"
        "\"auth_enabled\": false,"
        "\"cfg_publish_url\": \"tcp://10.252.1.254:*\","
        "\"cfg_request_url\": \"tcp://10.252.1.254:4415\","
        "\"ctladdr\": \"10.252.1.254\","
        "\"ctladdr_valid\": true,"
        "\"publish_url\": \"tcp://[::ffff:10.252.1.254]:49152\","
        "\"request_url\": \"tcp://[::ffff:10.252.1.254]:4415\","
        "\"timeout\": 120000"
"}}";

static const char *vpd_dpconfig0 = "{\"dataplanes\": [{}]}";

static const char *vpd_dpconfig2 =
"{\"dataplanes\": [{"
	"\"clocktick\": 4065,"
	"\"connected\": false,"
	"\"connects\": 3,"
	"\"control\": \"tcp://[::ffff:10.252.1.2]:49153\","
	"\"ctladdr\": \"10.252.1.2\","
	"\"delpend\": false,"
	"\"id\": 2,"
	"\"interfaces\": [],"
	"\"local\": false,"
	"\"sessionid\": \"002D5CD8A2\","
	"\"timeout\": 120000,"
	"\"uuid\": \"01234567-89ab-0001-0002-cdef01234567\""
	"},{"
	"\"clocktick\": 4888,"
	"\"connected\": true,"
	"\"connects\": 3,"
	"\"control\": \"tcp://[::ffff:10.252.1.1]:49153\","
	"\"ctladdr\": \"10.252.1.1\","
	"\"delpend\": false,"
	"\"id\": 1,"
	"\"interfaces\": [],"
	"\"local\": false,"
	"\"sessionid\": \"002D5CD8A1\","
	"\"timeout\": 120000,"
	"\"uuid\": \"01234567-89ab-0001-0001-cdef01234567\""
        "}]"
"}";

static bool
vpd_server(const char *request, const char *sts, const char *response)
{
	static int waittime = (500 * ZMQ_POLL_MSEC);
	zmsg_t *msg;
	zframe_t *topic;
	bool result;

	zsock_set_rcvtimeo(vpd_sock_server, waittime);
	msg = zmsg_recv(vpd_sock_server);
	if (msg == NULL)
		return false;

//	zmsg_dump(msg);

	topic = zmsg_first(msg);
	result = (topic != NULL) &&
		zframe_streq(topic, request);

	if (result && (response != NULL))
		CHECK(zsock_send(vpd_sock_server, "ss", sts, response) == 0);

	zmsg_destroy(&msg);
	return result;
}

TEST_GROUP(libvplaned_cfg)
{
	void setup(void) {
		mock().disable();
		/*
		 * There is a race condition between the close
		 * (teardown) and the subsequent create such that on
		 * occasions the create can fail. Rather than figure out
		 * the race, just create a unique socket for each test
		 * case.
		 */
		snprintf(vpd_sock_path, sizeof(vpd_sock_path),
			 "ipc:///var/tmp/libvpd-config.%d",
			 ++vpd_sock_path_instance);
		vpd_sock_server = zsock_new_rep(vpd_sock_path);
		CHECK(vpd_sock_server != NULL);
		mock().enable();
	}

	void teardown(void) {
		mock().checkExpectations();
		mock().clear();
		mock().removeAllComparatorsAndCopiers();
		mock().disable();
		zsock_destroy(&vpd_sock_server);
		CHECK(vpd_sock_server == NULL);
		mock().enable();
	}
};

TEST(libvplaned_cfg, connect_disconnect)
{
	zsock_t *s;

	/*
	 * Attempting to connect to the "real thing" (vplaned) is not
	 * going to work under test conditions...
	 */
	s = vplaned_connect();
	CHECK(s == NULL);
	vplaned_disconnect(&s);
	CHECK(s == NULL);

	s = __vplaned_connect(vpd_sock_path);
	CHECK(s != NULL);
	CHECK(zsock_is(s));
	vplaned_disconnect(&s);
	CHECK(s == NULL);
}

TEST(libvplaned_cfg, request_response)
{
	zsock_t *s;
	char *resp;
	json_object *jobj;

	s = __vplaned_connect(vpd_sock_path);
	CHECK(s != NULL);

	CHECK(vplaned_request_config(s) == 0);
	CHECK(vpd_server("GETCONFIG", "OK", vpd_config));
	CHECK(vplaned_response_get(s, VPD_TIMEOUT, &resp) == 0);

	jobj = json_tokener_parse(resp);
	CHECK(jobj != NULL);
	json_object_put(jobj);
	free(resp);

	CHECK(vplaned_request_dataplane(s) == 0);
	CHECK(vpd_server("GETVPCONFIG", "OK", vpd_dpconfig2));
	CHECK(vplaned_response_get(s, VPD_TIMEOUT, &resp) == 0);

	jobj = json_tokener_parse(resp);
	CHECK(jobj != NULL);
	json_object_put(jobj);
	free(resp);

	/*
	 * Provoke & check various error conditions
	 */
	CHECK(vplaned_request_config(NULL) < 0);

	CHECK(vplaned_response_get(NULL, 0, &resp) < 0);
	CHECK(vplaned_response_get(s, 0, NULL) < 0);

	CHECK(vplaned_request_config(s) == 0);
	CHECK(vpd_server("GETCONFIG", "ERR", vpd_config));
	CHECK(vplaned_response_get(s, VPD_TIMEOUT, &resp) < 0);

	/*
	 * This must be the last test case. Since we don't issue a
	 * response, the socket ends up in a failed state (REQ-REP
	 * forces a strict send/receive ordering of messages). Rather
	 * than play with the ZMQ_REQ_RELAXED socket option, run this
	 * last so that the connection is subsequently deleted.
	 */
	CHECK(vplaned_request_config(s) == 0);
	CHECK(vpd_server("GETCONFIG", "OK", NULL));
	CHECK(vplaned_response_get(s, VPD_TIMEOUT, &resp) < 0);

	vplaned_disconnect(&s);
	CHECK(s == NULL);
}

TEST(libvplaned_cfg, dataplane)
{
	zsock_t *s;
	zlist_t *list = zlist_new();
	struct vplaned_dataplane *dp;

	s = __vplaned_connect(vpd_sock_path);
	CHECK(vplaned_request_dataplane(s) == 0);
	CHECK(vpd_server("GETVPCONFIG", "OK", vpd_dpconfig0));

	CHECK(vplaned_dp_get_list(s, VPD_TIMEOUT, false, list) == 0);
	CHECK(zlist_size(list) == 0);
	zlist_purge(list);

	CHECK(vplaned_request_dataplane(s) == 0);
	CHECK(vpd_server("GETVPCONFIG", "OK", vpd_dpconfig0));
	CHECK(vplaned_dp_get_first(s, VPD_TIMEOUT, false, &dp) == 0);
	CHECK(dp == NULL);
	vplaned_dp_destroy(&dp);

	CHECK(vplaned_request_dataplane(s) == 0);
	CHECK(vpd_server("GETVPCONFIG", "OK", vpd_dpconfig0));
	CHECK(vplaned_dp_get(s, VPD_TIMEOUT, 99, &dp) == 0);
	CHECK(dp == NULL);
	vplaned_dp_destroy(&dp);

	vplaned_disconnect(&s);

	s = __vplaned_connect(vpd_sock_path);
	CHECK(vplaned_request_dataplane(s) == 0);
	CHECK(vpd_server("GETVPCONFIG", "OK", vpd_dpconfig2));

	CHECK(vplaned_dp_get_list(s, VPD_TIMEOUT, true, list) == 0);
	dp = (struct vplaned_dataplane *)zlist_pop(list);
	CHECK(dp != NULL);
	CHECK(zlist_size(list) == 0);
	CHECK(vplaned_dp_id(dp) == 1);
	vplaned_dp_destroy(&dp);
	zlist_purge(list);

	CHECK(vplaned_request_dataplane(s) == 0);
	CHECK(vpd_server("GETVPCONFIG", "OK", vpd_dpconfig2));

	CHECK(vplaned_dp_get_first(s, VPD_TIMEOUT, true, &dp) == 0);
	CHECK(dp != NULL);
	CHECK(vplaned_dp_id(dp) == 1);
	CHECK(vplaned_dp_is_connected(dp));
	CHECK(streq(vplaned_dp_console(dp), "tcp://[::ffff:10.252.1.1]:49153"));
	vplaned_dp_destroy(&dp);

	zlist_destroy(&list);
	vplaned_disconnect(&s);
}
