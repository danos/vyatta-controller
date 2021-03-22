/*
 * Copyright (c) 2018-2019, 2021 AT&T Intellectual Property.
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

#define CSTORE_TIMEOUT 100

static char cstore_sock_path[PATH_MAX];
static int cstore_sock_path_instance;
static zsock_t *cstore_sock_server;

static const char *cstore_json1 =
 "{\"security\":{\"firewall\":{\"name\":{\"test1\":{\"default-action\":"
	"{\"__INTERFACE__\":\"ALL\","
	"\"__SET__\":\"npf-cfg add fw:test1 10000 action=accept\"}"
"}}}}}";

static bool
jsonstr_object_equal(json_object *o1, json_object *o2)
{
	if (json_object_get_type (o1) != json_object_get_type (o2))
		return false;

	switch(json_object_get_type(o1)) {
	case json_type_boolean:
		return json_object_get_boolean(o1) ==
			json_object_get_boolean(o2);

	case json_type_double:
	       return json_object_get_double(o1) ==
		       json_object_get_double(o2);

	case json_type_int:
	       return json_object_get_int64(o1) ==
		       json_object_get_int64(o2);

	case json_type_string:
		return strcmp(json_object_get_string(o1),
			      json_object_get_string(o2)) == 0;

	case json_type_object:
		if (json_object_object_length(o1) !=
		    json_object_object_length(o2))
			return false;

		json_object_iter jiter;
		json_object_object_foreachC(o1, jiter) {
			json_object *valo2;

			if (!json_object_object_get_ex(o2, jiter.key, &valo2))
				return false;

			if (!jsonstr_object_equal(jiter.val, valo2))
				return false;
		}
		return true;

	case json_type_array:
		size_t len, i;

		len = json_object_array_length(o1);
		if (len != json_object_array_length(o2))
			return false;

		for (i = 0; i < len; i++) {
			if (!jsonstr_object_equal(
				    json_object_array_get_idx(o1, i),
				    json_object_array_get_idx(o2, i)))
				return false;
		}
		return true;

	case json_type_null:
		return true;
	};

	return false;
}

static bool
jsonstr_equal(const char *jstr1, const char *jstr2)
{
	if (jstr1 == jstr2)
		return true;

	if (jstr1 == NULL)
		return (jstr2 == NULL);

	if (jstr2 == NULL)
		return false;

	json_object *jobj1 = json_tokener_parse(jstr1);
	json_object *jobj2 = json_tokener_parse(jstr2);

	return jsonstr_object_equal(jobj1, jobj2);
}

static bool
cstore_server(const char *jsonexp, const char *sts)
{
	static int waittime = (500 * ZMQ_POLL_MSEC);
	zmsg_t *msg;
	bool result;

	zsock_set_rcvtimeo(cstore_sock_server, waittime);
	msg = zmsg_recv(cstore_sock_server);
	if (msg == NULL)
		return false;

//	zmsg_dump(msg);

	if (jsonexp == NULL)
		result = true;
	else {
		char *jsonrcv = zmsg_popstr(msg);
		result = jsonstr_equal(jsonexp, jsonrcv);
		free(jsonrcv);
	}

	if (sts != NULL)
		CHECK(zsock_send(cstore_sock_server, "s", sts) == 0);

	zmsg_destroy(&msg);
	return result;
}

TEST_GROUP(libvplaned_cstore)
{
	void setup(void) {
		mock().disable();
		snprintf(cstore_sock_path, sizeof(cstore_sock_path),
			 "ipc:///var/tmp/libvpd-cstore.%d",
			 ++cstore_sock_path_instance);
		cstore_sock_server = zsock_new_rep(cstore_sock_path);
		CHECK(cstore_sock_server != NULL);
		mock().enable();
	}

	void teardown(void) {
		mock().checkExpectations();
		mock().clear();
		mock().removeAllComparatorsAndCopiers();
		mock().disable();
		zsock_destroy(&cstore_sock_server);
		CHECK(cstore_sock_server == NULL);
		mock().enable();
	}
};

TEST(libvplaned_cstore, connect_disconnect)
{
	zsock_t *s;

	/*
	 * Attempting to connect to the "real thing" (vplaned) is not
	 * going to work under test conditions...
	 */
	s = vplaned_cstore_connect();
	CHECK(s == NULL);
	vplaned_cstore_disconnect(&s);
	CHECK(s == NULL);

	s = __vplaned_cstore_connect(cstore_sock_path);
	CHECK(s != NULL);
	CHECK(zsock_is(s));
	vplaned_cstore_disconnect(&s);
	CHECK(s == NULL);
}

TEST(libvplaned_cstore, error)
{
	zsock_t *s;

	s = __vplaned_cstore_connect(cstore_sock_path);
	CHECK(s != NULL);
	CHECK(vplaned_cstore_request(s,
				     "fablive default",
				     "fabric default liveness enabled 0 0 0",
				     NULL, NULL) < 0);
	CHECK(vplaned_cstore_response(NULL, 0) < 0);
	vplaned_cstore_disconnect(&s);
	CHECK(s == NULL);

	s = __vplaned_cstore_connect(cstore_sock_path);
	CHECK(s != NULL);
	CHECK(vplaned_cstore_response(s, CSTORE_TIMEOUT) < 0);

	/*
	 * This must be the last test case. Since we don't issue a
	 * response, the socket ends up in a failed state (REQ-REP
	 * forces a strict send/receive ordering of messages). Rather
	 * than play with the ZMQ_REQ_RELAXED socket option, run this
	 * last so that the connection is subsequently deleted.
	 */
	CHECK(vplaned_cstore_request(s,
				     "fablive default",
				     "fabric default liveness enabled 0 0 0",
				     NULL, "SET") == 0);
	CHECK(cstore_server(NULL, NULL));
	CHECK(vplaned_cstore_response(s, CSTORE_TIMEOUT) < 0);
	vplaned_cstore_disconnect(&s);
	CHECK(s == NULL);
}

TEST(libvplaned_cstore, asynccfg)
{
	zsock_t *s;

	s = __vplaned_cstore_connect(cstore_sock_path);
	CHECK(s != NULL);
	CHECK(vplaned_cstore_request(
		      s,
		      "security firewall name test1 default-action",
		      "npf-cfg add fw:test1 10000 action=accept",
		      NULL, "SET") == 0);
	CHECK(cstore_server(cstore_json1, "OK"));
	CHECK(vplaned_cstore_response(s, CSTORE_TIMEOUT) == 0);
	vplaned_cstore_disconnect(&s);
	CHECK(s == NULL);
}
