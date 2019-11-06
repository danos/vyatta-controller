/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "cpputest_comparators.h"

extern "C" {

#include <czmq.h>
#include "controller.h"
#include "CppUTestExt/MockSupport_c.h"

}
TEST_GROUP(hwbinding)
{
	void teardown(void) {
		mock().checkExpectations();
		mock().clear();
	}
};

TEST(hwbinding, interface_conf)
{
	mock().expectNCalls(3, "logit")
		.withParameter("level", LOG_ERR);

	CHECK(get_name_by_pciaddr("0:0:1.0") == NULL);
	CHECK(get_name_by_pcislot(2, 0) == NULL);
	CHECK(get_name_by_mac("00:00:00:00:00:03") == 0);
	CHECK(get_name_by_port(5) == NULL);
	CHECK(get_name_by_fwidx(6) == NULL);

	read_interface_cfg("src/testcfgs/interface.conf");

	CHECK(strcmp("s101", get_name_by_pciaddr("0:0:1.0")) == 0);
	CHECK(strcmp("s102", get_name_by_pcislot(2, 0)) == 0);
	CHECK(strcmp("s103", get_name_by_mac("00:00:00:00:00:03")) == 0);
	CHECK(strcmp("s104", get_name_by_port(4)) == 0);
	CHECK(strcmp("s105", get_name_by_fwidx(5)) == 0);
	CHECK(strcmp("s106", get_name_by_pcislot(6, 1)) == 0);
	CHECK(strcmp("s108", get_name_by_pciaddr("0:0:2.0")) == 0);

	CHECK(get_name_by_pciaddr(NULL) == NULL);
	CHECK(get_name_by_mac(NULL) == 0);

	CHECK(get_name_by_pciaddr("0:0:0.0") == NULL);
	CHECK(get_name_by_pcislot(0, 0) == NULL);
	CHECK(get_name_by_mac("00:00:00:00:00:00") == 0);
	CHECK(get_name_by_port(0) == NULL);
	CHECK(get_name_by_fwidx(0) == NULL);

	// Illegal interface name in configuration
	CHECK(get_name_by_pciaddr("0:0:6.0") == NULL);

	// Inline comment in configuration
	CHECK(strcmp("s999", get_name_by_pciaddr("0:0:7.0")) == 0);

	// New configuration
	read_interface_cfg("src/testcfgs/interface.conf2");

	CHECK(strcmp("s201", get_name_by_pciaddr("0:0:1.0")) == 0);
	CHECK(strcmp("s202", get_name_by_pcislot(2, 0)) == 0);
	CHECK(strcmp("s203", get_name_by_mac("00:00:00:00:00:03")) == 0);
	CHECK(strcmp("s204", get_name_by_port(4)) == 0);
	CHECK(strcmp("s205", get_name_by_fwidx(5)) == 0);

	// Should be missing now
	CHECK(get_name_by_pciaddr("0:0:7.0") == NULL);

	// Read missing file
	read_interface_cfg("src/testcfgs/missing.conf");
	CHECK(get_name_by_pciaddr("0:0:1.0") == NULL);
}
