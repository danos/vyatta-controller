/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
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

#include "cpputest_comparators.h"

extern "C" {

#include <czmq.h>
#include "parser.h"
#include "CppUTestExt/MockSupport_c.h"

        int vplane_cfg_set_attribute(int id, const char *name,
                                     const char *value)
        {
                return mock_c()->actualCall("vplane_cfg_set_attribute")
                        ->withIntParameters("id", id)
                        ->withStringParameters("name", name)
                        ->withStringParameters("value", value)
                        ->returnValue().value.intValue;
        }

        void vplane_cfg_begin(void)
        {
                mock_c()->actualCall("vplane_cfg_begin");
        }

        void vplane_cfg_end(void)
        {
                mock_c()->actualCall("vplane_cfg_end");
        }

        void vplane_cfg_failed(void)
        {
                mock_c()->actualCall("vplane_cfg_failed");
        }

        bool vplane_remote(void)
        {
                mock_c()->actualCall("vplane_remote");
                return mock_c()->returnValue().value.intValue;
        }

        int zsock_bind (zsock_t *self, const char *format, ...)
        {
                mock_c()->actualCall("zsock_bind");
                return mock_c()->returnValue().value.intValue;
        }
}

#define TESTCFGS(f) "src/testcfgs/" f

static void
parse_and_check_cfg(const char *name, bool validaddr)
{
        char cfg[128];
        int sts;

        if (validaddr)
                sts = 4321;
        else
                sts = -1;

        snprintf(cfg, sizeof(cfg), "src/testcfgs/%s", name);
        mock().expectOneCall("zsock_bind").andReturnValue(sts);
        sts = parser_controller_cfg(cfg);
        CHECK_EQUAL(0, sts);
}

TEST_GROUP(parser)
{
        AddrComparator ipComparator;

        void setup(void) {
                mock().installComparator("struct ip_addr", ipComparator);
                parser_controller_cfg_destroy();
        }

        void teardown(void) {
                parser_controller_cfg_destroy();
                // Make sure any expectations have been met.  Actual calls without
                // matching expectation will be flagged even without this call.
                mock().checkExpectations();

                // Clear any expectations etc before next test runs.
                mock().clear();

                // We installed one for this test ... so now we remove it.
                mock().removeAllComparatorsAndCopiers();
        }
};

TEST(parser, local_conf)
{
        struct ip_addr pass_addr;

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "ip")
                .withParameter("value", "127.0.0.1")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "00000000-0000-0000-0000-000000000000")
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(2, "vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        parse_and_check_cfg("local.conf", true);

        CHECK_EQUAL(86400, (parser_controller_timeout()/1000));
        pass_addr.af = AF_INET;
        CHECK(1 == inet_pton(AF_INET, "127.0.0.1", &pass_addr.ip));
        CHECK_EQUAL(0, addr_cmp(parser_local_addr(), &pass_addr));
        STRCMP_EQUAL("ipc:///var/run/vyatta/vplaned.req",
		     parser_endpoint_request());
        STRCMP_EQUAL("ipc:///var/run/vyatta/vplaned.pub",
		     parser_endpoint_publish());
}

#define DEFAULT_TIMEOUT (24*60*60)

TEST(parser, default_conf)
{
        struct ip_addr pass_addr;

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "ip")
                .withParameter("value", "127.0.0.1")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "00000000-0000-0000-0000-000000000000")
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(2, "vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        parse_and_check_cfg("local.conf", true);

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "ip")
                .withParameter("value", "127.0.0.1")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "00000000-0000-0000-0000-000000000000")
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(1, "vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(2, "vplane_remote").andReturnValue(false);

        parse_and_check_cfg("default.conf", true);

        CHECK_EQUAL(DEFAULT_TIMEOUT, parser_controller_timeout());
        pass_addr.af = AF_INET;
        CHECK(1 == inet_pton(AF_INET, "127.0.0.1", &pass_addr.ip));
        CHECK_EQUAL(0, addr_cmp(parser_local_addr(), &pass_addr));
        STRCMP_EQUAL("ipc:///var/run/vyatta/vplaned.req",
		     parser_endpoint_request());
        STRCMP_EQUAL("ipc://*", parser_endpoint_publish());
        CHECK_FALSE(parser_use_kernel_routes());

        /*
         * Parse a configuration with 2 vplanes, but with no explicit
         * URL definitions. That is, ensure the parser can generate the
         * default request URL (port 4415).
         */
        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");
        mock().expectNCalls(4,"vplane_cfg_set_attribute")
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(2, "vplane_remote").andReturnValue(true);

        parse_and_check_cfg("defvplanes.conf", true);

        CHECK_EQUAL(AF_INET, parser_local_af());
        STRCMP_EQUAL("tcp://192.168.250.100:4415", parser_endpoint_request());
        STRCMP_EQUAL("tcp://192.168.250.100:*", parser_endpoint_publish());
}

TEST(parser, no_conf)
{
        int result;

        mock().expectOneCall("logit")
                .withParameter("level", LOG_ERR);

        result = parser_controller_cfg(TESTCFGS("no-such-file.conf"));
        CHECK_EQUAL(-1, result);
}

TEST(parser, errors)
{
        int result;

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_failed");

        mock().expectNCalls(2, "logit")
                .withParameter("level", LOG_ERR);

        mock().expectOneCall("die");

        try {
                result = parser_controller_cfg(TESTCFGS("bad.conf"));
        } catch (const char *who) {
                STRCMP_EQUAL("die", who);
                result = -2;
        }

        CHECK_EQUAL(-2, result);

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_failed");
        mock().expectOneCall("die");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "ip")
                .withParameter("value", "127.0.0.1")
                .andReturnValue(PARSE_ERR);

        mock().expectNCalls(3, "vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .ignoreOtherParameters()
                .andReturnValue(PARSE_ERR);

        try {
                result = parser_controller_cfg(TESTCFGS("local.conf"));
        } catch (const char *who) {
                STRCMP_EQUAL("die", who);
                result = -2;
        }
        CHECK_EQUAL(-2, result);

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");
        mock().expectNCalls(4, "vplane_cfg_set_attribute")
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        /*
         * Force an address check failure and ensure we end up using
         * ipc-based URL's.
         */
        mock().expectOneCall("logit")
                .withParameter("level", LOG_ERR);

        parse_and_check_cfg("2vplanes.conf", false);

        struct ip_addr pass_addr;
        pass_addr.af = AF_INET;
        CHECK(1 == inet_pton(pass_addr.af, "192.168.250.100", &pass_addr.ip));
        CHECK_EQUAL(0, addr_cmp(parser_local_addr(), &pass_addr));
        STRCMP_EQUAL("ipc:///var/run/vyatta/vplaned.req",
		     parser_endpoint_request());
        STRCMP_EQUAL("ipc://*", parser_endpoint_publish());
}

TEST(parser, novplanes)
{
        /*
         * With no vplanes configured (just the controller), ensure that
         * the request and publish URL's are ipc:// based.
         */
        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");
        mock().expectNCalls(2, "vplane_remote").andReturnValue(false);

        parse_and_check_cfg("novplanes.conf", true);

        CHECK_EQUAL(AF_INET6, parser_local_af());
        STRCMP_EQUAL("ipc:///var/run/vyatta/vplaned.req",
		     parser_endpoint_request());
        STRCMP_EQUAL("ipc://*", parser_endpoint_publish());
}

TEST(parser, vplanes)
{
        struct ip_addr pass_addr;

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 1)
                .withParameter("name", "ip")
                .withParameter("value", "192.168.250.101")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 1)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "62FCE0B9-EE2D-8F41-9F3D-49A3E554F83D")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 3)
                .withParameter("name", "ip")
                .withParameter("value", "192.168.250.103")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 3)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "D9A20081-BE15-BB43-99E6-62B810596F3B")
                .andReturnValue(PARSE_OK);

        parse_and_check_cfg("2vplanes.conf", true);

        CHECK_EQUAL(10, (parser_controller_timeout()/1000));
        CHECK(1 == inet_pton(AF_INET, "192.168.250.100", &pass_addr.ip));
        pass_addr.af = AF_INET;
        CHECK_EQUAL(0, addr_cmp(parser_local_addr(), &pass_addr));
        STRCMP_EQUAL("tcp://192.168.250.100:5904", parser_endpoint_request());
}


TEST(parser, vplanes6)
{
        struct ip_addr pass_addr;

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 5)
                .withParameter("name", "ip")
                .withParameter("value", "2001::1")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 5)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "62FCE0B9-EE2D-8F41-9F3D-49A3E554F835")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 6)
                .withParameter("name", "ip")
                .withParameter("value", "2001::3")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 6)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "D9A20081-BE15-BB43-99E6-62B810596F36")
                .andReturnValue(PARSE_OK);

        parse_and_check_cfg("2vplanes6.conf", true);

        CHECK_EQUAL(10, (parser_controller_timeout()/1000));
        CHECK(1 == inet_pton(AF_INET6, "2001::2", &pass_addr.ip));
        pass_addr.af = AF_INET6;
        CHECK_EQUAL(0, addr_cmp(parser_local_addr(), &pass_addr));
        STRCMP_EQUAL("tcp://[2001::2]:5904", parser_endpoint_request());
}

TEST(parser, routesource)
{
        int result;

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "ip")
                .withParameter("value", "127.0.0.1")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "00000000-0000-0000-0000-000000000000")
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(1, "vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(2, "vplane_remote").andReturnValue(false);

        parse_and_check_cfg("routesourcerib.conf", true);

        CHECK_FALSE(parser_use_kernel_routes());

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_end");

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "ip")
                .withParameter("value", "127.0.0.1")
                .andReturnValue(PARSE_OK);

        mock().expectOneCall("vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .withParameter("name", "uuid")
                .withParameter("value",
                               "00000000-0000-0000-0000-000000000000")
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(1, "vplane_cfg_set_attribute")
                .withParameter("id", 0)
                .ignoreOtherParameters()
                .andReturnValue(PARSE_OK);

        mock().expectNCalls(2, "vplane_remote").andReturnValue(false);

        parse_and_check_cfg("routesourcekernel.conf", true);

        CHECK(parser_use_kernel_routes());

        mock().expectOneCall("vplane_cfg_begin");
        mock().expectOneCall("vplane_cfg_failed");

        mock().expectOneCall("logit")
                .withParameter("level", LOG_ERR);

        mock().expectOneCall("die");

        try {
                result = parser_controller_cfg(TESTCFGS("routesourcebad.conf"));
        } catch (const char *who) {
                STRCMP_EQUAL("die", who);
                result = -2;
        }

        CHECK_EQUAL(-2, result);
}
