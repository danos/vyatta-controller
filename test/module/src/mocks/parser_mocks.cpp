/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Unit test mocks (stubs)
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <string.h>

extern "C" {

#include "stubs.h"
#include "parser.h"

const char *parser_endpoint_request(void)
{
	return mock_c()->actualCall("parser_endpoint_request")
		->returnValue().value.stringValue;
}

const char *parser_endpoint_request_bound(void)
{
	return "";
}

const char *parser_endpoint_publish_bound(void)
{
	return "";
}

void
parser_set_endpoint_request_bound(char *url)
{
}

int parser_controller_timeout(void)
{
	return 0;
}

parse_result_t parse_atoi(uint32_t *i, const char *value)
{
	*i = 0;
	return PARSE_OK;
}

static struct ip_addr laddr;

const struct ip_addr *parser_local_addr(void)
{
	laddr.af = AF_INET;
	laddr.ip.v4.s_addr = inet_addr("127.0.0.1");
	return &laddr;
}

sa_family_t parser_local_af(void)
{
	return AF_INET;
}

bool parser_authentication_enabled(void)
{
	return false;
}

const char *parser_authentication_certificate(void)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

const char *parser_authentication_path(void)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

int parser_get_json_config(const char *, zmsg_t *, char **)
{
	return 0;
}

bool
parser_fabric_encrypt_enabled(void)
{
	return false;
}
void
parser_set_fabric_encrypt(bool encrypt)
{
}

void
parser_set_fabric_address(struct ip_addr *addr)
{
}

void
parser_delete_fabric_address(struct ip_addr *addr)
{
}

const struct ip_addr *
parser_fabric_addr(sa_family_t af)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

}
