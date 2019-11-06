/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * CppUTest only knows how to compare certain data types.  For the rest,
 * we define 'custom' comparators, which are used as follows:
 *
 * (a) In TEST_GROUP, declare a My<Type>Comparator object.  This must be
 *     outside any function, or will not be in scope when needed. Then
 *     install it in setup(), and remove it in teardown(), eg:
 *
 *        TEST_GROUP(cpputest_fw_commands)
 *        {
 *            MyStringComparator stringComparator;
 *
 *            void setup(void)
 *            {
 *                mock().installComparator("string", stringComparator);
 *            }
 *            void teardown(void)
 *            {
 *                mock().removeAllComparatorsAndCopiers();
 *            }
 *        };
 *
 * (b) Use the comparator as follows in mocks.  This example has a C++
 *     expect call, and a C-style actual call:
 *
 *        mock().expectOneCall("npf_new_configuration").
 *            withParameter("nat", 0).
 *            withParameter("global", 1).
 *            withParameter("tables", 1).
 *            withParameterOfType("string", "name", (void *)"bridge").
 *            withParameter("type", RTE_LOGTYPE_BRIDGE).
 *            andReturnValue(&test_conf);
 *
 *        return((npf_conf_t *)mock_c()->actualCall("npf_new_configuration")
 *            ->withIntParameters("nat", nat)
 *            ->withIntParameters("global", global)
 *            ->withIntParameters("tables", tables)
 *            ->withParameterOfType("string", "name", (char *)name)
 *            ->withIntParameters("type", type)
 *            ->returnValue().value.pointerValue);
 */
#include <stdlib.h>
#include <stdio.h>

extern "C" {
#include "ip_addr.h"
}

/*
 * Comparator for IP address  ip_addr objects.
 * Note that the parent class signatures changed and added a const qualifier to
 * the arguments between 3.4 and 3.7. To ensure compatibility with both versions
 * we thus need to implement both.
 */
class AddrComparator:public MockNamedValueComparator
{
public:
	virtual bool isEqual(void *obj1, void *obj2)
	{
		struct ip_addr *ip1 = (struct ip_addr *)obj1;
		struct ip_addr *ip2 = (struct ip_addr *)obj2;

		if (ip1->af != ip2->af)
			return false;

		if (ip1->af == AF_INET)
			return 0 == memcmp(&ip1->ip.v4,
					   &ip2->ip.v4,
					   sizeof(ip1->ip.v4));

		if (ip1->af == AF_INET6)
			return 0 == memcmp(&ip1->ip.v6,
					   &ip2->ip.v6,
					   sizeof(ip1->ip.v6));

		return false;
	}
	virtual bool isEqual(const void *obj1, const void *obj2)
	{
		return isEqual((void *)obj1, (void *)obj2);
	}
	virtual SimpleString valueToString(void *obj)
	{
		struct ip_addr *addr = (struct ip_addr *)obj;
		char buf[INET6_ADDRSTRLEN];

		return StringFrom(inet_ntop(addr->af, &(addr->ip), buf,
					    sizeof(buf)));
	}
	virtual SimpleString valueToString(const void *obj)
	{
		return valueToString((void *)obj);
	}
};
