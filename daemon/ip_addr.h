/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Address related data structures and functions.
 */
#if !defined(__ip_addr_h__)
#define __ip_addr_h__

#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Generic address */
struct ip_addr {
	sa_family_t af;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
};

/**
 * Compares  the passed address with local sock address.
 *  returns 0  if address is same, -1 otherwise
 */
static inline int
addr_cmp(const struct ip_addr *addr1, const struct ip_addr *addr2)
{
	if ((addr1 == NULL) || (addr2 == NULL) ||
	    (addr1->af != addr2->af))
		return -1;
	if (addr1->af == AF_INET) {
		if (addr1->ip.v4.s_addr == addr2->ip.v4.s_addr)
			return 0;
		return -1;
	}
	if (addr1->af == AF_INET6)
		return memcmp(&addr1->ip.v6, &addr2->ip.v6,
			      sizeof(struct in6_addr));
	return -1;
}

/**
 * Converts string to ip_addr
 */
static inline bool ip_addr_from_str(struct ip_addr *addr, const char *addrstr)
{
	int rc;

	if (!addrstr || !addr)
		return false;

	rc = inet_pton(AF_INET, addrstr, &addr->ip.v4);
	if (rc == 1) {
		addr->af = AF_INET;
		return true;
	}
	rc = inet_pton(AF_INET6, addrstr, &addr->ip.v6);
	if (rc == 1) {
		addr->af = AF_INET6;
		return true;
	}
	return false;
}

#endif
