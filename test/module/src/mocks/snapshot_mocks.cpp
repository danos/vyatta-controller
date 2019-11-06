/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
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
#include "controller.h"

snapshot_t *snapshot_new(void)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

void snapshot_destroy(snapshot_t **snap)
{
	CPPUTEST_STUB_RET;
}

void snapshot_send(snapshot_t *self, void *socket, zframe_t *to)
{
	CPPUTEST_STUB_RET;
}

void snapshot_send_ifindex(snapshot_t *self, void *socket, zframe_t *to,
			   int ifindex)
{
	CPPUTEST_STUB_RET;
}

uint64_t snapshot_seqno(const snapshot_t *self)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int snapshot_update(snapshot_t *snap, nlmsg_t *nmsg)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int sd_notify(int env, const char *state)
{
	CPPUTEST_STUB_RET_VAL(0);
}

}
