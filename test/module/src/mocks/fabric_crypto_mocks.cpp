/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
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
#include <czmq.h>

int fab_crypto_init(zsock_t *socket)
{
	CPPUTEST_STUB_RET_VAL(0);
}

void fab_crypto_exit()
{
	CPPUTEST_STUB_RET;
}

void fab_crypto_timer()
{
	CPPUTEST_STUB_RET;
}

}
