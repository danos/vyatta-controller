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
#include "vplane.h"

extern "C" {


void fabric_topo_upaddr_add(uint16_t id, const char *upaddr)
{

}
void fabric_topo_upaddr_delete(uint16_t id, const char *upaddr)
{

}
void fabric_topo_purge_upaddr(const vplane_t *vp)
{

}

void fabric_topo_notify_connect(const vplane_t *vp)
{

}

void fabric_topo_notify_disconnect(const vplane_t *vp)
{

}

void fabric_topo_encrypt(bool encrypt)
{

}
}
