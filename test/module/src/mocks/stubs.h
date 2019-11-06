/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#if !defined(__stubs_h__)
#define __stubs_h__

extern "C" {

#include <czmq.h>
#include "CppUTestExt/MockSupport_c.h"

#define CPPUTEST_STUB_RET_VAL(val)					\
	__extension__							\
	({								\
		fprintf(stderr, "\n*** %s not yet implemented ***\n", __func__); \
		assert(0);						\
		return val;						\
	})

#define CPPUTEST_STUB_RET						\
	__extension__							\
	({								\
		fprintf(stderr, "\n*** %s not yet implemented ***\n", __func__); \
		assert(0);						\
		return;							\
	})

}

#endif
