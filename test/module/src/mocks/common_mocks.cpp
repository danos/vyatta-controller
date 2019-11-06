/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "cpputest_comparators.h"

static bool
logmessages =
#if defined(LOGIT)
	1;
#else
	0;
#endif

/*
 * Both "die" and "panic" are marked as "noreturn" functions. Thus we
 * need a way to signal the test function that a fatal error has
 * occurred without returning to the code under test. The easiest option
 * is to generate an exception and have the test code catch the
 * exception.
 */

extern "C" {

#include "CppUTestExt/MockSupport_c.h"

	int debug;

	void __panic(const char *funcname, const char *format, ...)
	{
		CHECK(format != NULL);
		mock_c()->actualCall("__panic")
			->withStringParameters("funcname", funcname);
		throw __func__;
	}

	void die(const char *format, ...)
	{
		if (logmessages) {
			va_list ap;
			char line[1024];

			va_start(ap, format);
			vsnprintf(line, sizeof(line), format, ap);
			va_end(ap);
			fprintf(stderr, "LOGIT (die): %s\n", line);
		}

		CHECK(format != NULL);
		mock_c()->actualCall("die");
		throw __func__;
	}

	void logit(int level, char c, const char *format, ...)
	{
		if (logmessages) {
			va_list ap;
			char line[1024];

			va_start(ap, format);
			vsnprintf(line, sizeof(line), format, ap);
			va_end(ap);
			fprintf(stderr, "LOGIT (%c): %s\n", c, line);
		}

		CHECK(format != NULL);
		switch (level) {
		case LOG_ERR:
		case LOG_CRIT:
		case LOG_ALERT:
		case LOG_EMERG:
			mock_c()->actualCall("logit")
				->withIntParameters("level", level);
			break;
		default:
			break;
		}
	}

}
