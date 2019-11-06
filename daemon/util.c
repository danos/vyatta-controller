/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 * Copyright (c) 2012-2016 by Brocade Communications Systems, Inc.
 *
 * Genericish wrapper around logging.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

#include <libmnl/libmnl.h>

#include <czmq.h>
#include "controller.h"

int debug;
int udp_fd;

void __panic(const char *funcname, const char *format, ...)
{
	va_list ap;
	const char *err = errno ? strerror(errno) : NULL;
	char line[1024];

	va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
	va_end(ap);

	fprintf(stderr, "%s(): %s\n", funcname, line);

	syslog(LOG_CRIT, "PANIC in %s():\n", funcname);
	if (err)
		syslog(LOG_CRIT, "%s: %s", line, err);
	else
		syslog(LOG_CRIT, "%s", line);

	abort();
}

/* Startup problem */
void die(const char *format, ...)
{
	char line[1024];
	va_list ap;

	va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
	va_end(ap);
	syslog(LOG_ERR, "fatal: %s", line);
	exit(EXIT_FAILURE);
}

/* Protocol or other error */
void logit(int level, char c, const char *format, ...)
{
	char line[1024];
	va_list ap;

	va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
	va_end(ap);

	if (debug)
		zclock_log("%c: %s", c, line);
	else
		syslog(level, "%s", line);
}

#ifdef DEBUG
void dump_netlink(const struct nlmsghdr *nlh)
{
	/* extra header based on type of message */
	static const size_t rtm_header_size[RTM_NR_FAMILIES] = {
		[RTM_FAM(RTM_NEWLINK)]      = sizeof(struct ifinfomsg),
		[RTM_FAM(RTM_NEWADDR)]      = sizeof(struct ifaddrmsg),
		[RTM_FAM(RTM_NEWROUTE)]     = sizeof(struct rtmsg),
		[RTM_FAM(RTM_NEWRULE)]      = sizeof(struct fib_rule_hdr),
		[RTM_FAM(RTM_NEWQDISC)]     = sizeof(struct tcmsg),
		[RTM_FAM(RTM_NEWTCLASS)]    = sizeof(struct tcmsg),
		[RTM_FAM(RTM_NEWTFILTER)]   = sizeof(struct tcmsg),
		[RTM_FAM(RTM_NEWACTION)]    = sizeof(struct tcamsg),
		[RTM_FAM(RTM_GETMULTICAST)] = sizeof(struct rtgenmsg),
		[RTM_FAM(RTM_GETANYCAST)]   = sizeof(struct rtgenmsg),
		[RTM_FAM(RTM_NEWNETCONF)]   = sizeof(struct netconfmsg),
	};

	mnl_nlmsg_fprintf(stderr, nlh, nlh->nlmsg_len,
			  rtm_header_size[RTM_FAM(nlh->nlmsg_type)]);
}
#endif
