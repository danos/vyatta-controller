/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2014-2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef _MRTSTAT_H
#define _MRTSTAT_H
#include <linux/mroute.h>
#include <linux/mroute6.h>

#include <netinet/igmp.h>

/*
 * Multicast packet stats
 */

#define SIOCSETSGCNT    (SIOCPROTOPRIVATE+3)
#define SIOCSETSGCNT_IN6 (SIOCPROTOPRIVATE+3)

int set_sg_count(struct sioc_sg_req *sgreq, uint32_t vrf_id);
int set_sg6_count(struct sioc_sg_req6 *sgreq, uint32_t vrf_id);
int mcast_close_stats_socket(uint32_t vrf_id, uint32_t af);

void igmp_setup(void);
void igmp_teardown(void);
#endif
