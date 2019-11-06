/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2014-2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Multicast packet stats
 */

#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <syslog.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>

#ifndef SO_RTDOMAIN
#include <vrf_manager.h>
#endif

#include <czmq.h>
#include "compat.h"
#include "controller.h"
#include "mrtstat.h"

/*
 * Size of buffer to hold VRF ID as a string.
 * Max 10 digits (32 bit VRF IDs) + 1 digit (terminating "\0")
 */
#define MAX_MRT_HASH_KEY_LEN 11

/*
 * Hash tables  to hold per-VRF IGMP sockets for each AF.
 * Key is VRF ID (converted to a string).
 */
static zhash_t *igmpv4_sockets_hash_table;
static zhash_t *igmpv6_sockets_hash_table;

/*
 * Create hash tables at initialisation time.
 */
void igmp_setup(void)
{
	igmpv4_sockets_hash_table = zhash_new();
	igmpv6_sockets_hash_table = zhash_new();

	if (!igmpv4_sockets_hash_table || !igmpv6_sockets_hash_table)
	  die("Mcast stats socket creation failure\n");
}

/*
 * Destroying a hash table results in close_igmp_socket()
 * being executed for every hash table item (i.e. socket).
 * close_igmp_socket() closes the socket and frees the
 * associated memory.
 */
void igmp_teardown(void)
{
	zhash_destroy(&igmpv4_sockets_hash_table);
	zhash_destroy(&igmpv6_sockets_hash_table);
}

/*
 * Callback invoked when item deleted from IPv4/IPv6 hash tables.
 */
static void close_igmp_socket(void *arg)
{
	int *igmp_socket =  arg;
	close(*igmp_socket);
	free(igmp_socket);
}

/*
 * IPv4/IPv6 hash key is simply VRF ID converted into a string.
 */
static char *igmp_socket_hash_key(uint32_t vrf_id, char *key_buf,
				  uint32_t buf_size)
{
	uint32_t written;
	written = snprintf(key_buf, buf_size, "%d", vrf_id);
	if (written >= buf_size)
		return NULL;

	return key_buf;
}


static int igmp_socket_bind_vrf(int socket, uint32_t vrf_id, uint32_t af)
{
	if (vrf_id == VRF_DEFAULT_ID)
		return 0;

#ifdef SO_RTDOMAIN
	if (setsockopt (socket, SOL_SOCKET, SO_RTDOMAIN,
					&vrf_id, sizeof (vrf_id)) < 0) {
		err("Failure setting socket %d into VRF %u; err = %s",
		    socket, vrf_id, strerror(errno));
		return -1;
	}
#else
	char *vrf_name;
	uint32_t kernel_table_id;

	if (!get_vrf_name (vrf_id, &vrf_name)) {
		err("Failure getting name for VRF %u", vrf_id);
		return -1;
	}

	kernel_table_id = get_vrf_kernel_table_id (vrf_name, RT_TABLE_MAIN);
	free(vrf_name);

	if (kernel_table_id == RT_TABLE_UNSPEC) {
		err("Failure getting kernel table ID for VRF %u", vrf_id);
		return -1;
	}

	if (setsockopt (socket, af == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
					af == AF_INET ? MRT_TABLE : MRT6_TABLE,
					&kernel_table_id, sizeof(kernel_table_id)) < 0) {
		err("Failure setting kernel table ID %u for VRF %u on socket %d"
			"; err = %s", kernel_table_id, vrf_id, socket, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

/*
 * Create a new socket to deliver stats update from data plane to the kernel,
 * using the sockets options to ensure stats associated with correct VRF.
 * This socket will cached in an AF-specific hash table (key is VRF ID)
 * for use in subsequent stats updates.
 */
static int init_igmp_socket(uint32_t vrf_id, uint32_t af, uint32_t protocol)
{
	int igmp_socket;

	if ((igmp_socket = socket(af, SOCK_RAW, protocol)) < 0)
		return -1;

	if (igmp_socket_bind_vrf(igmp_socket, vrf_id, af) < 0) {
		close(igmp_socket);
		return -1;
	}

	return igmp_socket;
}

/*
 * Flag in stats message indicates this stats block is for an mroute
 * which is the last one in the VRF and is about to be deleted.  Thus
 * the corresponding per-VRF socket should be closed.
 */
int mcast_close_stats_socket(uint32_t vrf_id, uint32_t af)
{
	const char *key;
	char key_buf[MAX_MRT_HASH_KEY_LEN];
	zhash_t *sockets_hash_table;
	int *igmp_socket;

	switch (af) {
	case AF_INET:
	  sockets_hash_table = igmpv4_sockets_hash_table;
	  break;
	case AF_INET6:
	  sockets_hash_table = igmpv6_sockets_hash_table;
	  break;
	default:
	  return -1;
	}

	key = igmp_socket_hash_key(vrf_id, key_buf, sizeof(key_buf));
	if (!key)
		return -1;

	igmp_socket = zhash_lookup(sockets_hash_table, key);
	if (!igmp_socket) {
	  notice("%s mcast socket for VRF %u already closed",
		 (af == AF_INET) ? "IPv4" : "IPv6", vrf_id);
	  return 0;
	}

	zhash_delete(sockets_hash_table, key);
	return 0;
}

/*
 * Stats update from data plane received for specific IPv4 VRF.
 * Need to find or create the socket and deliver the stats to the
 * kernel via an ioctl call.
 */
int set_sg_count(struct sioc_sg_req *sgreq, uint32_t vrf_id)
{
	int *igmpv4_socket;
	const char *key;
	char key_buf[MAX_MRT_HASH_KEY_LEN];
	char source[INET_ADDRSTRLEN];
	char group[INET_ADDRSTRLEN];

	key = igmp_socket_hash_key(vrf_id, key_buf, sizeof(key_buf));
	if (!key)
		return 1;

	igmpv4_socket = zhash_lookup(igmpv4_sockets_hash_table, key);
	if (!igmpv4_socket) {
		igmpv4_socket = calloc(1, sizeof(int));
		if (!igmpv4_socket)
			return 1;

		inet_ntop(AF_INET, &sgreq->src, source, sizeof(source));
		inet_ntop(AF_INET, &sgreq->grp, group, sizeof(group));
		notice("First stats update for IPv4 VRF %u; mroute is (%s, %s)",
		       vrf_id, source, group);

		if ((*igmpv4_socket = init_igmp_socket(vrf_id, AF_INET,
						       IPPROTO_IGMP)) < 0) {
			err("Failure opening socket for IPv4 VRF %u", vrf_id);
			free(igmpv4_socket);
			return 1;
		}

		if (zhash_insert(igmpv4_sockets_hash_table,
				 key, igmpv4_socket) < 0) {
			err("Failure caching socket for IPv4 VRF %u", vrf_id);
			close_igmp_socket(igmpv4_socket);
			return 1;
		}

		zhash_freefn(igmpv4_sockets_hash_table, key, close_igmp_socket);
	}

	if (ioctl(*igmpv4_socket, SIOCSETSGCNT, (char *)sgreq) < 0) {
		err("SIOCSETSGCNT on socket %d failure; err = %s",
		    *igmpv4_socket, strerror(errno));
		zhash_delete(igmpv4_sockets_hash_table, key);
		return 1;
	}

	return 0;
}

/*
 * Stats update from data plane received for specific IPv6 VRF.
 * Need to find or create the socket and deliver the stats to the
 * kernel via an ioctl call.
 */
int set_sg6_count(struct sioc_sg_req6 *sgreq, uint32_t vrf_id)
{
	int *igmpv6_socket;
	const char *key;
	char key_buf[MAX_MRT_HASH_KEY_LEN];
	char source[INET6_ADDRSTRLEN];
	char group[INET6_ADDRSTRLEN];

	key = igmp_socket_hash_key(vrf_id, key_buf, sizeof(key_buf));
	if (!key)
		return 1;

	igmpv6_socket = zhash_lookup(igmpv6_sockets_hash_table, key);
	if (!igmpv6_socket) {
		igmpv6_socket = calloc(1, sizeof(int));
		if (!igmpv6_socket)
			return 1;

		inet_ntop(AF_INET6, &sgreq->src.sin6_addr,
			  source, sizeof(source));
		inet_ntop(AF_INET6, &sgreq->grp.sin6_addr,
			  group, sizeof(group));
		notice("First stats update for IPv6 VRF %u; mroute is (%s, %s)",
			vrf_id, source, group);

		if ((*igmpv6_socket = init_igmp_socket(vrf_id, AF_INET6,
						       IPPROTO_ICMPV6)) < 0) {
			err("Failure opening socket for IPv6 VRF %u", vrf_id);
			free(igmpv6_socket);
			return 1;
		}

		if (zhash_insert(igmpv6_sockets_hash_table, key,
				 igmpv6_socket) < 0) {
			err("Failure caching socket for IPv6 VRF %u", vrf_id);
			close_igmp_socket(igmpv6_socket);
			return 1;
		}

		zhash_freefn(igmpv6_sockets_hash_table, key, close_igmp_socket);
	}

	if (ioctl(*igmpv6_socket, SIOCSETSGCNT_IN6, (char *)sgreq) < 0) {
		err("SIOCSETSGCNT_IN6 on socket %d failure; err = %s",
		    *igmpv6_socket, strerror(errno));
		zhash_delete(igmpv6_sockets_hash_table, key);
		return 1;
	}

	return 0;
}
