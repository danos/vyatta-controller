/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Tunnel management
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include <czmq.h>

#include "controller.h"

/* Vyatta specific extension to GRE tunnel driver. */
#ifndef SIOCSIFSTATS
#define SIOCSIFSTATS	0x89D0
#endif

#ifndef SIOCTUNNELINFO
#define SIOCTUNNELINFO	(SIOCDEVPRIVATE + 15)
struct ip_tunnel_info {
	char driver[32];
	char bus[32];
};
#endif


/* Definitions are not in upstream kernel */
#ifndef SIOCTUNNELPERMADDR
#define SIOCTUNNELPERMADDR (SIOCDEVPRIVATE + 14)
#endif

#ifndef TUNSETPERMADDR
#define TUNSETPERMADDR _IOW('T', 230, struct ifreq)
#endif

/* template in net/if.h but that conflicts with linux/if.h */
extern unsigned int if_nametoindex(const char *__ifname);

/* Global state */
tun_t *tun;

static int port_tap_open(const char *ifname)
{
	struct ifreq ifr;
	int fd;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	fd = open("/dev/net/tun", O_RDWR|O_NDELAY);

	if (fd < 0) {
		err("can not open /dev/net/tun device: %s",
		    strerror(errno));
		return -1;
	}

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		err("ioctl(TUNSETIFF) failed: %s",
		    strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/* Make local TUN/TAP device to get ifindex assigned
 * then close it.
 */
static int port_tap_setup(const char *ifname, const struct ether_addr *eth)
{
	struct ifreq ifr;
	int fd, ret = -1;

	dbg("create tap %s", ifname);

	/* Set the name and type of new endpoint */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if ((fd = port_tap_open(ifname)) < 0)
		return -1;

	if (ioctl(fd, TUNSETPERSIST, 1) < 0)
		err("ioctl(TUNSETPERSIST) failed: %s",
		    strerror(errno));
	else {
		memcpy(ifr.ifr_hwaddr.sa_data, eth, ETH_ALEN);
		if (ioctl(fd, TUNSETPERMADDR, &ifr) < 0)
			/* This may fail if running on unpatched kernel. */
			err("ioctl(TUNSETPERMADDR) failed: %s\n",
			    strerror(errno));
		ret = 0;
	}
	close(fd);
	return ret;
}

/*
 * A tun/tap device stays in NO-CARRIER state if no
 * userspace app is connected to it. If the dataplane is
 * remote, then we'll have to do that here.
 */
static void port_tap_fd(const vplane_t *vp, uint32_t port,
			const char *ifname, bool up)
{
	int fd = vplane_iface_get_fd(vp, port);

	if (up) {
		if (fd == -1)
			fd = port_tap_open(ifname);
		else
			return;
	} else {
		if (fd != -1) {
			close(fd);
			fd = -1;
		} else
			return;
	}

	if (vplane_iface_set_fd(vp, port, fd) < 0) {
		err("port %s failed to store fd %d", ifname, fd);
		if (fd != -1)
			close(fd);
	}
}

static int port_teardown(unsigned int ifindex, const char *ifname)
{
	if (tun_delete(tun, ifindex) < 0) {
		err("port %s (ifindex %u) delete failed: %s",
		    ifname, ifindex, strerror(errno));
		return -1;
	}
	return 0;
}

/* Set the hardware (ethernet) address */
static void port_set_mac_address(const char *ifname,
				 const struct ether_addr *eth)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	memcpy(ifr.ifr_hwaddr.sa_data, eth, ETH_ALEN);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

	if (ioctl(udp_fd, SIOCSIFHWADDR, &ifr) < 0)
		err("ioctl(SIOCSIFHWADDR) failed: %s",
		    strerror(errno));
}

static void port_set_info(const char *ifname, const char *driver,
			  const char *bus_info, unsigned int if_flags,
			  unsigned int mtu)
{
	struct ip_tunnel_info info;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = &info;

	strncpy(info.driver, driver, sizeof(info.driver));
	strncpy(info.bus, bus_info ? : "", sizeof(info.bus));

	if (ioctl(udp_fd, SIOCTUNNELINFO, &ifr) < 0)
		notice("ioctl(SIOCTUNNELINFO): %s", strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(udp_fd, SIOCGIFFLAGS, &ifr) < 0) {
		notice("ioctl(SIOCGIFFLAGS): %s", strerror(errno));
		return;
	}
	ifr.ifr_flags |= if_flags;
	if (ioctl(udp_fd, SIOCSIFFLAGS, &ifr) < 0)
		notice("ioctl(SIOCSIFFLAGS): %s", strerror(errno));

	if (mtu) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

		ifr.ifr_mtu = mtu;
		if (ioctl(udp_fd, SIOCSIFMTU, &ifr) < 0)
			notice("ioctl(SIOCSIFMTU): %s", strerror(errno));
	}
}

/*
 * Process port creation message
 *
 *  0 if successful (ifindex value returned)
 * -1 if failed
 */
int port_create(const vplane_t *vp, uint32_t port, const char *ifname,
		const struct ether_addr *eth, const char *driver,
		const char *bus, unsigned int if_flags, unsigned int mtu,
		uint32_t *ifindexp)
{
	uint32_t ifindex = if_nametoindex(ifname);
	*ifindexp = 0;

	dbg("setup %s ifindex %d eth %s", ifname, ifindex, ether_ntoa(eth));

	/* initial creation */
	if (ifindex == 0) {
		if (port_tap_setup(ifname, eth) < 0)
			return -1;
		port_set_mac_address(ifname, eth);
	}

	*ifindexp = ifindex = if_nametoindex(ifname);

	/* Is this dataplane running on the controller? */
	if (!vplane_is_local(vp)) {
		/* put the tap into dormant mode */
		tun_set_dormant(tun, ifname);

		/* Toggle to restore correct IPv6 address/state if admin UP*/
		if (tun_admin_is_up(tun, ifindex) == true)
			tun_admin_toggle(tun, ifindex);

		/* If there was an fd open for this port already, close it. */
		port_tap_fd(vp, port, ifname, false);
	}

	/*
	 * Override the kernel default speed & duplex with unknown in
	 * case we don't get any LINKUP/LINKDOWN messages from the
	 * dataplane for this interface.
	 */
	port_set_speed(ifname, SPEED_UNKNOWN, DUPLEX_UNKNOWN, 0, true);

	if (driver)
		port_set_info(ifname, driver, bus, if_flags, mtu);

	return 0;
}

/*
 * Process port deletion message
 *
 *  0 if successful
 * -1 if failed
 */
int port_delete(const vplane_t *vp, uint32_t port,
		uint32_t ifindex)
{
	/* Is this dataplane running on the controller? */
	if (vplane_is_local(vp)) {
		if (ifindex == 0)
			goto bad;
	} else {
		const char *ifname = vplane_iface_get_ifname(vp, port);

		/* vplane_iface_get_ifname does its own logging on failure */
		if (!ifname)
			goto bad;

		port_tap_fd(vp, port, ifname, false);

		if (port_teardown(ifindex, ifname) < 0)
			goto bad;
	}

	return 0;

 bad:
	return -1;
}

int port_state_change(const vplane_t *vp, uint32_t port, uint32_t ifindex,
		      uint32_t operstate)
{
	if (!vplane_is_local(vp)) {
		const char *ifname = vplane_iface_get_ifname(vp, port);

		/* vplane_iface_get_ifname does its own logging on failure */
		if (!ifname)
			return -1;

		port_tap_fd(vp, port, ifname, (operstate == IF_OPER_UP));
	}

	return tun_set_linkstate(tun, ifindex, operstate);
}

int port_set_speed(const char *ifname, unsigned speed,
				       unsigned duplex,
				       uint32_t advertised,
				       bool preserve_link_modes)
{
	struct ethtool_cmd ecmd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = &ecmd;

	ecmd.cmd = ETHTOOL_GSET;
	if (ioctl(udp_fd, SIOCETHTOOL, &ifr) < 0) {
		notice("ethtool get settings %s failed %s",
		      ifname, strerror(errno));
		return -1;
	}

	if (ethtool_cmd_speed(&ecmd) == speed &&
	    ecmd.duplex == duplex &&
	    (!preserve_link_modes && ecmd.advertising == advertised))
		return 0;

	ecmd.duplex = duplex;
	ethtool_cmd_speed_set(&ecmd, speed);
	ecmd.cmd = ETHTOOL_SSET;
	if (!preserve_link_modes) {
		ecmd.advertising = advertised;
		ecmd.autoneg = advertised & ADVERTISED_Autoneg ?
							AUTONEG_ENABLE :
							AUTONEG_DISABLE;
	}
	ecmd.supported = SUPPORTED_Autoneg;
	ecmd.port = PORT_OTHER;

	if (ioctl(udp_fd, SIOCETHTOOL, &ifr) < 0) {
		if (errno != ENOTSUP)
			notice("ethtool set settings %s failed %s",
			      ifname, strerror(errno));
		return -1;
	}
	return 0;
}

/* Use Vyatta kernel specific ioctl to set link statistics on tunnel */
static int set_if_stats(const char *ifname, void *stats)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = stats;

	return ioctl(udp_fd, SIOCSIFSTATS, &ifr);
}

/*
 * Hash table of cached interface statistics
 */
static zhashx_t *if_stats;

/*
 * Structure used to cache interface statistics from one dataplane
 */
struct dp_stats {
	int dp_id;
	struct rtnl_link_stats64 stats;
};

/*
 * Add two blocks of interface statistics
 */
static void add_if_stats(struct rtnl_link_stats64 *stats,
			struct rtnl_link_stats64 *inc)
{
	stats->rx_packets += inc->rx_packets;
	stats->tx_packets += inc->tx_packets;
	stats->rx_bytes += inc->rx_bytes;
	stats->tx_bytes += inc->tx_bytes;
	stats->rx_errors += inc->rx_errors;
	stats->tx_errors += inc->tx_errors;
	stats->rx_dropped += inc->rx_dropped;
	stats->tx_dropped += inc->tx_dropped;
	stats->multicast += inc->multicast;
}

/*
 * Subtract two blocks of interface statistics
 */
static void sub_if_stats(struct rtnl_link_stats64 *stats,
			struct rtnl_link_stats64 *dec)
{
	stats->rx_packets -= dec->rx_packets;
	stats->tx_packets -= dec->tx_packets;
	stats->rx_bytes -= dec->rx_bytes;
	stats->tx_bytes -= dec->tx_bytes;
	stats->rx_errors -= dec->rx_errors;
	stats->tx_errors -= dec->tx_errors;
	stats->rx_dropped -= dec->rx_dropped;
	stats->tx_dropped -= dec->tx_dropped;
	stats->multicast -= dec->multicast;
}

/*
 * Delete cached interface statistics
 */
static void free_if_stats(void **item)
{
	struct dp_stats **dp_stats = (struct dp_stats **) item;

	free(*dp_stats);
	*dp_stats = NULL;
}

/*
 * Delete all cached statistics for an interface
 */
static void free_if_list(void **item)
{
	zlistx_t **if_stats_list = (zlistx_t **) item;

	zlistx_destroy(if_stats_list);
}

/*
 * Delete all cached interface statistics
 */
static void purge_if_stats(void)
{
	zhashx_destroy(&if_stats);
}

/*
 * Aggregate interface statistics with those already cached.
 *
 * We maintain a hash table with an entry for each interface generating
 * statistics.
 *
 * Each hash entry is a linked list of cached statistics generated by different
 * dataplanes.
 *
 * Each list entry contains the dataplane ID and a block of statistics.
 *
 * When the list contains entries from multiple dataplanes, the entry at the
 * head of list (with a dataplane ID of 0) maintains a running total of all
 * statistics cached in the list.
 */
static void aggregate_if_stats(const char *ifname, int dp_id,
			       struct rtnl_link_stats64 *stats)
{
	zlistx_t *if_stats_list;
	struct dp_stats *cache_stats, *dp_stats = NULL, *total_stats = NULL,
		*other_stats = NULL;

	/* Create cache hash table if it doesn't exist */
	if (if_stats == NULL) {
		if_stats = zhashx_new();
		if (if_stats == NULL)
			return;
		zhashx_set_destructor(if_stats, free_if_list);
	}

	/* Create list for this interface if it doesn't exist */
	if_stats_list = zhashx_lookup(if_stats, ifname);
	if (if_stats_list == NULL) {
		if_stats_list = zlistx_new();
		zlistx_set_destructor(if_stats_list, free_if_stats);
		if (zhashx_insert(if_stats, ifname, if_stats_list) != 0) {
			zlistx_destroy(&if_stats_list);
			return;
		}
	}

	cache_stats = zlistx_first(if_stats_list);
	while (cache_stats != NULL) {
		if (cache_stats->dp_id == 0)
			total_stats = cache_stats;
		else
			if (cache_stats->dp_id == dp_id)
				dp_stats = cache_stats;
			else
				other_stats = cache_stats;

		/* If we've found all relevant entries, look no further */
		if ((total_stats != NULL) && (dp_stats != NULL) &&
			(other_stats != NULL))
			break;

		cache_stats = zlistx_next(if_stats_list);
	}

	if (total_stats == NULL) {
		/*
		 * If we have statistics from other dataplanes but no existing
		 * total, create the total now
		 */
		if (other_stats != NULL) {
			total_stats = malloc(sizeof(struct dp_stats));
			if (total_stats == NULL)
				return;
			total_stats->dp_id = 0;

			/* Copy other stats to the total */
			total_stats->stats = other_stats->stats;

			if (zlistx_add_start(if_stats_list, total_stats)
				== NULL) {
				free(total_stats);
				return;
			}
		}
	} else
		/* Subtract previously cached stats from existing total */
		if (dp_stats != NULL)
			sub_if_stats(&total_stats->stats, &dp_stats->stats);

	/* Create cache entry for this dataplane if it doesn't already exist */
	if (dp_stats == NULL) {
		dp_stats = malloc(sizeof(struct dp_stats));
		if (dp_stats == NULL)
			return;
		dp_stats->dp_id = dp_id;

		if (zlistx_add_end(if_stats_list, dp_stats) == NULL) {
			free(dp_stats);
			return;
		}
	}

	/* Copy current stats to the cache */
	dp_stats->stats = *stats;

	/* If we have a running total, add the newly cached stats to it */
	if (total_stats != NULL) {
		add_if_stats(&total_stats->stats, &dp_stats->stats);

		/* Copy new total back to our caller */
		*stats = total_stats->stats;
	}
}

/*
 * Deleted cached interface statistics
 */
void del_if_stats(const char *ifname)
{
	if (if_stats != NULL)
		zhashx_delete(if_stats, ifname);
}

int port_set_stats(const char *ifname, zframe_t *fr, bool aggregate, int dp_id)
{
	size_t size = zframe_size(fr);
	struct rtnl_link_stats64 stats;

	if (size > sizeof(stats)) {
		notice("size of stats error from '%s' (got %zd expect <= %zd)",
		       ifname, size, sizeof(struct rtnl_link_stats64));
		return -1;
	}

	/* convert from protocol to kernel */
	memset(&stats, 0, sizeof(stats));
	memcpy(&stats, zframe_data(fr), size);

	if (aggregate)
		aggregate_if_stats(ifname, dp_id, &stats);

	if (set_if_stats(ifname, &stats) < 0)
		notice("can not set link statistics: %s",
		       strerror(errno));

	return 0;
}

void port_init(void)
{
	/* Setup tunnel (netlink) interface) */
	tun = tun_init();
	if (!tun)
		panic("tunnel_broker_init");
}

void port_destroy(void)
{
	tun_destroy(tun);
	purge_if_stats();
}
