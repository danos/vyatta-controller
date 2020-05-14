/*
 * Controller parameters
 *
 * Copyright (c) 2017-2020 AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifdef RTNLGRP_RTDMN
#include <linux/rtg_domains.h>
#endif
#include <linux/netlink.h>
#include "ip_addr.h"
#include "vplane.h"
#include "nlmsg.h"

/* Used to silence Gcc where necessary */
#define __unused	__attribute__((unused))

/* These are sanity check values, code should handle larger */
#define MAX_DATAPLANE_ID    1024
#define MAX_PORTS           256

/* command socket */
#define CMD_IPC "ipc:///var/run/vyatta/vplaned.socket"

extern int debug;
int zmsg_popu32(zmsg_t *msg, uint32_t *p);
void request_thread(zsock_t *pipe, void *args);
void request_test_msg(void *sock, zmsg_t *msg, void *snap);
zsock_t *request_test_reconfigure(zloop_t *loop, zmsg_t *msg, void *pipe,
				  zsock_t *request);
void authentication_enable(zsock_t *socket);

extern int udp_fd;
#define panic(format, args...) __panic(__func__, format, ##args)
void __panic(const char *funcname, const char *format, ...)
	__attribute__((noreturn))
	__attribute__((format(printf, 2, 3)));
void die(const char *format, ...)
	__attribute__((noreturn))
	__attribute__((format(printf, 1, 2)));

void logit(int level, char c, const char *format, ...)
	__attribute__((format(printf, 3, 4)));

#define dbg(format, args...)						\
	do {								\
		if (debug) logit(LOG_DEBUG, 'D', format, ##args);	\
	} while(0)
#define info(format, args...)   logit(LOG_INFO, 'I', format, ##args)
#define notice(format, args...) logit(LOG_NOTICE, 'N', format, ##args)
#define err(format, args...)    logit(LOG_ERR, 'E', format, ##args)

struct nlattr;
int link_attr(const struct nlattr *attr, void *data);
int linkinfo_attr(const struct nlattr *attr, void *data);

int if_get_flags(const char *ifname);
int if_set_flags(const char *ifname, unsigned flags);
struct ether_addr;
int if_get_ethaddr(const char *ifname, struct ether_addr *eth);
int if_set_ethaddr(const char *ifname, const struct ether_addr *eth);
int if_rename(const char *oldname, const char *newname);

/* Port management */
void port_init(void);
void port_destroy(void);
int port_create(const vplane_t *vp, uint32_t port,
		const char *ifname, const struct ether_addr *eth,
		const char *driver, const char *bus,
		unsigned int if_flags, unsigned int mtu,
		uint32_t *ifindex);
int port_delete(const vplane_t *vp, uint32_t port,
		uint32_t ifindex);
int port_state_change(const vplane_t *vp, uint32_t port, uint32_t ifindex,
		      uint32_t operstate);
int port_set_stats(const char *ifname, zframe_t *fr, bool aggregate, int dp_id);
int port_set_speed(const char *ifname, unsigned speed,
		   unsigned duplex, uint32_t advertised,
		   bool preserve_link_modes);
int assign_port(const char *json, unsigned int dp_id,
		char *ifname, struct ether_addr *eth,
		char **driver, char **bus, unsigned int *if_flags,
		unsigned int *mtu);
void del_if_stats(const char *ifname);

/* Tunnel management */
typedef struct mnl_socket tun_t;
tun_t *tun_init(void);
void tun_destroy(tun_t *);
struct ether_addr;
int tun_delete(tun_t *self, unsigned int ifindex);
int tun_set_dormant(tun_t *nl, const char *ifname);
int tun_set_linkstate(tun_t *self, unsigned int ifindex,
		      unsigned int operstate);
bool tun_admin_is_up(tun_t *self, unsigned int ifindex);
void tun_admin_toggle(tun_t *self, unsigned int ifindex);

const char *nl_route_type(unsigned int type);
int nl_generate_topic(const struct nlmsghdr *nlm, char *buf, size_t len,
		      uint32_t *ifindex);

void nl_propagate_nlmsg(nlmsg_t *nmsg);
const char *nlmsg_type_name_rtnl(const struct nlmsghdr *nlm);

typedef struct _snapshot snapshot_t;
snapshot_t *snapshot_new(void);
void snapshot_destroy(snapshot_t **snap);
uint64_t snapshot_seqno(const snapshot_t *snap);
int snapshot_update(snapshot_t *snap, nlmsg_t *nmsg);
void snapshot_send(snapshot_t *snap, void *socket, zframe_t *to);

/* Config */
void publish_cmd(const char *topic, uint64_t seqno, const char *line, bool bin);
int nl_generate_topic_xfrm(const struct nlmsghdr *nlh, char *buf,
			   size_t buflen, bool *snapshot);
int nl_generate_topic_l2tp(const struct nlmsghdr *nlh, char *buf,
			   size_t buflen);
void set_perm(const char *path);
int process_gen_config(const char *line);

/* Hwbinding */
const char *get_name_by_pcislot(int slot, int function);
const char *get_name_by_pciaddr(const char *pciaddress);
const char *get_name_by_mac(const char *mac);
const char *get_name_by_fwidx(int fwidx);
const char *get_name_by_port(int port);
void read_interface_cfg(const char *name);
void interface_cfg_destroy(void);

int fsnotify_init(void);
void fsnotify_handle_events(void);
void fsnotify_destroy(void);
void fsnotify_add_mpls_watchers(void);
void fsnotify_add_redirects_watchers(void);
