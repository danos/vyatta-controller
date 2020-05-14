/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#if !defined(__nlmsg_h__)
#define __nlmsg_h__

typedef struct _nlmsg nlmsg_t;

int seqno_sendm(zsock_t *socket, uint64_t seqno);
nlmsg_t *nlmsg_new(const char *str, uint64_t seqno, const void *data,
		   size_t len);
void nlmsg_free(nlmsg_t *nlmsg);
nlmsg_t *nlmsg_recv(const char *topic, zmsg_t *msg);
int nlmsg_send(nlmsg_t *nlmsg, zsock_t *socket);
void nlmsg_dump(const char *prefix, const nlmsg_t *nlmsg);
nlmsg_t *nlmsg_copy(nlmsg_t *nlmsg);
const char *nlmsg_key(const nlmsg_t *nlmsg);
uint64_t nlmsg_seqno(const nlmsg_t *nlmsg);
const void *nlmsg_data(const nlmsg_t *nlmsg);

void nlmsg_pending_add(const char *topic, const struct nlmsghdr *nlh,
		       uint32_t ifindex);
void nlmsg_pending_propagate(uint32_t ifindex, uint64_t *seqno);
bool nlmsg_ifindex_add(uint32_t ifindex, const char *ifname);
bool nlmsg_ifindex_lookup(uint32_t ifindex);
void nlmsg_ifindex_del(uint32_t ifindex);

zhashx_t *nlmsg_ifindex_hash(void);
zlist_t *nlmsg_pending_list(void);

void nlmsg_setup(void);
void nlmsg_cleanup(void);
#endif
