/*
 * netlink message handling functions
 *
 * Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>

#include <czmq.h>

#include "controller.h"

struct _nlmsg {
	atomic_int	refcnt;
	char	       *topic;
	uint64_t	seqno;

	size_t		size;	/* number of bytes of data */
	byte		data[];	/* variable length */
};

/*
 * Construct a netlink message object from
 */
nlmsg_t *nlmsg_new(const char *str, uint64_t seqno,
		   const void *data, size_t len)
{
	nlmsg_t *self = malloc(sizeof(*self) + len);
	if (!self)
		return NULL;

	atomic_store_explicit(&self->refcnt, 1, memory_order_relaxed);
	self->topic = strdup(str);
	self->seqno = seqno;
	self->size = len;
	memcpy(self->data, data, len);

	return self;
}

void nlmsg_free(nlmsg_t *self)
{
	assert(atomic_load_explicit(&self->refcnt, memory_order_relaxed) != 0);

	int old_refcnt = atomic_fetch_sub_explicit(&self->refcnt, 1,
						   memory_order_relaxed);
	if (old_refcnt <= 1) {
		free(self->topic);
		free(self);
	}
}

static
void zmq_nlmsg_free(void *data __unused, void *hint)
{
	nlmsg_t *self = hint;
	nlmsg_free(self);
}

nlmsg_t *nlmsg_copy(nlmsg_t *self)
{
	atomic_fetch_add_explicit(&self->refcnt, 1, memory_order_relaxed);
	return self;
}

int seqno_sendm(zsock_t *socket, uint64_t seqno)
{
	zmsg_t *m = zmsg_new();
	if (zmsg_addmem(m, &seqno, sizeof(uint64_t)) == -1)
		return -1;

	if (zmsg_sendm(&m, socket) == -1)
		return -1;

	return 0;
}

/*
 * Constructor from incoming message
 * received protocol with three parts:
 *  [1] topic string - extracted and pass-in by caller.
 *  [2] sequence number
 *  [3] netlink data
 */
nlmsg_t *nlmsg_recv(const char *topic, zmsg_t *msg)
{
	nlmsg_t *nmsg = NULL;
	zframe_t *frame = zmsg_first(msg);
	if (!frame || zframe_size(frame) != sizeof(uint64_t))
		return NULL;

	uint64_t seqno;
	memcpy(&seqno, zframe_data(frame), sizeof(uint64_t));

	frame = zmsg_next(msg);
	if (frame != NULL)
		nmsg = nlmsg_new(topic, seqno,
				 zframe_data(frame), zframe_size(frame));

	return nmsg;
}

/* Send topic/seqno/netlink.
   If successful then destroyed after sending. */
int nlmsg_send(nlmsg_t *self, zsock_t *socket)
{
	zmq_msg_t message;
	void *handle = zsock_resolve(socket);
	int rc;

	rc = zmq_msg_init_data(&message,
			       self->topic, strlen(self->topic),
			       NULL, NULL);
	if (rc)
		goto err;

	if (zmq_msg_send(&message, handle, ZMQ_SNDMORE) == -1) {
		rc = -1;
		zmq_msg_close(&message);
		goto err;
	}

	rc = zmq_msg_init_data(&message,
			       &self->seqno, sizeof(uint64_t),
			       NULL, NULL);
	if (rc)
		goto err;

	if (zmq_msg_send(&message, handle, ZMQ_SNDMORE) == -1) {
		rc = -1;
		zmq_msg_close(&message);
		goto err;
	}

	rc = zmq_msg_init_data(&message,
			       self->data, self->size,
			       zmq_nlmsg_free, self);
	if (rc)
		goto err;
	nlmsg_copy(self);

	if (zmq_msg_send(&message, handle, 0) == -1) {
		rc = -1;
		zmq_msg_close(&message);
		goto err;
	}

 err:
	nlmsg_free(self);
	return rc;
}

void nlmsg_dump(const char *prefix, const nlmsg_t *self)
{
	unsigned l = 0;
	char buf[BUFSIZ];

	if (!self)
		return;

	if (prefix) {
		if (debug > 2)
			l = snprintf(buf, sizeof(buf), "--- %s ---\n", prefix);
		else
			l = snprintf(buf, sizeof(buf), "%s ", prefix);
	}

	l += snprintf(buf + l, sizeof(buf) - l,
		      "[%"PRIu64"] %s",
		      self->seqno, self->topic);

	if (debug > 2) {
		unsigned i;

		l += snprintf(buf + l, sizeof(buf) - l,
			      "\n %4zu\t", self->size);
		for (i = 0; i < self->size && i < 32; i++) {
			l += snprintf(buf + l, sizeof(buf) - l,
				      "%02x", self->data[i]);
		}
	}

	dbg("%s", buf);
}

const char *nlmsg_key(const nlmsg_t *self)
{
	return self->topic;
}

uint64_t nlmsg_seqno(const nlmsg_t *self)
{
	return self->seqno;
}

const void *nlmsg_data(const nlmsg_t *self)
{
	return self->data;
}
