/**
 *  Mostly interface between the generic configuration store
 *  and the rest of the controller. The external requirements
 *  are to interpret single commands and to provide a snapshot
 *  of all commands during a resync request.
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017-2019 AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 **/
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <net/if.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <json.h>
#include <czmq.h>

#include "protobuf.h"
#include "controller.h"
#include "configdb.h"
#include "configstore.h"
#include "configcmd.h"

static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	zsock_t *socket;		/* socket to send to */
	zframe_t *client;	/* identity of client requesting */
} target_t;

/*
  Configuration command entry point. Expects JSON formatted request
  with specific value nodes (see documentation else in this file and
  in configdb.c).

  Currently locked via mutex (can be upgraded as needed)
 */
int config_cmd(const char *line)
{
	//parse json
	enum json_tokener_error error = json_tokener_success;
	json_object *jobj = json_tokener_parse_verbose(line, &error);
	if (is_error(jobj)) {
		err("json_tokener_parse error: %s, \"%s\"",
		    json_tokener_error_desc(error), line);
		return -1;
	}

	pthread_mutex_lock(&_mutex);
	update_db(jobj);
	json_object_put(jobj); /* release ref count */
	pthread_mutex_unlock(&_mutex);
	return 0;
}

/*
  Dispatch new commands as as received by config_cmd. Also updates
  internal data representation.
 */
void send_cmds(uint64_t *msg_seq)
{
	pthread_mutex_lock(&_mutex);
	zlist_t *coll = get_cmd_coll();
	if (!coll) {
		pthread_mutex_unlock(&_mutex);
		return;
	}

	command_node_t *cmd;
	while ( (cmd = zlist_pop(coll)) ) {
		/* suppress cmd if intf doesn't exist
		 * and isn't a deletion command
		 */
		if (cmd->_ephemeral == NULL &&
		    suppress_intf_cmd(cmd->_node->_interface)) {
			free(cmd);
			continue;
		}

		if (publish_config_cmd(cmd, msg_seq) != 0)
			err("error sending commands to dataplane");

		free(cmd);
	}
	reset_cmd_coll();
	pthread_mutex_unlock(&_mutex);
}

/*
  Dispatch commands with the interface name hint. Will be
  invoked on NEWLINK netlink event.
 */
void send_intf_cmds(const char *ifname, uint64_t *msg_seq)
{
	if (!ifname)
		return;

	zlist_t *coll = get_resync_coll();
	if (coll) {
		command_node_t *c;
		for (c = zlist_first(coll); c; c = zlist_next(coll))
			/* only pub commands for iface */
			if ((c->_node->_interface != NULL) &&
			    streq(ifname, c->_node->_interface))
				if (publish_config_cmd(c, msg_seq) != 0)
					err("send interface command error");
	}
}

/*
   Send single configuration command during resync
   operation.
*/
static int publish_resync_cmd(void *s, void *morestuff)
{
	command_node_t *cmd = (command_node_t *) s;
	if (cmd == NULL || cmd->_node == NULL || morestuff == NULL)
		return -1;

	target_t *target = (target_t *) morestuff;

	if (zframe_send(&target->client, target->socket,
			ZFRAME_MORE + ZFRAME_REUSE)) {
		err("zframe_send failed: %s", strerror(errno));
		return -1;
	}

	if (cmd->_node->_bin) {
		int bin_len;
		char *line = strdup(cmd->_node->_value);
		if (!line)
			panic("Memory allocation failure copying cmd line");

		if (extract_protobuf((char **)&line, &bin_len) != 0) {
			err("Failure to publish binary");
			free(line);
			return -1;
		}

		dbg("send binary [%"PRIu64"] topic '%s', (%d)",
		    cmd->_node->_seq,
		    "protobuf", bin_len);

		if (zstr_sendm(target->socket, PROTOBUF_TOPIC)) {
			err("zstr_sendm failed: %s", strerror(errno));
			free(line);
			return -1;
		}

		/* FIXME racy on resync */
		if (seqno_sendm(target->socket, cmd->_node->_seq)) {
			err("seqno_sendm failed: %s", strerror(errno));
			free(line);
			return -1;
		}

		/* just create a frame and send.. */
		zframe_t *frame = zframe_new(line, bin_len);
		if (zframe_send(&frame, target->socket, 0)) {
			err("zframe_send failed: %s", strerror(errno));
			zframe_destroy(&frame);
			free(line);
			return -1;
		}
		free(line);
		zframe_destroy(&frame);
	} else {
		dbg("send [%"PRIu64"] cmd '%s' '%s'", cmd->_node->_seq,
		    cmd->_node->_topic, cmd->_node->_value);

		if (zstr_sendm(target->socket, cmd->_node->_topic)) {
			err("zstr_sendm failed: %s", strerror(errno));
			return -1;
		}

		/* FIXME racy on resync */
		if (seqno_sendm(target->socket, cmd->_node->_seq)) {
			err("seqno_sendm failed: %s", strerror(errno));
			return -1;
		}

		if (zstr_send(target->socket, cmd->_node->_value)) {
			err("zstr_send failed: %s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

/*
   Resync all configuration commands to requesting
   dataplane.
*/
void config_send(zsock_t *socket, zframe_t * to)
{
	target_t t = { socket, to };
	target_t *target = &t;

	pthread_mutex_lock(&_mutex);
	zlist_t *coll = get_resync_coll();
	if (coll) {
		command_node_t *c;
		for (c = zlist_first(coll); c; c = zlist_next(coll))
			if (!suppress_intf_cmd(c->_node->_interface))
				publish_resync_cmd(c, target);
	}
	pthread_mutex_unlock(&_mutex);
}
