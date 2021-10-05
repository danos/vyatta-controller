/**
 *  Supports operations on the configuration store system. Updates, retrievals,
 *  ordering of commands.
 *
 * Copyright (c) 2018-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 **/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <linkhash.h>
#include <czmq.h>
#include "bstr.h"
#include "controller.h"
#include "configdb.h"
#include "configcmd.h"

/* Global *temporary* containers */
static zlist_t *_root_cmd_coll;	/* new cmds to dispatch */

/*
   Cache is kept until next conf command. In
   which case this is flushed. Handles case
   where multiple dataplanes restart--this only
   costs a single global tree walk in this case.
*/
static zlist_t *_root_resync_coll;	/* cache of resync commands */

/* Global active interface collection */
static zhash_t *_intf_coll;

/*
 *  Helper function for active interface collection
 */
zhash_t*
get_intf_coll(void)
{
	if (!_intf_coll) {
		_intf_coll = zhash_new();
		zhash_autofree(_intf_coll);
	}
	return _intf_coll;
}

bool
insert_intf_coll(const char *name)
{
	if (!name)
		return false;

	zhash_t *coll = get_intf_coll();

	return zhash_insert(coll, (char *)name, (void *)name) == 0;
}

void
delete_intf_coll(const char *name)
{
	if (!name)
		return;

	zhash_t *coll = get_intf_coll();

	zhash_delete(coll, name);
}

bool
suppress_intf_cmd(const char *iface)
{
	if (!iface)
		return false;

	zhash_t *coll = get_intf_coll();
	if (strcasecmp(iface, "ALL") &&
	    !zhash_lookup(coll, iface))
		return true;
	return false;
}

/*
  Helper functions below for configstore interface
 */
zlist_t *get_cmd_coll(void)
{
	return _root_cmd_coll;
}

void reset_cmd_coll(void)
{
	zlist_destroy(&_root_cmd_coll);
	_root_cmd_coll = NULL;
}

int publish_config_cmd(command_node_t *cmd, uint64_t *msg_seq)
{
	if (cmd == NULL || cmd->_node == NULL)
		return -1;

	if (cmd->_node->_topic != NULL) {
		if (cmd->_ephemeral != NULL) {
			publish_cmd(cmd->_node->_topic, ++(*msg_seq),
				    cmd->_ephemeral, cmd->_node->_bin);
			free(cmd->_ephemeral);
		} else {
			publish_cmd(cmd->_node->_topic, ++(*msg_seq),
				    cmd->_node->_value, cmd->_node->_bin);
		}
	}
	cmd->_node->_seq = *msg_seq;	/* save sequence number for resyncing */
	return 0;
}

/*
  Add received command to processing list.
 */
void add_cmd(config_node_t *config_node, const char *ephemeral)
{
	command_node_t *cmd = malloc(sizeof(command_node_t));

	if (cmd == NULL) {
		err("failure to allocate memory");
		return;
	}
	cmd->_node = config_node;

	if (ephemeral == NULL)
		cmd->_ephemeral = NULL;
	else
		cmd->_ephemeral = strdup(ephemeral);

	if (!_root_cmd_coll)
		_root_cmd_coll = zlist_new();

	zlist_append(_root_cmd_coll, (void *)cmd);
}

/*
  Build up resync command list from configuration tree.
 */
static void walk_db(struct lh_table *db, zlist_t **coll, struct bstr *db_key)
{
	struct lh_entry *e;
	int curr_len = db_key->len;

	if (db == NULL)
		return;

	lh_foreach(db, e) {
		config_node_t *config_node = (config_node_t *) e->v;

		if (config_node->_value == NULL) {
			bstr_addf(db_key, "%s ", (char *)e->k);
		} else {
			command_node_t *cmd = malloc(sizeof(command_node_t));
			if (cmd == NULL) {
				err("failure to allocate memory");
				return;
			}
			cmd->_node = config_node;
			cmd->_ephemeral = NULL;
			cmd->_db_key = strdup((char *)db_key->buf);
			if (cmd->_db_key == NULL) {
				err("failure to allocate memory for db key");
				free(cmd);
				return;
			}

			/*
			 * Handles required sorting of sequence
			 * value. Needed since configuration data
			 * arrives in expected replay order.
			 *
			 * Sorting below is inefficient.
			 * TODO: Needs to be updated with a single
			 * post sorting operation.
			 */
			if (*coll == NULL)
				*coll = zlist_new();

			zlist_append(*coll, (void *)cmd);
		}
		walk_db(config_node->_hash, coll, db_key);

		/* remove names added by lower nodes from the key */
		bstr_setlen(db_key, curr_len);
	}
}

static int resync_comp(void *item1, void *item2)
{
	if (((command_node_t *) item1)->_node->_seq == -1ULL)
		return -1;

	return ((command_node_t *) item1)->_node->_seq >
		((command_node_t *) item2)->_node->_seq;
}

zlist_t *get_resync_coll(void)
{
	if (!_root_resync_coll) {
		struct bstr db_key;

		bstr_init(&db_key, 128 /* initial length */);

		/* rebuild resync */
		walk_db(get_config_coll(), &_root_resync_coll, &db_key);
		if (_root_resync_coll)
			zlist_sort(_root_resync_coll, resync_comp);

		bstr_release(&db_key);
	}

	return _root_resync_coll;
}

void flush_resync(void)
{
	command_node_t *n;

	if (!_root_resync_coll)
		return;

	while ((n = (command_node_t *) zlist_pop(_root_resync_coll))) {
		free(n->_db_key);
		free(n);	/* ephemeral should be null on resync */
	}

	zlist_destroy(&_root_resync_coll);
	_root_resync_coll = NULL;
}
