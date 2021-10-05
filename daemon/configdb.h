/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2013-2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef __CONFIGDB_H__
#define __CONFIGDB_H__

typedef struct {
	lh_table      *_hash;
	char	      *_value;
	char	      *_topic;
	char	      *_interface;
	bool          _bin;
	uint64_t      _seq;
} config_node_t;


/* TODO roll LL and command_node_t into one w/ quicksort */
typedef struct {
	/* ACTION=DELETE, removed after publishing */
	char	        *_ephemeral;
	config_node_t	*_node;
	char		*_db_key;
} command_node_t;

/* Function decls */
void update_db(json_object *);
void add_cmd(config_node_t *, const char *);
void flush_resync(void);
lh_table *get_config_coll(void);
void config_coll_destroy(void);

#endif /* __CONFIGDB_H__ */
