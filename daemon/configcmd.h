/**
 * Header supporting operations on the configuration store system. 
 * Updates, retrievals, ordering of commands.
 *
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017-2019 AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 **/
#ifndef __CONFIGCMD_H__
#define __CONFIGCMD_H__

/* Function decls */
zhash_t *get_intf_coll(void);
bool insert_intf_coll(const char *name);
void delete_intf_coll(const char *name);
bool suppress_intf_cmd(const char *iface);
zlist_t *get_cmd_coll(void);
void     reset_cmd_coll(void);
zlist_t *get_resync_coll(void);
int      publish_config_cmd(command_node_t *, uint64_t *);

#endif /* __CONFIGCMD_H__ */
