/**
 *  Header supporting mostly interface between the generic configuration 
 *  store and the rest of the controller. The external requirements
 *  are to interpret single commands and to provide a snapshot
 *  of all commands during a resync request.
 *
 * Copyright (c) 2019-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 **/
#ifndef __CONFIGSTORE_H__
#define __CONFIGSTORE_H__

int config_cmd(const char *line);
void send_cmds(uint64_t *msg_seq);
void send_intf_cmds(const char *ifname, uint64_t *msg_seq);
void config_send(zsock_t *socket, zframe_t * to, bool send_db_key);

#endif /* __CONFIGSTORE_H__ */
