/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Controller vplane (dataplane) database and associated access API's.
 */
#if !defined(__vplane_h__)
#define __vplane_h__

#include <czmq.h>
#include "parser.h"

typedef struct vplane_ vplane_t;

/* Do we have any remote vplanes configured? */
bool vplane_remote(void);

/* Local vplane (co-located with controller)? */
bool vplane_is_local(const vplane_t *vp);

/* Is the vplane connected (and by implication authenticated)? */
bool vplane_is_connected(const vplane_t *vp);

/* Has the vplane configuration changed? */
bool vplane_is_update_needed(const vplane_t *vp);

int vplane_get_id(const vplane_t *vp);
const char *vplane_get_uuid(const vplane_t *vp);
const char *vplane_get_control(const vplane_t *vp);
zlist_t *vplane_get_upaddr_list(const vplane_t *vp);
zframe_t *vplane_get_envelope(const vplane_t *vp);

/*
 * Set (or update) the ZeroMQ URL used to retrieve operational data from
 * the dataplane.
 *
 *  0 - success
 * <0 - error
 */
int vplane_set_control(vplane_t *vp, const char *url);

/*
 * Locate a vplane instance using various "keys":
 *
 * o session - use the 0MQ message envelope to locate a connected vplane
 *
 * o UUID - use the UUID to locate a configured vplane
 *
 * o IPv4 - use the IPv4 control address to locate a configured vplane
 *
 * The latter is for backwards compatibility
 */
vplane_t *vplane_findbysession(zframe_t *envelope);
vplane_t *vplane_findbyuuid(const char *uuid);
const vplane_t *vplane_findbyid(int id);

/* Vplane walker function prototype */
typedef void vplane_iter_func_t(const vplane_t *vp, void *arg);

/*  Walker function for all vplanes */
void vplane_walk_all(vplane_iter_func_t func, void *arg);

/*
 * Obtain the name and index associated with an interface on a specific
 * vplane instance.
 */
const char *vplane_iface_get_ifname(const vplane_t *vp, uint32_t ifn);
uint32_t vplane_iface_get_ifindex(const vplane_t *vp, uint32_t ifn);

/* Storage for a file descriptor if the interface is remote */
int vplane_iface_get_fd(const vplane_t *vp, uint32_t ifn);
int vplane_iface_set_fd(const vplane_t *vp, uint32_t ifn, int fd);

/* Update the state of an interface on a specific vplane instance. */
int vplane_iface_set_state(const vplane_t *vp, uint32_t ifn,
			   uint32_t operstate);

/* Delete an interface from a specific vplane instance */
void vplane_iface_del(vplane_t *vp, uint32_t ifn);

/* Add an interface to a specific vplane instance. */
int vplane_iface_add(vplane_t *vp, uint32_t ifn, uint32_t ifindex,
		     const char *ifname);

void *vplane_iface_get_cookie(const vplane_t *vp, uint32_t ifn);
int vplane_iface_set_cookie(const vplane_t *vp, uint32_t ifn, void *cookie);

/*
 * Using the message envelope as the session key, mark a vplane as
 * connected.
 */
int vplane_local_connect(vplane_t *vp, zframe_t *envelope);

int vplane_connect(vplane_t *vp, zframe_t *envelope);

/* Clock tick - update (expire) the timer values for each vplane */
void vplane_tick(void);

/* Update the keepalive timer for the indicated vplane. */
void vplane_keepalive(vplane_t *vp, const char *request, uint32_t ifno);

/* Parse an individual vplane configuration attribute - name/value pair. */
parse_result_t vplane_cfg_set_attribute(int id, const char *name,
					const char *value);

/* Configuration mode */
void vplane_cfg_failed(void);
void vplane_cfg_end(void);
void vplane_cfg_begin(void);

/*
 * Create JSON string describing the vplane database
 */
int vplane_get_json_config(const char *topic, zmsg_t *msg, char **json);

/* Initialize the vplane module */
void vplane_setup(void);

/* Forcibly disconnect all vplane instances */
void vplane_disconnect_all(void);

/*
 * Cleanup the vplane module.
 */
void vplane_teardown(void);

/*
 * Test-only function used to set the vplane timeout in milliseconds in
 * order to keep the test times down to a reasonable level - 10ms vs
 * 10s.
 */
void vplane_test_set_timeout(int id, int ms);
#endif
