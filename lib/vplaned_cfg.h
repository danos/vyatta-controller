/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for the controller (vplaned). Similar to the
 * Vyatta::Dataplane.pm module, the functions allow a user to retrieve
 * configuration details about the controller together with details of
 * individual dataplane(s). Primarily the console (control) URL in order
 * to issue status/show commands.
 *
 * A typical blocking call pattern might be:
 *
 *    s = vplaned_connect();
 *    vplaned_request_dataplane(s);
 *    struct vplaned_dataplane *dp;
 *    vplaned_dp_get(sock, TIMEOUT, dpid, &dp);
 *    if (dp != NULL)
 *        url = strdup(vplaned_dp_console(dp));
 *    vplaned_dp_destroy(&dp);
 *    vplaned_disconnect(&sock);
 *
 *    <use "url" to issue console command to dataplane>
 *
 *    free(url);
 *
 * A typical non-blocking call pattern might be:
 *
 *    s = vplaned_connect();
 *    vplaned_request_dataplane(s);
 *
 *    <use zpoller or zloop to wait for response>
 *
 *    struct vplaned_dataplane *dp;
 *    vplaned_dp_get_first(s, 0, true, &dp);
 *
 *    if (dp != NULL)
 *        url = strdup(vplaned_dp_console(dp));
 *    vplaned_dp_destroy(&dp);
 *    vplaned_disconnect(&s);
 *
 *    <use "url" to issue console command to dataplane>
 *
 *    free(url);
 */
#if !defined(__vplaned_cfg_h__)
#define __vplaned_cfg_h__

/*
 * DO NOT USE: testing only
 */
extern zsock_t *
__vplaned_connect(const char *path);

/*
 * Connect to the controller daemon (vplaned)
 */
extern zsock_t *
vplaned_connect(void);

/*
 * Disconnect & destroy the connection to the controller daemon.
 */
extern void
vplaned_disconnect(zsock_t **sock);

/*
 * Request the JSON dataplane object from the controller - details of
 * every configured dataplane instance.
 *
 * sock - ZMQ connection to the controller
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_request_dataplane(zsock_t *sock);

/*
 * Request the JSON configuration object from the controller - details
 * of the controller configuration.
 *
 * sock - ZMQ connection to the controller
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_request_config(zsock_t *sock);

/*
 * Retrieve the previously requested (raw) JSON object from the
 * controller.
 *
 * sock - ZMQ connection to the controller
 *
 * timeout - ZMQ receive timeout value (millseconds), 0 => non-blocking
 *
 * json - Returned JSON string. Caller owns string, use free() when
 *        finished
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_response_get(zsock_t *sock, int timeout, char **json);

/*
 * Having previously issued a request for the controller configuration,
 * retrieve the ZeroMQ address of the publish or request sockets.
 *
 * sock - ZMQ connection to the controller
 *
 * timeout - ZMQ receive timeout value (millseconds), 0 => non-blocking
 *
 * Caller owns returned string, use free() when finished.
 */
extern char *
vplaned_ctrl_get_publish_url(zsock_t *sock, int timeout);
extern char *
vplaned_ctrl_get_request_url(zsock_t *sock, int timeout);

/*
 * Dataplane entry returned by the following vplane_dp_xxx()
 * functions. Use the accessor functions to derive details of the
 * element. Use vplane_dp_destroy() when finished with the object.
 */
struct vplaned_dataplane;

/*
 * Process the previous dataplane request and return the the dataplane
 * with the specified ID
 *
 * sock - ZMQ connection to the controller
 *
 * timeout - ZMQ receive timeout value (millseconds), 0 => non-blocking
 *
 * dpid - Dataplane ID
 *
 * dp - Returned dataplane object (or NULL if none found). Use
 *      vplane_dp_destroy() when finished.
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_dp_get(zsock_t *sock, int timeout, uint16_t dpid,
	       struct vplaned_dataplane **dp);

/*
 * Process the previous dataplane request and return the first (any)
 * dataplane element.
 *
 * sock - ZMQ connection to the controller
 *
 * timeout - ZMQ receive timeout value (millseconds), 0 => non-blocking
 *
 * connected - Only return a connected dataplane
 *
 * dp - Returned dataplane object (or NULL if none found). Use
 *      vplane_dp_destroy() when finished.
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_dp_get_first(zsock_t *sock, int timeout, bool connected,
		     struct vplaned_dataplane **dp);

/*
 * Process the previous dataplane request and return a list of all
 * dataplanes.
 *
 * sock - ZMQ connection to the controller
 *
 * timeout - ZMQ receive timeout value (millseconds), 0 => non-blocking
 *
 * connected - Only return a list of connected dataplanes
 *
 * list - List of dataplane objects, maybe empty if no dataplanes exist. Use
 *        vplane_dp_destroy() when finished.
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_dp_get_list(zsock_t *sock, int timeout, bool connected,
		    zlist_t *list);

/*
 * Accessor functions for an individual dataplane element
 */

extern bool
vplaned_dp_is_local(const struct vplaned_dataplane *dp);

extern bool
vplaned_dp_is_connected(const struct vplaned_dataplane *dp);

extern uint16_t
vplaned_dp_id(const struct vplaned_dataplane *dp);

extern const char *
vplaned_dp_console(const struct vplaned_dataplane *dp);

extern void
vplaned_dp_destroy(struct vplaned_dataplane **dp);

#endif
