/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for the controller (vplaned). Similar to the
 * Vyatta::VPlaned.pm (and vyatta.vplaned.py), the API's allow an
 * application to inject configuration objects into the Controller
 * cstore database.
 *
 * The module provides both blocking and non-blocking functions. A
 * typical blocking call pattern might be:
 *
 *     err = vplaned_cstore_store(
 *               "security firewall name test1 default-action",
 *               "npf-cfg add fw:test1 10000 action=accept",
 *               NULL, "SET",
 *               TIMEOUT);
 *
 * a non-blocking call pattern might be:
 *
 *     s = vplaned_cstore_connect();
 *     err = vplaned_cstore_request(
 *               s,
 *               "security firewall name test1 default-action",
 *               "npf-cfg add fw:test1 10000 action=accept",
 *               NULL, "SET");
 *
 *      <use zpoller or zloop to wait for response>
 *
 *      err = vplaned_cstore_response(s, 0);
 *      vplaned_cstore_disconnect(&s);
 *
 */
#if !defined(__vplaned_cstore_h__)
#define __vplaned_cstore_h__

/*
 * DO NOT USE: testing only
 */
extern zsock_t *
__vplaned_cstore_connect(const char *path);
extern int
__vplaned_cstore_store(const char *path, const char *cmd, const char *interface,
		       const char *action, int timeout, const char *spath);

/*
 * Connect to the controller daemon (vplaned)
 */
extern zsock_t *
vplaned_cstore_connect(void);

/*
 * Disconnect & destroy the connection to the controller daemon.
 */
extern void
vplaned_cstore_disconnect(zsock_t **sock);

/*
 * Pass a command object to the cstore subsystem inside vplaned
 *
 * sock - ZMQ connection to the controller
 * path - Path to stored object (the "key")
 * cmd  - Configuration string to be stored with "key" (the "value")
 * interface - Optional interface name used to augment the "key", if
 *             absent, "ALL" is used.
 * action - How the "key"/"value" pair is to be processed: "SET" or "DELETE"
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_cstore_request(zsock_t *sock, const char *path, const char *cmd,
		       const char *interface, const char *action);

/*
 * Retrieve the result of the previous cstore request from the controller.
 *
 * sock - ZMQ connection to the controller
 * timeout - How long to block waiting for the response from the
 *           controller (millseconds). A value of 0 indicates an
 *           indefinite wait
 *
 * Returns 0 on success and a negative (< 0) errno value on failure
 */
extern int
vplaned_cstore_response(zsock_t *sock, int timeout);

/*
 * Pass a command object to the cstore subsystem and wait for the
 * response, i.e. a synchronous wrapper around
 * vplaned_cstore_connect(), vplaned_cstore_request() &
 * vplaned_cstore_response(), vplaned_cstore_disconnect().
 *
 * path - Path to stored object (the "key")
 * cmd  - Configuration string to be stored with "key" (the "value")
 * interface - Optional interface name used to augment the "key", if
 *             absent, "ALL" is used.
 * action - How the "key"/"value" pair is to be processed: "SET" or "DELETE"
 * timeout - How long to block waiting for the response from the
 *           controller (millseconds). A value of 0 indicates an
 *           indefinite wait
 *
 */
extern int
vplaned_cstore_store(const char *path, const char *cmd, const char *interface,
		     const char *action, int timeout);

#endif
