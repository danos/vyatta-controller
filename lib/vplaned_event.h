/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for the controller (vplaned).
 */
#if !defined(__vplaned_event_h__)
#define __vplaned_event_h__

/*
 * Create a subscriber connected to the controller daemon's event
 * publisher and subscribe to the given topic.
 */
extern zsock_t *
vplaned_event_subscribe(const char *topic);

/*
 * Disconnect & destroy the connection to the controller daemon.
 */
extern void
vplaned_event_disconnect(zsock_t **sock);
#endif
