/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for vplaned event publisher.
 */

#include <czmq.h>
#include "vplaned_event.h"

zsock_t *
vplaned_event_subscribe(const char *topic)
{
	const char *event_path = "ipc:///var/run/vyatta/vplaned-event.pub";

	if (access(event_path + 6, R_OK) < 0)
		return NULL;

	return zsock_new_sub(event_path, topic);
}

void
vplaned_event_disconnect(zsock_t **sock)
{
	zsock_destroy(sock);
}
