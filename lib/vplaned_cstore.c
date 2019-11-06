/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for vplaned cstore database.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <czmq.h>
#include <json.h>

#include "vplaned_cstore.h"

static const char *vplaned_cstore_path =
	"ipc:///var/run/vyatta/vplaned.socket";

zsock_t *
__vplaned_cstore_connect(const char *path)
{
	if (path == NULL)
		path = vplaned_cstore_path;

	if ((strncmp(path, "ipc://", 6) == 0) &&
	    (access(path + 6, W_OK|R_OK) < 0))
		return NULL;

	return zsock_new_req(path);
}

zsock_t *
vplaned_cstore_connect(void)
{
	return __vplaned_cstore_connect(NULL);
}

void
vplaned_cstore_disconnect(zsock_t **sock)
{
	zsock_destroy(sock);
}

struct cstore_args {
	char **markerstr;
	char *savestr;
	const char *cmd;
	const char *action;
	const char *interface;
};

static json_object *
vplaned_cstore_format(const char *token, const struct cstore_args *args)
{
	json_object *parent;

	parent = json_object_new_object();
	if (parent == NULL)
		return NULL;

	if (token != NULL) {
		json_object *child;

		child = vplaned_cstore_format(
			strtok_r(NULL, " ", args->markerstr),
			args);
		if (child != NULL)
			json_object_object_add(parent, token, child);
		else {
			json_object_put(parent);
			parent = NULL;
		}
		return parent;
	}

	json_object *cmdstr = json_object_new_string(args->cmd);
	json_object *intfstr = json_object_new_string(args->interface);

	if ((cmdstr != NULL) && (intfstr != NULL)) {
		char actbuf[64];

		snprintf(actbuf, sizeof(actbuf), "__%s__", args->action);
		json_object_object_add(parent, actbuf, cmdstr);
		json_object_object_add(parent, "__INTERFACE__", intfstr);
		return parent;
	}

	json_object_put(parent);
	json_object_put(cmdstr);
	json_object_put(intfstr);
	return NULL;
}

int
vplaned_cstore_request(zsock_t *sock, const char *path, const char *cmd,
		       const char *interface, const char *action)
{
	struct cstore_args args;

	if ((sock == NULL) ||
	    (path == NULL) ||
	    (cmd == NULL) ||
	    (action == NULL))
		return -EINVAL;

	args.cmd = cmd;
	args.action = action;
	if (interface == NULL)
		args.interface = "ALL";
	else
		args.interface = interface;

	args.savestr = NULL;
	args.markerstr = &args.savestr;

	char *key = strdup(path);
	json_object *jobj = NULL;

	if (key != NULL)
		jobj = vplaned_cstore_format(
			strtok_r(key, " ", args.markerstr),
			&args);

	free(key);
	if (jobj == NULL)
		return -ENOMEM;

	const char *str;
	int rc = 0;

	str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
	if (str == NULL)
		rc = -ENOMEM;

	if ((rc == 0) && (zstr_send(sock, str) < 0))
		rc = -EIO;

	json_object_put(jobj);
	return rc;
}

int
vplaned_cstore_response(zsock_t *sock, int timeout)
{
	zmsg_t *msg;
	char *sts;
	int rc = 0;

	if (sock == NULL)
		return -EINVAL;

	if (timeout > 0)
		zsock_set_rcvtimeo(sock, timeout*ZMQ_POLL_MSEC);

	msg = zmsg_recv(sock);
	if (msg == NULL)
		return -ENODATA;

	sts = zmsg_popstr(msg);
	if (sts == NULL)
		rc = -EBADMSG;

	if ((rc == 0) && (!streq(sts, "OK")))
		rc = -EPROTO;

	free(sts);
	zmsg_destroy(&msg);
	return rc;
}

int
__vplaned_cstore_store(const char *path, const char *cmd, const char *interface,
		       const char *action, int timeout, const char *spath)
{
	zsock_t *s;
	int rc;

	s = __vplaned_cstore_connect(spath);
	if (s == NULL)
		return -ENOENT;

	rc = vplaned_cstore_request(s, path, cmd, interface, action);
	if (rc == 0)
		rc = vplaned_cstore_response(s, timeout);

	vplaned_cstore_disconnect(&s);
	return rc;
}

int
vplaned_cstore_store(const char *path, const char *cmd, const char *interface,
		     const char *action, int timeout)
{
	return __vplaned_cstore_store(path, cmd, interface, action, timeout,
				      NULL);
}
