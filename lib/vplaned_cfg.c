/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for vplaned configuration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <czmq.h>
#include <json.h>

#include "vplaned_cfg.h"

static const char *vplaned_config_path =
	"ipc:///var/run/vyatta/vplaned-config.socket";

struct vplaned_dataplane {
	uint16_t id;                    /* Dataplane ID */
	bool connected;                 /* Connected (active) dataplane? */
	bool local;                     /* Local dataplane? */
	char url[0];                    /* ZMQ console address */
};

bool
vplaned_dp_is_local(const struct vplaned_dataplane *dp)
{
	return dp->local;
}

bool
vplaned_dp_is_connected(const struct vplaned_dataplane *dp)
{
	return dp->connected;
}

uint16_t
vplaned_dp_id(const struct vplaned_dataplane *dp)
{
	return dp->id;
}

const char *
vplaned_dp_console(const struct vplaned_dataplane *dp)
{
	return dp->url;
}

void
vplaned_dp_destroy(struct vplaned_dataplane **dp)
{
	free(*dp);
	*dp = NULL;
}

static void
parse_json_dataplane(const char *json, int dpid, bool only_connected,
		     bool first, zlist_t *list)
{
	json_object *jobj_root, *jobj_dataplanes, *jobj_dp, *jobj_id, *jobj_url,
		    *jobj;
	int index, count = 0;
	struct vplaned_dataplane *dp;

	if (!json)
		return;

	jobj_root = json_tokener_parse(json);
	if (!jobj_root)
		return;

	if (json_object_object_get_ex(jobj_root, "dataplanes",
				      &jobj_dataplanes) &&
	    json_object_is_type(jobj_dataplanes, json_type_array))
		count = json_object_array_length(jobj_dataplanes);

	for (index = 0; index < count; index++) {
		bool connected;

		jobj_dp = json_object_array_get_idx(jobj_dataplanes, index);

		if (!(json_object_object_get_ex(jobj_dp, "id", &jobj_id)
		      && json_object_is_type(jobj_id, json_type_int)))
			continue;

		if ((dpid >= 0) && (dpid != json_object_get_int(jobj_id)))
			continue;

		connected = json_object_object_get_ex(
			jobj_dp, "connected", &jobj) &&
			json_object_get_boolean(jobj);

		if (only_connected && !connected)
			continue;

		if (!(json_object_object_get_ex(jobj_dp, "control", &jobj_url)
		      && json_object_get_string_len(jobj_url)))
			continue;

		dp = malloc(sizeof(*dp) +
			    json_object_get_string_len(jobj_url) + 1);
		if (dp != NULL) {
			dp->id = json_object_get_int(jobj_id);
			dp->connected = connected;
			dp->local = json_object_object_get_ex(
				jobj_dp, "local", &jobj) &&
				json_object_get_boolean(jobj);
			strcpy(dp->url, json_object_get_string(jobj_url));
			zlist_append(list, dp);
			if (first || (dp->id == dpid))
				break;
		}
	}

	json_object_put(jobj_root);
}

static int
get_dataplane(const char *json, int dpid, bool connected, bool first,
	      struct vplaned_dataplane **dp)
{
	zlist_t *list = zlist_new();

	if (list == NULL)
		return -ENOMEM;

	parse_json_dataplane(json, dpid, connected, first, list);

	*dp = zlist_pop(list);
	zlist_destroy(&list);
	return 0;
}

int
vplaned_response_get(zsock_t *sock, int timeout, char **json)
{
	zmsg_t *msg;
	char *sts;
	int rc = 0;

	if ((sock == NULL) || (json == NULL))
		return -EINVAL;

	*json = NULL;

	if (timeout > 0)
		zsock_set_rcvtimeo(sock, timeout*ZMQ_POLL_MSEC);

	msg = zmsg_recv(sock);
	if (msg == NULL)
		return -ENODATA;

	sts = zmsg_popstr(msg);
	if (sts == NULL)
		rc = -EBADMSG;

	if ((rc == 0) && (!streq(sts, "OK")))
		rc = -EBADMSG;

	free(sts);
	if (rc == 0)
		*json = zmsg_popstr(msg);

	zmsg_destroy(&msg);
	return rc;
}

int
vplaned_dp_get(zsock_t *sock, int timeout, uint16_t dpid,
	       struct vplaned_dataplane **dp)
{
	char *json;
	int rc;

	if (dp == NULL)
		return -EINVAL;

	*dp = NULL;
	rc = vplaned_response_get(sock, timeout, &json);
	if (rc == 0) {
		rc = get_dataplane(json, dpid, false, false, dp);
		free(json);
	}
	return rc;
}

int
vplaned_dp_get_first(zsock_t *sock, int timeout, bool connected,
		     struct vplaned_dataplane **dp)
{
	char *json;
	int rc;

	if (dp == NULL)
		return -EINVAL;

	*dp = NULL;
	rc = vplaned_response_get(sock, timeout, &json);
	if (rc == 0) {
		rc = get_dataplane(json, -1, connected, true, dp);
		free(json);
	}
	return rc;
}

static int
compare_dpids(void *item1, void *item2)
{
	struct vplaned_dataplane *a = item1, *b = item2;

	if (a->id < b->id)
		return -1;

	if (a->id > b->id)
		return 1;

	return 0;
}

int
vplaned_dp_get_list(zsock_t *sock, int timeout, bool connected,
		    zlist_t *list)
{
	char *json;
	int rc;

	if (list == NULL)
		return -EINVAL;

	rc = vplaned_response_get(sock, timeout, &json);
	if (rc == 0) {
		parse_json_dataplane(json, -1, connected, false, list);
		zlist_sort(list, compare_dpids);
		free(json);
	}

	return rc;
}

static void
parse_json_controller(const char *json, char **pub, char **req)
{
	json_object *jobj_root, *jobj_c, *jobj;

	if (!json)
		return;

	jobj_root = json_tokener_parse(json);
	if (!jobj_root)
		return;

	if (!json_object_object_get_ex(jobj_root, "controller", &jobj_c))
		return;

	if ((pub != NULL) &&
	    json_object_object_get_ex(jobj_c, "publish_url", &jobj) &&
	    json_object_get_string_len(jobj))
		*pub = strdup(json_object_get_string(jobj));

	if ((req != NULL) &&
	    json_object_object_get_ex(jobj_c, "request_url", &jobj) &&
	    json_object_get_string_len(jobj))
		*req = strdup(json_object_get_string(jobj));

	json_object_put(jobj_root);
}

char *
vplaned_ctrl_get_publish_url(zsock_t *sock, int timeout)
{
	char *json;
	char *url = NULL;

	if (vplaned_response_get(sock, timeout, &json) == 0) {
		parse_json_controller(json, &url, NULL);
		free(json);
	}
	return url;
}

char *
vplaned_ctrl_get_request_url(zsock_t *sock, int timeout)
{
	char *json;
	char *url = NULL;

	if (vplaned_response_get(sock, timeout, &json) == 0) {
		parse_json_controller(json, NULL, &url);
		free(json);
	}
	return url;
}

static int
vplaned_request_object(zsock_t *sock, const char *obj)
{
	if (sock == NULL)
		return -EINVAL;

	if (zstr_send(sock, obj) < 0)
		return -errno;
	return 0;
}

int
vplaned_request_dataplane(zsock_t *sock)
{
	return vplaned_request_object(sock, "GETVPCONFIG");
}

int
vplaned_request_config(zsock_t *sock)
{
	return vplaned_request_object(sock, "GETCONFIG");
}

void
vplaned_disconnect(zsock_t **sock)
{
	zsock_destroy(sock);
}

zsock_t *
__vplaned_connect(const char *path)
{
	/*
	 * Allow test code to specify the IPC socket path
	 */
	if (path == NULL)
		path = vplaned_config_path;

	if ((strncmp(path, "ipc://", 6) == 0) &&
	    (access(path + 6, W_OK|R_OK) < 0))
		return NULL;

	return zsock_new_req(path);
}

zsock_t *
vplaned_connect(void)
{
	return __vplaned_connect(NULL);
}
