/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * External API's for vplaned cstore database.
 */

#include <b64/cencode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <czmq.h>
#include <json.h>

#include "vplaned_cstore.h"

#include "DataplaneEnvelope.pb-c.h"
#include "VPlanedEnvelope.pb-c.h"

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
	bool protobuf;
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
	json_object *protobufstr = NULL;

	if ((cmdstr != NULL) && (intfstr != NULL)) {
		char actbuf[64];

		snprintf(actbuf, sizeof(actbuf), "__%s__", args->action);
		json_object_object_add(parent, actbuf, cmdstr);
		json_object_object_add(parent, "__INTERFACE__", intfstr);
		if (args->protobuf) {
			protobufstr = json_object_new_boolean(args->protobuf);
			if (protobufstr)
				json_object_object_add(parent, "__PROTOBUF__",
						       protobufstr);
		}
		return parent;
	}

	json_object_put(parent);
	json_object_put(cmdstr);
	json_object_put(intfstr);
	return NULL;
}

static int
vplaned_cstore_request_internal(zsock_t *sock, const char *path,
				const char *cmd, const char *interface,
				const char *action, bool protobuf)
{
	struct cstore_args args;

	if ((sock == NULL) ||
	    (path == NULL) ||
	    (cmd == NULL) ||
	    (action == NULL))
		return -EINVAL;

	args.cmd = cmd;
	args.action = action;
	args.protobuf = protobuf;
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

/*
 * Build up pb json cstore message. It is of the form:
 *
 * { "__<action>__"  : "protobuf <base64_encoded_msg>",
 *   "__PROTOBUF__"  : true,
 *   "__INTERFACE__" : <interface name | ALL>
 * }
 *
 * The base64_encoded message is formed by doing the following:
 * - wrap the given cmd in the DataplaneEnvelope protobuf
 * - then wrap that in the VPlanedEnvelope
 * - then base64 encode the result.
 */
int
vplaned_cstore_pb_request(zsock_t *sock, const char *path, void *cmd,
			  int cmd_len,
			  const char *cmd_name,
			  const char *interface, const char *action)
{
	DataplaneEnvelope dp_msg = DATAPLANE_ENVELOPE__INIT;
	VPlanedEnvelope vplaned_msg = VPLANED_ENVELOPE__INIT;
	int dp_len;
	void *dp_buf;
	int vplaned_len;
	void *vplaned_buf;
	base64_encodestate encode_state;
	char *base64_outbuf;
	char *base64_outbuf_ptr;
	int count;
	char *pb_str = "protobuf ";
	int extra_len = strlen(pb_str);

	if ((sock == NULL) ||
	    (path == NULL) ||
	    (cmd == NULL) ||
	    (cmd_name == NULL) ||
	    (action == NULL))
		return -EINVAL;

	if (strcmp(action, "SET") == 0)
		vplaned_msg.action = VPLANED_ENVELOPE__ACTION__SET;
	else if ( strcmp(action, "DELETE") == 0)
		vplaned_msg.action = VPLANED_ENVELOPE__ACTION__DELETE;
	else
		return -EINVAL;

	/*
	 * build the base64 encoded message, then call vplaned_store_request
	 * which will build the json.
	 */

	/* Build up dataplane envelope. */
	dp_msg.type = (char *)cmd_name;
	dp_msg.msg.data = cmd;
	dp_msg.msg.len = cmd_len;
	dp_len = dataplane_envelope__get_packed_size(&dp_msg);
	dp_buf = malloc(dp_len);
	if (!dp_buf)
		return -ENOMEM;
	dataplane_envelope__pack(&dp_msg, dp_buf);

	/* Build up vplaned envelope. */
	vplaned_msg.key = (char *)path;
	vplaned_msg.interface = (char *)interface;
	vplaned_msg.msg.data = dp_buf;
	vplaned_msg.msg.len = dp_len;
	vplaned_len = vplaned_envelope__get_packed_size(&vplaned_msg);
	vplaned_buf = malloc(vplaned_len);
	if (!vplaned_buf) {
		free(dp_buf);
		return -ENOMEM;
	}
	vplaned_envelope__pack(&vplaned_msg, vplaned_buf);
	free(dp_buf);

	/* Convert to base64 */

	/* More mem than needed but at least it is always enough  */
	base64_outbuf = calloc(1, vplaned_len * 2 + 1 + extra_len);
	if (!base64_outbuf) {
		free(vplaned_buf);
		return -ENOMEM;
	}

	/* Store 'protobuf ' at the start of the string. */
	snprintf(base64_outbuf, extra_len + 1, "%s", pb_str);
	base64_outbuf_ptr = base64_outbuf + extra_len;

	/* And then store the base64 encoded message */
	base64_init_encodestate(&encode_state);
	count = base64_encode_block(vplaned_buf, vplaned_len, base64_outbuf_ptr,
				    &encode_state);
	base64_outbuf_ptr += count;
	count = base64_encode_blockend(base64_outbuf_ptr, &encode_state);
	base64_outbuf_ptr += count;
	*base64_outbuf_ptr = 0;

	return vplaned_cstore_request_internal(sock, path, base64_outbuf,
					       interface, action, true);
}

int
vplaned_cstore_request(zsock_t *sock, const char *path, const char *cmd,
		       const char *interface, const char *action)
{
	return vplaned_cstore_request_internal(sock, path, cmd,
					       interface, action, false);
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
