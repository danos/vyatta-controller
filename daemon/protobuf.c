/*
 * protobuf.c
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <czmq.h>
#include <b64/cdecode.h>
#include "VPlanedEnvelope.pb-c.h"
#include "protobuf.h"
#include "controller.h"

/*
 * extract_protobuf() overwrites *cmd with the decoded base64
 * and vplane stripped binary representation. The length of
 * this will be less than the cmd_len of the passed in format.
 * But if *cmd is to be used in an un-modified representation
 * a copy must be passed in (see bug 44870).
 */
int
extract_protobuf(char **cmd, int *cmd_len)
{
	size_t out_len;
	size_t msg_len = strlen(*cmd) - strlen(PROTOBUF_TOPIC) - 1;
	if ((int)msg_len < 1)
		return -1;

	/* first decode from base64 */
	char buf[msg_len];
	base64_decodestate state;
	base64_init_decodestate(&state);
	out_len = base64_decode_block(
			    (*cmd) + strlen(PROTOBUF_TOPIC) + 1,
			    msg_len,
			    buf,
			    &state);
	if (buf[0] == '\0' || out_len == 0) {
		err("failed to decode base64");
		return -1;
	}

	/* strip off vplaned envelope first */
	VPlanedEnvelope *vpd_msg;
	vpd_msg = vplaned_envelope__unpack(NULL,
					   out_len,
					   (const uint8_t *)buf);
	if (vpd_msg == NULL) {
		err("failed to unpack vplaned envelope");
		return -1;
	}

	*cmd_len = vpd_msg->msg.len;

	if (vpd_msg->msg.len > strlen(*cmd)) {
		err("error in decoding binary");
		return -1;
	}

	memcpy(*cmd,
	       vpd_msg->msg.data,
	       vpd_msg->msg.len);

	vplaned_envelope__free_unpacked(vpd_msg, NULL);
	return 0;
}

