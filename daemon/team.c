/*
 * Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <linux/genetlink.h>
#include <linux/if_team.h>
#include <syslog.h>
#include <czmq.h>
#include <libmnl/libmnl.h>

#include "controller.h"
#include "team.h"

static struct nlmsghdr *team_nlmsg(struct team_msg_desc *desc,
				    uint16_t attrtype,
				    const struct nlattr *attr)
{
	struct nlmsghdr *nlh = malloc(MNL_SOCKET_BUFFER_SIZE);

	if  (!nlh)
		return  NULL;

	mnl_nlmsg_put_header(nlh);
	nlh->nlmsg_type = desc->orighdr.nlmsg_type;
	nlh->nlmsg_flags = desc->orighdr.nlmsg_flags;
	nlh->nlmsg_seq = desc->orighdr.nlmsg_seq;
	nlh->nlmsg_pid = desc->orighdr.nlmsg_pid;

	struct genlmsghdr *ghdr = mnl_nlmsg_put_extra_header(nlh, GENL_HDRLEN);
	ghdr->cmd = desc->cmd;
	ghdr->version = TEAM_GENL_VERSION;
	ghdr->reserved = 0;

	mnl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, desc->ifindex);
	mnl_attr_put(nlh, attrtype, mnl_attr_get_len(attr), attr);

	return nlh;
}

static int team_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, TEAM_ATTR_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int team_attr_option(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, TEAM_ATTR_OPTION_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int team_attr_port(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, TEAM_ATTR_PORT_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static void team_port(struct nlattr **attrs, void *data)
{
	struct team_port_info *info = data;

	if (attrs[TEAM_ATTR_PORT_IFINDEX])
		info->port_ifindex =
		    mnl_attr_get_u32(attrs[TEAM_ATTR_PORT_IFINDEX]);

	if (attrs[TEAM_ATTR_PORT_CHANGED])
		info->changed = 1;

	if (attrs[TEAM_ATTR_PORT_LINKUP])
		info->linkup = 1;

	if (attrs[TEAM_ATTR_PORT_REMOVED])
		info->removed = 1;

	if (attrs[TEAM_ATTR_PORT_SPEED])
		info->speed = mnl_attr_get_u32(attrs[TEAM_ATTR_PORT_SPEED]);

	if (attrs[TEAM_ATTR_PORT_DUPLEX])
		info->duplex = mnl_attr_get_u8(attrs[TEAM_ATTR_PORT_DUPLEX]);
}

static int team_port_topic(uint32_t ifindex, struct team_port_info *info)
{
	int rv;
	char **str = &info->topic;

	rv = asprintf(str, "team %u port %d", ifindex,
		      info->port_ifindex);
	if (rv < 0)
		return rv;
	return 0;
}

static void team_option_data_free(void *arg)
{
	struct team_option_info *info = arg;

	if ((info->type == MNL_TYPE_STRING || info->type == MNL_TYPE_BINARY)
	    && info->data.binary)
		free(info->data.binary);

	free(info->topic);
	free(info->nlh);
}

static void team_port_data_free(void *arg)
{
	struct team_port_info *info = arg;

	free(info->topic);
	free(info->nlh);
}

void team_msg_data_free(struct team_msg_desc *desc)
{
	if (desc->infolist == NULL)
		return;

	zlist_destroy(&desc->infolist);
}

static void team_option(struct nlattr **attrs, void *data)
{
	struct team_option_info *info = data;

	if (attrs[TEAM_ATTR_OPTION_NAME])
		strncpy(info->name,
			mnl_attr_get_str(attrs[TEAM_ATTR_OPTION_NAME]),
			sizeof(info->name));

	if (attrs[TEAM_ATTR_OPTION_CHANGED])
		info->changed = 1;

	if (attrs[TEAM_ATTR_OPTION_TYPE])
		info->type = mnl_attr_get_u8(attrs[TEAM_ATTR_OPTION_TYPE]);

	if (attrs[TEAM_ATTR_OPTION_DATA]) {
		struct nlattr *attr = attrs[TEAM_ATTR_OPTION_DATA];

		switch (info->type) {
		case MNL_TYPE_UNSPEC:
		case MNL_TYPE_U16:
		case MNL_TYPE_U64:
		case MNL_TYPE_MSECS:
		case MNL_TYPE_NESTED:
		case MNL_TYPE_NESTED_COMPAT:
		case MNL_TYPE_NUL_STRING:
			break;

		case MNL_TYPE_U8:
			info->data.u8 = mnl_attr_get_u8(attr);
			break;
		case MNL_TYPE_U32:
		case MNL_TYPE_FLAG:
			info->data.u32 = mnl_attr_get_u32(attr);
			break;
		case MNL_TYPE_STRING:
			info->data.str = strdup(mnl_attr_get_str(attr));
			break;
		case MNL_TYPE_BINARY:
			info->payload_len = mnl_attr_get_payload_len(attr);
			info->data.binary = malloc(info->payload_len);
			if (info->data.binary == NULL)
				break;

			memcpy(info->data.binary,
			       mnl_attr_get_payload(attr), info->payload_len);
			break;

		default:
			/* catch signed 32-bit ints here.  There is no
			 * MNL_TYPE_ defined for this.
			 */
			info->data.u32 = mnl_attr_get_u32(attr);
		}
	}

	if (attrs[TEAM_ATTR_OPTION_REMOVED])
		info->removed = 1;

	if (attrs[TEAM_ATTR_OPTION_PORT_IFINDEX])
		info->port_ifindex =
		    mnl_attr_get_u32(attrs[TEAM_ATTR_OPTION_PORT_IFINDEX]);

	if (attrs[TEAM_ATTR_OPTION_ARRAY_INDEX])
		info->array_index =
		    mnl_attr_get_u32(attrs[TEAM_ATTR_OPTION_ARRAY_INDEX]);
}

static int team_option_topic(uint32_t ifindex,
			     struct team_option_info *info)
{
	int rv;
	char **str = &info->topic;

	if (!strcmp(info->name, "enabled"))
		rv = asprintf(str, "team %u select %d",
			      ifindex,
			      info->port_ifindex);
	else if (!strcmp(info->name, "mode"))
		rv = asprintf(str, "team %u mode", ifindex);
	else if (!strcmp(info->name, "bpf_hash_func"))
		rv = asprintf(str, "team %u hash", ifindex);
	else if (!strcmp(info->name, "activeport"))
		rv = asprintf(str, "team %u activeport", ifindex);
	else
		return -1;

	if (rv < 0)
		return rv;
	return 0;
}

static int team_option_list(const struct nlattr *attr, void *data)
{
	const struct nlattr *cur;
	struct team_msg_desc *desc = data;
	struct team_option_info info = { .nlh = NULL,};

	mnl_attr_for_each_nested(cur, attr) {
		struct nlattr *tb[TEAM_ATTR_OPTION_MAX + 1] = { NULL, };

		team_attr_option(cur, tb);
		team_option(tb, &info);
	}

	if (debug > 1 && (info.name[0] != '\0'))
		info("found team option %s", info.name);

	team_option_topic(desc->ifindex, &info);
	if (!info.topic)
		return MNL_CB_OK;

	info.nlh = team_nlmsg(desc, TEAM_ATTR_LIST_OPTION, attr);
	if (!info.nlh) {
		notice("cannot allocate memory for netlink message");
		goto error;
	}

	struct team_option_info *copy = malloc(sizeof(*copy));
	if (copy == NULL) {
		notice("cannot allocate memory for team option");
		goto error;
	}

	memcpy(copy, &info, sizeof(info));
	if (zlist_append(desc->infolist, copy) < 0) {
		notice("cannot add team option to list");
		free(copy);
		goto error;
	}

	zlist_freefn(desc->infolist, copy, team_option_data_free, true);

	return MNL_CB_OK;

error:
	free(info.nlh);
	return MNL_CB_ERROR;
}

static int team_port_list(const struct nlattr *attr, void *data)
{
	const struct nlattr *cur;
	struct team_msg_desc *desc = data;
	struct team_port_info info = { .nlh = NULL,};
	struct team_port_info *copy = NULL;

	mnl_attr_for_each_nested(cur, attr) {
		struct nlattr *tb[TEAM_ATTR_PORT_MAX + 1] = { NULL, };

		team_attr_port(cur, tb);
		team_port(tb, &info);
	}

	team_port_topic(desc->ifindex, &info);
	if (!info.topic)
		return MNL_CB_OK;

	info.nlh = team_nlmsg(desc, TEAM_ATTR_LIST_PORT, attr);
	if (!info.nlh) {
		notice("can't allocate netlink header");
		goto error;
	}


	copy = malloc(sizeof(*copy));
	if (copy == NULL) {
		notice("cannot allocate memory for team port info");
		goto error;
	}

	memcpy(copy, &info, sizeof(info));
	if (zlist_append(desc->infolist, copy) < 0) {
		notice("cannot add team port info to list");
		goto error;
	}

	zlist_freefn(desc->infolist, copy, team_port_data_free, true);

	return MNL_CB_OK;
error:
	free(info.nlh);
	free(copy);
	return MNL_CB_ERROR;
}

static int process_team_portlist(const struct nlmsghdr *nlh,
				 struct team_msg_desc *desc)
{
	struct nlattr *tb[TEAM_ATTR_MAX + 1] = {NULL, };

	mnl_attr_parse(nlh, GENL_HDRLEN, team_attr, tb);
	if (!tb[TEAM_ATTR_LIST_PORT]) {
		info("Not a team portlist?");
		return MNL_CB_OK;
	}

	if (tb[TEAM_ATTR_TEAM_IFINDEX])
		desc->ifindex = mnl_attr_get_u32(tb[TEAM_ATTR_TEAM_IFINDEX]);

	/* ignore messages that don't have an interface index or that
	 * set it to zero
	 */
	if (desc->ifindex == 0)
		return MNL_CB_OK;

	return mnl_attr_parse_nested(tb[TEAM_ATTR_LIST_PORT],
				     team_port_list, desc);
}

static int process_team_optionlist(const struct nlmsghdr *nlh,
				   struct team_msg_desc *desc)
{
	struct nlattr *tb[TEAM_ATTR_MAX + 1] = {NULL, };

	mnl_attr_parse(nlh, GENL_HDRLEN, team_attr, tb);
	if (!tb[TEAM_ATTR_LIST_OPTION]) {
		info("Not a team options list?");
		return MNL_CB_OK;
	}

	if (tb[TEAM_ATTR_TEAM_IFINDEX])
		desc->ifindex = mnl_attr_get_u32(tb[TEAM_ATTR_TEAM_IFINDEX]);

	/* ignore messages that don't have an interface index or that
	 * set it to zero
	 */
	if (desc->ifindex == 0)
		return MNL_CB_OK;

	return mnl_attr_parse_nested(tb[TEAM_ATTR_LIST_OPTION],
				     team_option_list, desc);
}

int process_genetlink_teamcmd(const struct nlmsghdr *nlh,
			      struct team_msg_desc *desc)
{
	struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);
	int ret = MNL_CB_ERROR;

	desc->cmd = genlhdr->cmd;
	desc->orighdr = *nlh;
	desc->infolist = zlist_new();

	switch (genlhdr->cmd) {
	case TEAM_CMD_OPTIONS_SET:
		ret = MNL_CB_OK;
		break;
	case TEAM_CMD_OPTIONS_GET:
		return process_team_optionlist(nlh, desc);
		break;
	case TEAM_CMD_PORT_LIST_GET:
		return process_team_portlist(nlh, desc);
		break;
	default:
		info("unknown team message %d", genlhdr->cmd);
		break;
	}
	return ret;
}

static int team_query(struct mnl_socket *s, int family_id, uint8_t cmd,
		      unsigned long ifindex, unsigned int dump_seq)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct genlmsghdr *ghdr =
		mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));

	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = dump_seq;
	mnl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, ifindex);
	ghdr->cmd = cmd;
	ghdr->version = TEAM_GENL_VERSION;

	return mnl_socket_sendto(s, nlh, nlh->nlmsg_len);
}

int team_query_portlist(struct mnl_socket *s, int family_id,
			unsigned long ifindex, unsigned int dump_seq)
{
	return team_query(s, family_id, TEAM_CMD_PORT_LIST_GET,
			  ifindex, dump_seq);
}

int team_query_options(struct mnl_socket *s, int family_id,
		       unsigned long ifindex, unsigned int dump_seq)
{
	return team_query(s, family_id, TEAM_CMD_OPTIONS_GET,
			  ifindex, dump_seq);
}
