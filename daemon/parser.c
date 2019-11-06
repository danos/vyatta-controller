/*
 * Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Configuration file (controller.conf) parser for controller.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>

#include <czmq.h>
#include <json.h>

#include <ini.h>

#include "controller.h"
#include "parser.h"
#include "vplane.h"

#define DEFAULT_TIMEOUT (24*60*60)

#define DEFAULT_REQUEST_PORT    4415
#define DEFAULT_REQUEST_IPC     "ipc:///var/run/vyatta/vplaned.req"

struct ctrl_cfg {
	/*
	 * 0MQ sockets from controller to vplane(s)
	 */
	char *publish_url;
	char *request_url;
	/*
	 * Dead timer (seconds) for individual vplane(s)
	 */
	unsigned timeout;
	/*
	 * Controller endpoint address
	 */
	bool ctl_addr_valid;
	struct ip_addr  ctl_addr;
	/*
	 * 0MQ authentication
	 */
	bool auth_enabled;	/* true if authentication enabled */
	char *certificate;	/* Our certificate file name */
	char *auth_path;	/* Remote certificates path */
	/*
	 * Kernel routes
	 */
	bool use_kernel_routes; /* true if kernel routes should be used */
};

struct ctrl_state {
	/*
	 * 0MQ Bound URLs
	 */
	char *publish_url;
	char *request_url;
	/* Information programmed in vplaned via cfg socket */
	bool fab_encrypt;		/* Fabric Encryption */
	struct ip_addr fab_addr_v4;	/* ipv4 ctrl fabric address */
	struct ip_addr fab_addr_v6;	/* ipv6 ctrl fabric address */
};

static struct ctrl_cfg controller_cfg;
static struct ctrl_state controller_state;

const char *is_url_ipc(const char *url)
{
	if ((url != NULL) &&
	    (strncmp(url, "ipc://", 6) == 0))
		return url+6;

	return NULL;
}

/*
 * Before accepting the provided controller address, make sure its valid
 * by attempting to bind to that address.
 */
static bool
parser_address_check(void)
{
	char ep[PARSE_MAX_EP_LEN];
	char ip[INET6_ADDRSTRLEN];
	zsock_t *s;
	bool valid;

	if (controller_cfg.ctl_addr.af == AF_UNSPEC) {
		err("parser address check failed: no address defined");
		return false;
	}

	/*
	 * Ideally we'd use any request URL that has been included in
	 * the configuration, but that may already be in use. Instead
	 * generate a simple wildcard URL. This only checks the validity
	 * of the IP address rather than any IP+port combination.
	 */
	inet_ntop(controller_cfg.ctl_addr.af,
		  &controller_cfg.ctl_addr.ip, ip, sizeof(ip));
	snprintf(ep, sizeof(ep), "tcp://%s:*", ip);

	s = zsock_new_router(ep);
	valid = (s != NULL);
	zsock_destroy(&s);
	if (!valid)
		err("parser address check failed (%s): '%s'", ip,
		    strerror(errno));
	return valid;
}

/*
 * Allocate a default publisher endpoint string
 */
static char *
parser_default_endpoint_publish(void)
{
	if (controller_cfg.ctl_addr_valid && vplane_remote()) {
		char *ep = malloc(PARSE_MAX_EP_LEN);

		if (ep != NULL) {
			char ip[INET6_ADDRSTRLEN];

			inet_ntop(controller_cfg.ctl_addr.af,
				  &controller_cfg.ctl_addr.ip, ip, sizeof(ip));
			snprintf(ep, PARSE_MAX_EP_LEN, "tcp://%s:*", ip);
		}

		return ep;
	}

	return strdup("ipc://*");
}

/*
 * Allocate a default request endpoint string
 */
static char *
parser_default_endpoint_request(void)
{
	if (controller_cfg.ctl_addr_valid && vplane_remote()) {
		char *ep = malloc(PARSE_MAX_EP_LEN);

		if (ep != NULL) {
			char ip[INET6_ADDRSTRLEN];

			inet_ntop(controller_cfg.ctl_addr.af,
				  &controller_cfg.ctl_addr.ip, ip, sizeof(ip));
			snprintf(ep, PARSE_MAX_EP_LEN, "tcp://%s:%d",
				 ip, DEFAULT_REQUEST_PORT);
		}

		return ep;
	}

	return strdup(DEFAULT_REQUEST_IPC);
}

const char *
parser_endpoint_request(void)
{
	return controller_cfg.request_url;
}

const char *
parser_endpoint_publish(void)
{
	return controller_cfg.publish_url;
}

const char *
parser_endpoint_request_bound(void)
{
	return controller_state.request_url;
}

const char *
parser_endpoint_publish_bound(void)
{
	return controller_state.publish_url;
}

void
parser_set_endpoint_request_bound(char *url)
{
	free(controller_state.request_url);
	controller_state.request_url = url;
}

void
parser_set_endpoint_publish_bound(char *url)
{
	free(controller_state.publish_url);
	controller_state.publish_url = url;
}

void
parser_set_fabric_encrypt(bool encrypt)
{
	controller_state.fab_encrypt = encrypt;
}

void
parser_set_fabric_address(struct ip_addr *addr)
{
	if (addr->af == AF_INET) {
		controller_state.fab_addr_v4.af = AF_INET;
		controller_state.fab_addr_v4.ip.v4 = addr->ip.v4;
	} else {
		controller_state.fab_addr_v6.af = AF_INET6;
		controller_state.fab_addr_v6.ip.v6 = addr->ip.v6;
	}
}

void
parser_delete_fabric_address(struct ip_addr *addr)
{
	if ((addr->af == AF_INET) &&
	    (!addr_cmp(addr, &controller_state.fab_addr_v4))) {
		controller_state.fab_addr_v4.af = AF_UNSPEC;
		controller_state.fab_addr_v4.ip.v4.s_addr = 0;
	}
	if ((addr->af == AF_INET6) &&
	    (!addr_cmp(addr, &controller_state.fab_addr_v6))) {
		controller_state.fab_addr_v6.af = AF_UNSPEC;
		memset(&controller_state.fab_addr_v6.ip.v6, 0,
			       sizeof(struct in6_addr));
	}
}

const struct ip_addr *
parser_fabric_addr(sa_family_t af)
{
	if (af == AF_INET)
		if (controller_state.fab_addr_v4.af == AF_INET)
			return &controller_state.fab_addr_v4;
	if (af == AF_INET6)
		if (controller_state.fab_addr_v6.af == AF_INET6)
			return &controller_state.fab_addr_v6;
	return NULL;
}

sa_family_t
parser_local_af(void)
{
	return controller_cfg.ctl_addr.af;
}

/**
 * Get the controller local address
 */
const struct ip_addr *
parser_local_addr(void)
{
	return &controller_cfg.ctl_addr;
}

int
parser_controller_timeout(void)
{
	return controller_cfg.timeout;
}

bool
parser_authentication_enabled(void)
{
	return controller_cfg.auth_enabled;
}

bool
parser_fabric_encrypt_enabled(void)
{
	return controller_state.fab_encrypt;
}

const char *
parser_authentication_certificate(void)
{
	return controller_cfg.certificate;
}

const char *
parser_authentication_path(void)
{
	return controller_cfg.auth_path;
}

bool
parser_use_kernel_routes(void)
{
	return controller_cfg.use_kernel_routes;
}

/*
 * Create JSON string describing the config database
 */
int
parser_get_json_config(const char *topic __unused, zmsg_t *msg __unused,
		       char **json)
{
	char addr[INET6_ADDRSTRLEN];

	json_object *jobj = json_object_new_object();
	json_object *ctrl = json_object_new_object();

	if (controller_state.publish_url)
		json_object_object_add(ctrl, "publish_url",
			json_object_new_string(controller_state.publish_url));

	if (controller_state.request_url)
		json_object_object_add(ctrl, "request_url",
			json_object_new_string(controller_state.request_url));

	json_object_object_add(ctrl, "fab_encrypt",
			json_object_new_boolean(controller_state.fab_encrypt));

	if (controller_state.fab_addr_v4.af == AF_INET)
		json_object_object_add(ctrl, "fab_addr_v4",
			       json_object_new_string(
			       inet_ntop(controller_state.fab_addr_v4.af,
			       &controller_state.fab_addr_v4.ip,
			       addr, sizeof(addr))));
	else
		json_object_object_add(ctrl, "fab_addr_v4",
			       json_object_new_string(""));

	if (controller_state.fab_addr_v6.af == AF_INET6)
		json_object_object_add(ctrl, "fab_addr_v6",
			       json_object_new_string(
			       inet_ntop(controller_state.fab_addr_v6.af,
			       &controller_state.fab_addr_v6.ip,
			       addr, sizeof(addr))));
	else
		json_object_object_add(ctrl, "fab_addr_v6",
			       json_object_new_string(""));

	if (controller_cfg.publish_url)
		json_object_object_add(ctrl, "cfg_publish_url",
			json_object_new_string(controller_cfg.publish_url));

	if (controller_cfg.request_url)
		json_object_object_add(ctrl, "cfg_request_url",
			json_object_new_string(controller_cfg.request_url));

	json_object_object_add(ctrl, "timeout",
			json_object_new_int(controller_cfg.timeout));

	json_object_object_add(ctrl, "ctladdr_valid",
		       json_object_new_boolean(controller_cfg.ctl_addr_valid));
	json_object_object_add(ctrl, "ctladdr",
			json_object_new_string(
					inet_ntop(controller_cfg.ctl_addr.af,
						  &controller_cfg.ctl_addr.ip,
						  addr, sizeof(addr))));

	json_object_object_add(ctrl, "auth_enabled",
			json_object_new_boolean(controller_cfg.auth_enabled));

	if (controller_cfg.auth_enabled) {
		json_object_object_add(ctrl, "auth_certificate",
		json_object_new_string(controller_cfg.certificate));

		json_object_object_add(ctrl, "auth_path",
		json_object_new_string(controller_cfg.auth_path));
	}

	json_object_object_add(ctrl, "use_kernel_routes",
			json_object_new_boolean(controller_cfg.use_kernel_routes));

	json_object_object_add(jobj, "controller", ctrl);
	*json = strdup(json_object_to_json_string(jobj));

	/* Free JSON objects */
	json_object_put(jobj);

	return 0;
}

parse_result_t
parse_atoi(uint32_t *i, const char *value)
{
	char *endp = NULL;
	uint32_t result;

	*i = 0;
	errno = 0;
	result = strtoul(value, &endp, 10);
	if ((errno != 0) || (*endp != '\0')) {
		err("failed to parse integer value: %s", value);
		return PARSE_ERR;
	}

	*i = result;
	return PARSE_OK;
}


static parse_result_t
parse_copy_str(char **str_ref, const char *value)
{
	free(*str_ref);
	*str_ref = strdup(value);
	return PARSE_OK;
}

static bool
parse_ipaddr(sa_family_t af, const char *value, void *saddr)
{
	return 1 == inet_pton(af, value, saddr);
}

static parse_result_t
parse_address(struct ctrl_cfg *config, const char *value)
{
	if (parse_ipaddr(AF_INET, value, &config->ctl_addr.ip.v4)) {
		config->ctl_addr.af = AF_INET;
		return PARSE_OK;
	}

	if (parse_ipaddr(AF_INET6, value, &config->ctl_addr.ip.v6)) {
		config->ctl_addr.af = AF_INET6;
		return PARSE_OK;
	}

	err("failed to parse IP address: %s", value);
	return PARSE_ERR;
}

static parse_result_t
parse_section_controller(struct ctrl_cfg *config, const char *name,
			 const char *value)
{
	if (streq("publish", name))
		return parse_copy_str(&config->publish_url, value);

	if (streq("request", name))
		return parse_copy_str(&config->request_url, value);

	if (streq("ip", name))
		return parse_address(config, value);

	if (streq("certificate", name))
		return parse_copy_str(&config->certificate, value);

	if (streq("timeout", name)) {
		uint32_t to;

		if (parse_atoi(&to, value) != PARSE_OK)
			to = DEFAULT_TIMEOUT;
		config->timeout = to * 1000;
		return PARSE_OK;
	}

	if (streq("route-source", name)) {
		if (streq("kernel", value)) {
			config->use_kernel_routes = true;
			return PARSE_OK;
		}
		if (streq("rib", value)) {
			config->use_kernel_routes = false;
			return PARSE_OK;
		}
		err("unknown value for route_source: %s", value);
		return PARSE_ERR;
	}

	return PARSE_IGNORED;
}

static parse_result_t
parse_section_authentication(struct ctrl_cfg *config, const char *name,
			     const char *value)
{
	if (streq("method", name)) {
		if (streq("elliptic-curve", value)) {
			config->auth_enabled = true;
			return PARSE_OK;
		}
		if (streq("none", value)) {
			config->auth_enabled = false;
			return PARSE_OK;
		}
	} else if (streq("path", name))
		return parse_copy_str(&config->auth_path, value);

	return PARSE_IGNORED;
}

static parse_result_t
parse_section_dataplane(struct ctrl_cfg *config __unused, int id,
			const char *name, const char *value)
{
	return vplane_cfg_set_attribute(id, name, value);
}

/*
 * Callback from the ini library for each name value pair.
 *
 * return 0 = error, 1 = ok
 */
static int
parse_entry(void *arg, const char *section, const char *name,
	    const char *value)
{
	static const char prefix[] = "dataplane.";
	size_t prefixlen = strlen(prefix);
	struct ctrl_cfg *config = arg;
	parse_result_t psts;

	psts = PARSE_IGNORED;

	if (strcasecmp("controller", section) == 0)
		psts = parse_section_controller(config, name, value);
	else if (strcasecmp("authentication", section) == 0)
		psts = parse_section_authentication(config, name, value);
	else if (strncasecmp(prefix, section, prefixlen) == 0) {
		int id;

		if (sscanf(section+prefixlen, "fabric%d", &id) == 1)
			psts = parse_section_dataplane(config, id, name, value);
		else {
			err("invalid dataplane section header: %s", section);
			psts = PARSE_ERR;
		}
	}

	switch (psts) {
	case PARSE_IGNORED:
		dbg("parsing '%s', ignored attribute '%s'", section, name);
		/* fall-through */
	case PARSE_OK:
		return 1;
	case PARSE_ERR:
		break;
	default:
		panic("unknown parse result");
		break;
	}

	return 0;
}

void
parser_controller_cfg_destroy()
{
	free(controller_cfg.publish_url);
	free(controller_cfg.request_url);
	free(controller_cfg.certificate);
	free(controller_cfg.auth_path);
	memset(&controller_cfg, '\0', sizeof(controller_cfg));
}

int
parser_controller_cfg(const char *fname)
{
	FILE *f;
	int rc;

	f = fopen(fname, "r");
	if (f == NULL) {
		err("file %s: %s\n", fname, strerror(errno));
		return -1;
	}

	dbg("parsing configuration file: %s", fname);

	parser_controller_cfg_destroy();

	controller_cfg.timeout = DEFAULT_TIMEOUT;
	controller_cfg.ctl_addr.af = AF_UNSPEC;

	vplane_cfg_begin();
	rc = ini_parse_file(f, parse_entry, &controller_cfg);
	fclose(f);
	if (rc) {
		vplane_cfg_failed();
		die("configuration file format error %s line %d\n", fname, rc);
	}
	vplane_cfg_end();

	controller_cfg.ctl_addr_valid = parser_address_check();
	if (!controller_cfg.ctl_addr_valid) {
		/*
		 * Invalid controller address, scrap any defined URL's
		 * that are NOT IPC based. By definition any IPC-based
		 * URL's are fine.
		 */
		if (is_url_ipc(controller_cfg.publish_url) == NULL) {
			free(controller_cfg.publish_url);
			controller_cfg.publish_url = NULL;
		}
		if (is_url_ipc(controller_cfg.request_url) == NULL) {
			free(controller_cfg.request_url);
			controller_cfg.request_url = NULL;
		}
	}

	/* Use default publish URL if not configured */
	if (controller_cfg.publish_url == NULL)
		controller_cfg.publish_url = parser_default_endpoint_publish();

	/* Use default request URL if not configured */
	if (controller_cfg.request_url == NULL)
		controller_cfg.request_url = parser_default_endpoint_request();

	if ((controller_cfg.publish_url == NULL) ||
	    (controller_cfg.request_url == NULL))
		die("Failed to allocate default endpoint URL\n");

	return 0;
}
