/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Configuration file (controller.conf) parser for controller.
 */
#if !defined(__parser_h__)
#define __parser_h__

#include "ip_addr.h"

typedef enum {
	PARSE_OK = 1,
	PARSE_ERR,
	PARSE_IGNORED
} parse_result_t;

#define PARSE_MAX_EP_LEN 128

/**
 * Is the supplied URL an IPC-based endpoint? If so return a pointer to
 * the start of the path.
 */
extern const char *
is_url_ipc(const char *url);

/*
 * Return URLs for use with request & publish ZeroMQ sockets.
 */
extern const char *
parser_endpoint_request(void);

extern const char *
parser_endpoint_publish(void);

extern const char *
parser_endpoint_request_bound(void);

extern const char *
parser_endpoint_publish_bound(void);

extern void
parser_set_endpoint_request_bound(char *url);

extern void
parser_set_endpoint_publish_bound(char *url);


/**
 * Get adddress family of the local address
 */
extern sa_family_t
parser_local_af(void);

/**
 * Get the controller local address
 */
const struct ip_addr *
parser_local_addr(void);
/*
 * Timeout, in seconds, for vplane connections. The vplane is assumed to
 * have died if nothing has been received within this interval.
 */
extern int
parser_controller_timeout(void);

extern parse_result_t
parse_atoi(uint32_t *i, const char *value);

/*
 * Is ZeroMQ authentication enabled?
 */
extern bool
parser_authentication_enabled(void);

/*
 * Return ZeroMQ authentication certificate filename
 */
extern const char *
parser_authentication_certificate(void);

/*
 * Return path storing remote ZeroMQ certificates
 */
extern const char *
parser_authentication_path(void);

/*
 * Will kernel routes be used?
 */
extern bool
parser_use_kernel_routes(void);

/*
 * Create JSON string describing the config database
 */
int parser_get_json_config(const char *topic, zmsg_t *msg, char **json);

/*
 * Reset (clear) the current controller configuration. Currently only
 * used during unit-testing.
 */
extern void
parser_controller_cfg_destroy(void);

/*
 * Parse and save the configuration provided by the given file. Return values:
 *
 * 0   - Success, no parsing errors encountered
 * < 0 - Parser or file access error
 */
extern int
parser_controller_cfg(const char *fname);

/**
 * Is fabric encryption enabled
 * Returns true if enabled, false if disabled
 */
bool
parser_fabric_encrypt_enabled(void);

/**
 * Set fabric encryption
 * Set true to enable and false to disable
 */
void
parser_set_fabric_encrypt(bool encrypt);

/*
 * Set controller fabric address.
 */
void
parser_set_fabric_address(struct ip_addr *addr);

/*
 * Delete controller fabric address.
 */
void
parser_delete_fabric_address(struct ip_addr *addr);

/*
 * Returns controller fabric address for given address family
 */
const struct ip_addr *
parser_fabric_addr(sa_family_t af);

#endif
