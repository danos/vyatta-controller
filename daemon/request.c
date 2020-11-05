/*
 * Request socket handling thread.
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <dirent.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/limits.h>
#ifdef RTNLGRP_RTDMN
#include <linux/rtg_domains.h>
#endif
#include <systemd/sd-daemon.h>

#include <czmq.h>
#include <json.h>

#include "compat.h"
#include "controller.h"
#include "mrtstat.h"
#include "parser.h"
#include "vplane.h"
#include "configstore.h"

#define CONNECT_VERSION 0

typedef struct request_ {
	zsock_t *sock;
	char *action;
	zframe_t **envelope;
	snapshot_t *snap;
	vplane_t *vp;
	int32_t portno;
	zsock_t *pipe;
	zsock_t *event_pub;
} request_t;

typedef struct loopargs_ {
	zloop_t *loop;
	snapshot_t *snap;
	zsock_t *pipe;
	zsock_t *request;
	zsock_t *event_pub;
	bool requestor_running;
} loopargs_t;

/* 
 * This needs to be less (with a margin for error) than the service
 * start timeout
 */
#define SNAPSHOT_TIMEOUT_SECS 80

static int snapreq_to_timerid;
static zloop_t *snapreq_to_loop;

int zmsg_popu32(zmsg_t *msg, uint32_t *p)
{
	zframe_t *frame = zmsg_pop(msg);
	if (frame == NULL) {
		dbg("popu32: missing message element");
		return -1;
	}

	if (zframe_size(frame) != sizeof(uint32_t)) {
		dbg("popu32: wrong message size %zd", zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(p, zframe_data(frame), sizeof(uint32_t));
	zframe_destroy(&frame);
	return 0;
}

static int zmsg_popu64(zmsg_t *msg, uint64_t *p)
{
	zframe_t *frame = zmsg_pop(msg);
	if (frame == NULL) {
		dbg("popu64: missing message element");
		return -1;
	}

	if (zframe_size(frame) != sizeof(uint64_t)) {
		dbg("popu64: wrong message size %zd", zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(p, zframe_data(frame), sizeof(uint64_t));
	zframe_destroy(&frame);
	return 0;
}

static int zmsg_popport(zmsg_t *msg)
{
	uint32_t port;

	if (zmsg_popu32(msg, &port) < 0) {
		dbg("popport: missing message element");
		return -1;
	}

	if (port > MAX_PORTS) {
		dbg("popport: value out of range %u", port);
		return -1;
	}

	return port;
}

static int zmsg_popaddr(zmsg_t *msg, struct ip_addr *addr)
{
	zframe_t *frame = zmsg_pop(msg);
	size_t fsz;
	void *data;
	int rc = 0;

	if (frame == NULL) {
		dbg("popaddr: missing message element");
		return -1;
	}

	fsz = zframe_size(frame);
	data = zframe_data(frame);
	if (fsz == sizeof(struct ip_addr))
		memcpy(addr, data, fsz);
	else if (fsz == sizeof(struct in_addr)) {
		addr->af = AF_INET;
		memcpy(&addr->ip.v4, data, fsz);
	} else {
		dbg("popaddr: wrong message size %zd", fsz);
		rc = -1;
	}

	zframe_destroy(&frame);
	return rc;
}

static int zmsg_pop_sg_req(zmsg_t *msg, struct sioc_sg_req *sg)
{
	zframe_t *frame = zmsg_pop(msg);

	if (frame == NULL) {
		dbg("sioc_sg_req: missing message element");
		return -1;
	}

	if (zframe_size(frame) != sizeof(struct sioc_sg_req)) {
		dbg("sioc_sg_req: wrong message size %zd", zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(sg, zframe_data(frame), sizeof(struct sioc_sg_req));
	zframe_destroy(&frame);
	return 0;
}

static int zmsg_pop_sg_req6(zmsg_t *msg, struct sioc_sg_req6 *sg)
{
	zframe_t *frame = zmsg_pop(msg);

	if (frame == NULL) {
		dbg("sioc_sg_req: missing message element");
		return -1;
	}

	if (zframe_size(frame) != sizeof(struct sioc_sg_req6)) {
		dbg("sioc_sg_req: wrong message size %zd", zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(sg, zframe_data(frame), sizeof(struct sioc_sg_req6));
	zframe_destroy(&frame);
	return 0;
}

/*
 * Build and send a reply message
 */
static void send_reply(request_t *req, zmsg_t *reply, const char *response)
{
	int rc;

	if (!reply)
		panic("missing response message");

	rc = zmsg_pushstr(reply, response);
	if (rc == 0)
		rc = zmsg_prepend(reply, req->envelope);

	if (rc == 0) {
		if (debug > 1)
			zmsg_dump(reply);

		rc = zmsg_send(&reply, req->sock);
	}

	if (rc == 0)
		info("%s (%d): sent '%s'", req->action, vplane_get_id(req->vp),
		     response);
	else {
		err("%s: failed to send response (%s)", req->action,
		    strerror(errno));
		zmsg_destroy(&reply);
	}
}

/* An error occurred whilst processing a request, log the error */
static void request_error(request_t *req, const char *error)
{
	err("%s: failed '%s'", req->action, error);
}

/* An error occurred whilst processing a request, send reply to dataplane */
static void reply_error(request_t *req, const char *error)
{
	send_reply(req, zmsg_new(), error);
}

static void send_ifindex(request_t *req, uint32_t ifindex, uint64_t seqno)
{
	zmsg_t *reply = zmsg_new();

	if (!reply)
		panic("zmsg_new failed");

	if (zmsg_addmem(reply, &seqno, sizeof(seqno)) < 0)
		panic("zmsg_addmem(seqno) failed");

	if (zmsg_addmem(reply, &ifindex, sizeof(ifindex)) < 0)
		panic("zmsg_addmem(ifindex) failed");

	send_reply(req, reply, "OK");
}

static void send_port_response(request_t *req, uint32_t ifindex,
			       const char *ifname, uint64_t seqno)
{
	zmsg_t *reply = zmsg_new();

	if (!reply) {
		err("zmsg_new failed");
		return;
	}

	if (zmsg_addmem(reply, &seqno, sizeof(seqno)) < 0) {
		err("zmsg_addmem(seqno) failed");
		goto fail;
	}
	if (zmsg_addmem(reply, &ifindex, sizeof(ifindex)) < 0) {
		err("zmsg_addmem(ifindex) failed");
		goto fail;
	}
	if (zmsg_addstr(reply, ifname) < 0) {
		err("zmsg_addstr(ifname) failed");
		goto fail;
	}
	send_reply(req, reply, "OK");
	return;

  fail:
	zmsg_destroy(&reply);
}

/* end of snapshot marker */
static void send_eom(request_t *req)
{
	nlmsg_t *msg = nlmsg_new("THATSALLFOLKS!",
				 snapshot_seqno(req->snap),  "", 0);
	if (debug)
		nlmsg_dump("send eom", msg);

	if (!msg)
		err("can't make end-of-sync message");
	else {
		zframe_send(req->envelope, req->sock, ZFRAME_MORE);
		nlmsg_send(msg, req->sock);
	}
}

static int connect_parse(request_t *req, zmsg_t *msg, uint32_t *version,
			 char **uuid, char **control)
{
	*version = 0;
	*control = NULL;
	*uuid = NULL;

	if (zmsg_popu32(msg, version) < 0) {
		request_error(req, "version");
		return -1;
	}
	*uuid = zmsg_popstr(msg);
	if (*uuid == NULL) {
		request_error(req, "uuid");
		return -1;
	}
	*control = zmsg_popstr(msg);
	if (*control == NULL) {
		request_error(req, "control");
		return -1;
	}

	return 0;
}

static int connect_process(request_t *req, vplane_t *vp, uint32_t version,
			   const char *control)
{
	if (version != CONNECT_VERSION) {
		request_error(req, "version mismatch");
		return -1;
	}

	if (vplane_set_control(vp, control) < 0) {
		request_error(req, "cannot set control");
		return -1;
	}

	return 0;
}

static const char * const virtual_ifprefix[] = { "br", "erspan", "tun", "vti" };

/*
 * Delete 'clear' stat files of virtual interfaces resident in the dataplane.
 */
static void del_virtual_intf_stat_files(char *file_name)
{
	char stats_file[PATH_MAX];
	int if_cnt = sizeof(virtual_ifprefix)/sizeof(*virtual_ifprefix);
	int i;

	for (i = 0; i < if_cnt; i++) {
		if (strncmp(file_name, virtual_ifprefix[i],
				strlen(virtual_ifprefix[i])) == 0) {
			snprintf(stats_file, sizeof(stats_file),
				"/var/run/vyatta/%s", file_name);
			unlink(stats_file);
		}
	}
}

/*
 * When a dataplane restarts, clean up *.stats files in /var/run/vyatta
 * pertaining to this dataplane's interfaces. The stat files store
 * interface statistics counters when the "clear interface counters"
 * CLI command is issued. Stale counter values must be deleted when
 * dataplane restarts.
 */
static void cleanup_stats(vplane_t *vp)
{
	char fprefix[8];
	char dpid[8];
	char stats_file[PATH_MAX];
	DIR *dir;
	struct dirent *dent;
	char *fextn;

	snprintf(fprefix, sizeof(fprefix), "dp%d", vplane_get_id(vp));
	snprintf(dpid, sizeof(dpid), ".dp%d.", vplane_get_id(vp));
	dir = opendir("/var/run/vyatta");
	if (dir == NULL)
		return;
	while ((dent = readdir(dir))) {
		fextn = strrchr(dent->d_name, '.');
		if (fextn == NULL)
			continue;
		if (strncmp(fextn, ".stats", 6) != 0)
			continue;
		if (strncmp(dent->d_name, fprefix, strlen(fprefix)) == 0 ||
		    strstr(dent->d_name, dpid)) {
			snprintf(stats_file, sizeof(stats_file),
				"/var/run/vyatta/%s", dent->d_name);
			unlink(stats_file);
		} else
			del_virtual_intf_stat_files(dent->d_name);
	}
	closedir(dir);
}

static int connect_accept(request_t *req, vplane_t *vp)
{
	zmsg_t *msg = zmsg_new();
	uint16_t id;
	int rc;
	char buf[64];

	if (msg == NULL) {
		request_error(req, "cannot allocate accept");
		return -1;
	}

	id = vplane_get_id(vp);
	rc = zmsg_addstr(msg, vplane_get_uuid(vp));
	if (rc == 0)
		rc = zmsg_addmem(msg, &id, sizeof(id));
	if (rc == 0) {
		cleanup_stats(vp);
		send_reply(req, msg, "ACCEPT");
		return 0;
	}

	snprintf(buf, sizeof(buf), "cannot create accept: %s",
		 strerror(errno));
	request_error(req, buf);
	zmsg_destroy(&msg);
	return -1;
}

static void connect_reject(request_t *req, const char *uuid)
{
	zmsg_t *msg = zmsg_new();
	char buf[64];

	if (msg != NULL)
		if (zmsg_addstr(msg, uuid) == 0) {
			send_reply(req, msg, "REJECT");
			return;
		}

	snprintf(buf, sizeof(buf), "cannot create reject: %s",
		 strerror(errno));
	request_error(req, buf);
	zmsg_destroy(&msg);
}

enum {
	CONNECT_ERROR_NONE = 0,
	CONNECT_ERROR_PROCESS,
	CONNECT_ERROR_UUID,
	CONNECT_ERROR_PARSE,
	CONNECT_ERROR_CONNECT,
	CONNECT_ERROR_MAX
};

static const char * const connect_error_label[] = { "process", "uuid", "parse",
						    "connect" };

#define CONNECT_ERROR_LIST 10

struct connect_errors {
	uint64_t count[CONNECT_ERROR_MAX - 1];
	int recent[CONNECT_ERROR_LIST];
	char *uuid[CONNECT_ERROR_LIST];
	int next;
} *con_errs;

static void connect_error_clear(void)
{
	int i;

	if (con_errs != NULL) {
		for (i = 0; i < CONNECT_ERROR_LIST; i++)
			free(con_errs->uuid[i]);
		free(con_errs);
		con_errs = NULL;
	}
}

static void connect_error_log(int error, const char *uuid)
{
	int i;

	if ((error <= CONNECT_ERROR_NONE) || (error >= CONNECT_ERROR_MAX))
		return;

	if (con_errs == NULL) {
		con_errs = malloc(sizeof(struct connect_errors));
		if (con_errs != NULL)
			memset(con_errs, 0, sizeof(struct connect_errors));
	}
	if (con_errs == NULL)
		return;

	con_errs->count[error - 1]++;

	/* Avoid storing duplicate errors */
	for (i = 0; i < CONNECT_ERROR_LIST; i++)
		if ((con_errs->recent[i] == error) &&
		    (((uuid == NULL) && (con_errs->uuid[i] == NULL)) ||
		     ((uuid != NULL) && (con_errs->uuid[i] != NULL) &&
		      (strcmp(uuid, con_errs->uuid[i]) == 0))))
			return;

	con_errs->recent[con_errs->next] = error;
	free(con_errs->uuid[con_errs->next]);
	con_errs->uuid[con_errs->next] = NULL;
	if (uuid != NULL)
		con_errs->uuid[con_errs->next] = strdup(uuid);
	con_errs->next++;
	con_errs->next %= CONNECT_ERROR_LIST;
}

static int connect_get_json_errors(const char *topic __unused,
				   zmsg_t *msg __unused,
				   char **json)
{
	int i, j;

	if (con_errs == NULL)
		return 0;

	json_object *jobj = json_object_new_object();
	json_object *jarray = json_object_new_array();

	for (i = CONNECT_ERROR_NONE + 1; i < CONNECT_ERROR_MAX; i++)
		if (con_errs->count[i - 1])
			json_object_object_add(jobj, connect_error_label[i - 1],
				json_object_new_int(con_errs->count[i - 1]));

	for (i = con_errs->next;
	     i < (con_errs->next + CONNECT_ERROR_LIST); i++) {
		j = i % CONNECT_ERROR_LIST;
		if (con_errs->recent[j] == CONNECT_ERROR_NONE)
			continue;

		json_object *jentry = json_object_new_object();
		const char *label =
				 connect_error_label[con_errs->recent[j] - 1];

		json_object_object_add(jentry, "error",
				       json_object_new_string(label));
		if (con_errs->uuid[j] != NULL)
			json_object_object_add(jentry, "uuid",
				json_object_new_string(con_errs->uuid[j]));

		json_object_array_add(jarray, jentry);

	}

	json_object_object_add(jobj, "recent", jarray);

	*json = strdup(json_object_to_json_string(jobj));

	/* Free JSON objects */
	json_object_put(jobj);

	return 0;
}

static void interface_delete_pending(const vplane_t *vp, uint32_t ifn,
				     void *arg __unused)
{
	vplane_iface_set_delpend(vp, ifn, true);
}

/*
 * Parse connect message from vplane:
 *
 * [1] <version> 32bit
 * [2] <UUID> string
 * [3] <control> string - 0MQ URL of control socket
 */
static int connect_request(request_t *req, zmsg_t *msg)
{
	char *uuid;
	char *control;
	uint32_t version;
	vplane_t *vp = NULL;
	int rc = -1;
	int error = CONNECT_ERROR_NONE;

	if (connect_parse(req, msg, &version, &uuid, &control) == 0) {
		vp = vplane_findbyuuid(uuid);
		if (vp != NULL) {
			if (connect_process(req, vp, version, control) < 0) {
				connect_reject(req, uuid);
				vp = NULL;
				error = CONNECT_ERROR_PROCESS;
			}
		} else {
			char buf[64];

			snprintf(buf, sizeof(buf), "cannot find vplane (%s)",
				 uuid);
			request_error(req, buf);
			error = CONNECT_ERROR_UUID;
		}
	} else
		error = CONNECT_ERROR_PARSE;

	if (vp != NULL) {
		req->vp = vp;
		if (vplane_connect(vp, *req->envelope) < 0) {
			connect_reject(req, uuid);
			error = CONNECT_ERROR_CONNECT;
		} else {
			connect_accept(req, vp);
			rc = 0;
		}
		info("vplane(%d) control URL %s", vplane_get_id(vp), control);
	}

	if (error != CONNECT_ERROR_NONE)
		connect_error_log(error, uuid);
	else
		/*
		 * dataplane restart, mark the current set of ports as
		 * delete pending; the attribute is cleared as each
		 * port is (re-)created.
		 */
		vplane_iface_iterate(vp, interface_delete_pending, NULL);

	free(uuid);
	free(control);
	return rc;
}

/*
 * Provide configuration parameters to the dataplane which were formerly held in
 * the file dataplane.conf.
 *
 * The message consists of any number of parameters, which can be listed in any
 * order.
 *
 * Each parameter is specified using two message components - the first is a
 * string giving the name of the parameter, the second component is the
 * parameter value.
 *
 * Currently we only have the publisher URL, but the list of parameters may
 * be expanded later.
 */
static int conf_request(request_t *req, zmsg_t *req_msg __unused)
{
	zmsg_t *msg = zmsg_new();
	int rc;
	char buf[64];

	const char *cur_ep = parser_endpoint_publish_bound();

	if (msg != NULL) {
		rc = zmsg_addstr(msg, "PUBLISH");
		if (rc == 0) {
			info("sending publisher URL %s", cur_ep);
			rc = zmsg_addstr(msg, cur_ep);
		}
		if (rc == 0) {
			send_reply(req, msg, "CONF");
			return 0;
		}
	}

	snprintf(buf, sizeof(buf), "cannot create conf message: %s",
		 strerror(errno));
	request_error(req, buf);
	zmsg_destroy(&msg);
	return 1;
}

/*
 * Parse port creation message:
 *   [1] <seqno> 64bit
 *   [2] <myip> 32bits - network byte order (ignored)
 *   [3] <info> string - JSON encoded slot related info
 */
static int newport_request(request_t *req, zmsg_t *msg)
{
	char ifname[IFNAMSIZ];
	struct ether_addr eth;
	struct ip_addr raddr;
	uint64_t seqno;
	char *devinfo, *driver = NULL, *bus = NULL;
	unsigned int if_flags = 0;
	unsigned int mtu = 0;
	int rc;

	if (zmsg_popu64(msg, &seqno) < 0) {
		reply_error(req, "seqno");
		return -1;
	}

	if (zmsg_popaddr(msg, &raddr) < 0) {
		reply_error(req, "raddr");
		return -1;
	}

	devinfo = zmsg_popstr(msg);
	if (devinfo == NULL) {
		reply_error(req, "info");
		return -1;
	}

	rc = assign_port(devinfo, vplane_get_id(req->vp),
			 ifname, &eth, &driver, &bus,
			 &if_flags, &mtu);
	free(devinfo);

	if (rc < 0)
		goto err;

	req->portno = rc;

	/*
	 * Now generate the shadow port and get hold of the resultant ifindex
	 */
	uint32_t ifindex;
	rc = port_create(req->vp, req->portno, ifname, &eth, driver, bus,
			 if_flags, mtu, &ifindex);
	free(driver);
	free(bus);

	if (rc < 0)
		goto err;

	rc = vplane_iface_add(req->vp, req->portno, ifindex, ifname);
	if (rc < 0)
		goto err;

	send_port_response(req, ifindex, ifname, seqno);
	return 0;

  err:
	reply_error(req, "FAIL: newport_request");
	return rc;
}

/*
 * Parse port deletion message.
 *   [1] <seqno>  64bit
 *   [2] <port> 32bit
 *   [3] <ifindex>  32bit (ignored)
 *   [4] <myip> ipv4/ipv6 address (ignored)
 */
static int delport_request(request_t *req, zmsg_t *msg)
{
	uint64_t seqno;
	uint32_t ifindex;
	struct ip_addr raddr;

	if (zmsg_popu64(msg, &seqno) < 0) {
		reply_error(req, "seqno");
		return -1;
	}

	req->portno = zmsg_popport(msg);
	if (req->portno < 0) {
		reply_error(req, "popport");
		return -1;
	}

	if (zmsg_popu32(msg, &ifindex) < 0) {
		reply_error(req, "ifindex");
		return -1;
	}

	if (zmsg_popaddr(msg, &raddr) < 0) {
		reply_error(req, "raddr");
		return -1;
	}

	int rc = port_delete(req->vp, req->portno);

	vplane_iface_del(req->vp, req->portno);
	send_ifindex(req, rc, seqno);
	return 0;
}

struct dpport_cookie {
	struct ether_addr eth;
	char *driver;
	char *bus;
	unsigned int if_flags;
	unsigned int mtu;
};

static void dpport_cookie_destroy(struct dpport_cookie **cookiep)
{
	struct dpport_cookie *cookie = *cookiep;

	if (cookie != NULL) {
		free(cookie->driver);
		free(cookie->bus);
		free(cookie);
	}

	*cookiep = NULL;
}

static struct dpport_cookie *dpport_cookie_create(void)
{
	return calloc(1, sizeof(struct dpport_cookie));
}

/*
 * Parse port initialisation message:
 *   [1] <seqno>  64bit
 *   [2] <devinfo> string - JSON string with details of the device
 *
 * Response
 *   [1] <seqno>  64bit
 *   [2] <cookie> 32bit  - context to be supplied in ADDPORT
 *   [3] <ifname> string - generated interface name
 */
static int iniport_request(request_t *req, zmsg_t *msg)
{
	struct dpport_cookie *cookie = NULL;
	char ifname[IFNAMSIZ];
	char *devinfo;
	uint64_t seqno;
	int rc;

	if (zmsg_popu64(msg, &seqno) < 0) {
		reply_error(req, "seqno");
		return -1;
	}

	devinfo = zmsg_popstr(msg);
	if (devinfo == NULL) {
		reply_error(req, "info");
		return -1;
	}

	cookie = dpport_cookie_create();
	if (cookie == NULL) {
		reply_error(req, "cookie");
		return -1;
	}

	/*
	 * Parse the physical device details
	 */
	rc = assign_port(devinfo, vplane_get_id(req->vp), ifname,
			 &cookie->eth, &cookie->driver, &cookie->bus,
			 &cookie->if_flags, &cookie->mtu);
	free(devinfo);

	if (rc < 0)
		goto err;

	/*
	 * Establish an interface "placeholder" and save the device
	 * details until we get the corresponding ADDPORT message.
	 */
	req->portno = rc;
	rc = vplane_iface_add(req->vp, req->portno, 0, ifname);
	if (rc < 0)
		goto err;

	rc = vplane_iface_set_cookie(req->vp, req->portno, cookie);
	if (rc < 0) {
		vplane_iface_del(req->vp, req->portno);
		goto err;
	}

	vplane_iface_set_delpend(req->vp, req->portno, false);
	send_port_response(req, req->portno, ifname, seqno);
	return 0;

err:
	dpport_cookie_destroy(&cookie);
	reply_error(req, "FAIL: iniport_request");
	return rc;
}

/*
 * Parse port add message:
 *   [1] <seqno>  64bit
 *   [2] <cookie> 32bit  - context, as provided by INI response
 *   [3] <ifname> string - Interface name, as provided by INI response
 *
 * Response
 *   [1] <seqno>  64bit
 *   [2] <ifindex> 32bit - Interface ifindex
 *   [3] <ifname> string - Interface name
 */
static int addport_request(request_t *req, zmsg_t *msg)
{
	struct dpport_cookie *cookie = NULL;
	const char *ifname;
	char *dpifname;
	uint64_t seqno;
	uint32_t portno;
	int rc = -1;

	if (zmsg_popu64(msg, &seqno) < 0) {
		reply_error(req, "seqno");
		return -1;
	}

	if (zmsg_popu32(msg, &portno) < 0) {
		reply_error(req, "cookie");
		return -1;
	}
	req->portno = portno;

	dpifname = zmsg_popstr(msg);
	if (dpifname == NULL) {
		reply_error(req, "ifname");
		return -1;
	}

	ifname = vplane_iface_get_ifname(req->vp, req->portno);
	if ((ifname == NULL) ||
	    !streq(ifname, dpifname)) {
		err("mismatched or missing ifnames %s %s",
		    ifname == NULL ? "N/A" : ifname,
		    dpifname);
		goto err;
	}

	free(dpifname);
	dpifname = NULL;
	cookie = vplane_iface_get_cookie(req->vp, req->portno);
	if (cookie == NULL) {
		err("missing port cookie");
		goto err;
	}
	vplane_iface_set_cookie(req->vp, req->portno, NULL);

	/*
	 * Now generate the shadow port and get hold of the resultant ifindex
	 */
	uint32_t ifindex;

	/* Take publisher lock to make sure port create is completed
	 * before netlink for new link is published
	 */
	nl_publisher_lock();
	rc = port_create(req->vp, req->portno, ifname,
			 &cookie->eth, cookie->driver, cookie->bus,
			 cookie->if_flags, cookie->mtu, &ifindex);
	nl_publisher_unlock();

	dpport_cookie_destroy(&cookie);

	if (rc < 0)
		goto err;

	rc = vplane_iface_add(req->vp, req->portno, ifindex, ifname);
	if (rc < 0)
		goto err;

	send_port_response(req, ifindex, ifname, seqno);
	return 0;

err:
	free(dpifname);
	dpport_cookie_destroy(&cookie);
	vplane_iface_del(req->vp, req->portno);
	reply_error(req, "FAIL: addport_request");
	return rc;
}

static int get_duplex(zmsg_t *msg, unsigned *duplex)
{
	char *str = zmsg_popstr(msg);
	if (!str)
		return -1;

	if (streq(str, "full"))
		*duplex = DUPLEX_FULL;
	else if (streq(str, "half"))
		*duplex = DUPLEX_HALF;
	else
		*duplex = DUPLEX_UNKNOWN;
	free(str);
	return 0;
}

static int link_state_change(request_t *req, uint32_t port, int up)
{
	uint32_t operstate = up ? IF_OPER_UP : IF_OPER_DORMANT;
	uint32_t ifindex = vplane_iface_get_ifindex(req->vp, port);
	char buf[64];

	if (ifindex == 0) {
		snprintf(buf, sizeof(buf), "unknown port: %u", port);
		request_error(req, buf);
		return -1;
	}

	/*
	 * If this is a bonding interface, we don't need to
	 * update the link status.  This has already been
	 * handled by teamd.  For remote dataplane bonding
	 * interfaces this may not be true -- TBD.
	 */
	const char *if_name = vplane_iface_get_ifname(req->vp, port);

	if (strncmp("dp0bond", if_name, strlen("dp0bond")) != 0) {
		if (port_state_change(req->vp, port, ifindex, operstate) < 0) {
			snprintf(buf, sizeof(buf), "cannot set link state: %s",
				 up ? "UP" : "DOWN");
			request_error(req, buf);
			return -1;
		}
	}

	return vplane_iface_set_state(req->vp, port, operstate);
}

static int linkdown_request(request_t *req, zmsg_t *msg)
{
	int32_t port = zmsg_popport(msg);
	if (port < 0) {
		reply_error(req, "BADLINKPORT");
		return -1;
	}

	const char *ifname = vplane_iface_get_ifname(req->vp, port);

	if (ifname)
		port_set_speed(ifname, SPEED_UNKNOWN, DUPLEX_UNKNOWN, 0, true);

	link_state_change(req, port, 0);

	req->portno = port;
	return 0;
}

static int linkup_request(request_t *req, zmsg_t *msg)
{
	int32_t port = zmsg_popport(msg);

	if (port < 0) {
		reply_error(req, "BADLINKPORT");
		return -1;
	}

	struct ip_addr raddr;

	if (zmsg_popaddr(msg, &raddr) < 0) {
		request_error(req, "missing source IP");
		return -1;
	}

	uint64_t speed;
	unsigned duplex;
	if (zmsg_popu64(msg, &speed) < 0) {
		reply_error(req, "BADSPEED");
		return -1;
	}

	if (get_duplex(msg, &duplex) < 0) {
		reply_error(req, "BADDUPLEX");
		return -1;
	}

	const char *ifname = vplane_iface_get_ifname(req->vp, port);

	/* Link up may carry statistics information */
	zframe_t *fr = zmsg_pop(msg);
	if (fr) {
		if (ifname) {
			if (vplane_is_local(req->vp))
				port_set_stats(ifname, fr, false, 0);
			else
				port_set_stats(ifname, fr, true,
					       vplane_get_id(req->vp));
		}
		zframe_destroy(&fr);
	} else
		notice("Missing stats port %d (%s)", port,
						     ifname ? ifname : "");

	uint64_t advertised = ADVERTISED_Autoneg; /* assume default */
	if (zmsg_popu64(msg, &advertised) < 0)
		notice("Missing advertised port %d (%s)", port,
							  ifname ? ifname : "");

	if (ifname) {
		/* advertised is truncated to uint32_t here because the
		 * dataplane doesn't set anything in the upper 32 bits.
		 */
		port_set_speed(ifname, speed, duplex, advertised, false);
	}

	if (link_state_change(req, port, 1) < 0) {
		reply_error(req, "FAIL: linkup_request");
		return -1;
	}

	req->portno = port;
	return 0;
}

/* Process "STATS" statistics update */
static int stats_update(request_t *req, zmsg_t *msg)
{
	char *ifname = zmsg_popstr(msg);

	if (!ifname) {
		reply_error(req, "missing ifname");
		return -1;
	}

	zframe_t *fr  = zmsg_first(msg);
	if (!fr) {
		reply_error(req, "missing data");
		free(ifname);
		return -1;
	}

	if (vplane_is_local(req->vp))
		port_set_stats(ifname, fr, false, 0);
	else
		port_set_stats(ifname, fr, true, vplane_get_id(req->vp));
	free(ifname);
	return 0;
}

/* Process "MRTSTAT" requests  */
static int mrt_request(request_t *req, zmsg_t *msg)
{
	struct sioc_sg_req sg;
	uint32_t vrf_id, flags;
	char source[INET_ADDRSTRLEN];
	char group[INET_ADDRSTRLEN];

	if (zmsg_pop_sg_req(msg, &sg)) {
		reply_error(req, "FAIL: mrt_request stats");
		return -1;
	}

	/*
	 * For backwards compatibility, cope with MRSTAT
	 * request from data plane not containing a VRF ID.
	 */
	if (zmsg_popu32(msg, &vrf_id) < 0)
		vrf_id = VRF_DEFAULT_ID;

	if (zmsg_popu32(msg, &flags) < 0) {
		flags = 0;
	}

	/*
	 * If data plane is indicating last mroute in VRF about to be
	 * deleted, close per-VRF socket and exit. i.e. do not attempt
	 * to update kernel with this final stats block; update will fail
	 * since mroute must have already been deleted by kernel.
	 */
	if (flags) {
		inet_ntop(AF_INET, &sg.src, source, sizeof(source));
		inet_ntop(AF_INET, &sg.grp, group, sizeof(group));
		notice("Last stats update for IPv4 VRF %u; mroute is (%s, %s)",
		       vrf_id, source, group);
		if (mcast_close_stats_socket(vrf_id, AF_INET) < 0) {
			err("Error closing IPv4 mcast stats socket for VRF %u", vrf_id);
		}

		return 0;
	}

	if (set_sg_count(&sg, vrf_id)) {
		inet_ntop(AF_INET, &sg.src, source, sizeof(source));
		inet_ntop(AF_INET, &sg.grp, group, sizeof(group));
		err("Failure updating kernel with mcast stats for (%s, %s); VRF ID = %u",
		    source, group, vrf_id);
	}

	return 0;
}

/*
 * An interface is no longer part of the dataplane configuration. Need
 * to remove the link from the snapshot database. Get the main thread
 * to issue a "fake" DELLINK message for the given interface.
 */
static void snapshot_interface_purge(const vplane_t *vp, uint32_t ifn,
				     void *arg)
{
	request_t *req = arg;
	const char *action;
	const char *ifname;
	uint32_t ifindex;
	zmsg_t *msg;
	int rc = 0;

	if (!vplane_iface_get_delpend(vp, ifn))
		return;

	ifindex = vplane_iface_get_ifindex(vp, ifn);
	ifname = vplane_iface_get_ifname(vp, ifn);
	action = "allocate";
	msg = zmsg_new();
	if (msg == NULL) {
		rc = -1;
		goto done;
	}

	action = "build";
	rc = zmsg_addstr(msg, "PURGEINK");
	if (rc < 0)
		goto done;

	rc = zmsg_addmem(msg, &ifindex, sizeof(ifindex));
	if (rc < 0)
		goto done;

	rc = zmsg_addstr(msg, ifname);
	if (rc < 0)
		goto done;

	action = "send";
	rc = zmsg_send(&msg, req->pipe);
	if (rc < 0)
		goto done;

done:
	if (rc >= 0) {
		action = "delete port after";
		rc = port_delete(vp, ifn);
	}

	vplane_iface_del((vplane_t *)vp, ifn);
	if (rc != 0)
		err("vplane(%d) failed to %s purge %s message",
		    vplane_get_id(vp), action, ifname);
	zmsg_destroy(&msg);
}

static void do_snapshot(request_t *req, const char *who, bool skip_cstore)
{
	int vpid = vplane_get_id(req->vp);

	if (vpid < 0)
		info("%s BEGIN", who);
	else
		info("%s (%d) BEGIN", who, vpid);

	snapshot_send(req->snap, req->sock, *req->envelope);
	if (!skip_cstore)
		config_send(req->sock, *req->envelope);
	send_eom(req);
	info("%s END", who);
}

/*
 * Snapshot message from collector. This is a request from the dataplane
 * that was inserted into the snapshot queue. Time to actually send the
 * snapshot.
 */
static int snapshot_req_recv(zmsg_t *msg)
{
	request_t req;
	zframe_t *frame;

	frame = zmsg_pop(msg);
	if (!frame)
		return -1;
	req.sock = *(zsock_t **) zframe_data(frame);
	zframe_destroy(&frame);

	frame = zmsg_pop(msg);
	if (!frame)
		return -1;
	req.snap = *(snapshot_t **) zframe_data(frame);
	zframe_destroy(&frame);

	frame = zmsg_pop(msg);
	if (!frame)
		return -1;
	req.envelope = &frame;

	req.vp = vplane_findbysession(frame);

	do_snapshot(&req, "SNAPSHOT-REQ", false);

	zframe_destroy(&frame);
	return 0;
}
/*
 * Handle snapshot request from dataplane.
 *
 * This is part of the dataplane startup sequence. As the dataplane
 * has just sent NEWPORT requests for its ports, we will have just
 * sent NEWLINKs to the kernel to update the mac address, etc. These
 * might be waiting in the queue between the publisher and collector.
 *
 * So, rather than immediately sending the snapshot, send a message
 * to the publisher which will insert it into the snapshot queue. When
 * it pops out in the collector we will actually send the snapshot.
 *
 * This also indicates that we have progressed far enough through the
 * init sequence that we can tell systemd we are done. This needs to
 * be done after the shadow interfaces have been created in the
 * kernel, so that when the config is parsed the interfaces exist,
 * since dataplane type interfaces don't currently support deferred
 * commit action processing. This can be removed once they do. Note
 * also that this reasoning only works for a single dataplane, so if
 * there is more than one then deferred commit action processing for
 * dataplane interface types needs to be supported.
 */
static int snapshot_request(request_t *req, zmsg_t *msg __unused)
{
	int rc = 0;
	zframe_t *env_frame;

	/* Cancel timeout timer */
	zloop_timer_end(snapreq_to_loop, snapreq_to_timerid);
	sd_notify(0, "READY=1");
	env_frame = zframe_new(zframe_data(*req->envelope),
			       zframe_size(*req->envelope));

	if (env_frame) {
		/*
		 * Purge any snapshot link entries associated with
		 * interfaces that no longer exist (marked as delete
		 * pending)
		 */
		vplane_iface_iterate(req->vp, snapshot_interface_purge, req);

		rc = zsock_send(req->pipe, "sppf", "SNAPMARK",
				req->sock, req->snap, env_frame);
	} else
		rc = -ENOMEM;

	zframe_destroy(&env_frame);

	return rc;
}

static int snapshot_req_timeout_handle_event(
	zloop_t *loop __unused, int timerid __unused, void *arg __unused)
{
	logit(LOG_WARNING, 'W',
	      "timeout waiting for dataplane snapshot to begin. Signalling service start anyway\n");
	sd_notify(0, "READY=1");
	return 0;
}

static void snapshot_req_timeout_init(zloop_t *loop)
{
	snapreq_to_timerid = zloop_timer(loop, SNAPSHOT_TIMEOUT_SECS * 1000,
					 1 /* one time */,
					 snapshot_req_timeout_handle_event,
					 NULL);
	if (snapreq_to_timerid < 0)
		panic("zloop_timer for snapshot timeout");
	snapreq_to_loop = loop;
}

static int snapshot_dump(request_t *req, zmsg_t *msg __unused)
{
	do_snapshot(req, "SNAPSHOT-DUMP", true);
	return 0;
}

static int cstore_dump(request_t *req, zmsg_t *msg __unused)
{
	int vpid = vplane_get_id(req->vp);
	const char *who = "CSTORE-DUMP";

	if (vpid < 0)
		info("%s BEGIN", who);
	else
		info("%s (%d) BEGIN", who, vpid);

	config_send(req->sock, *req->envelope);
	send_eom(req);
	info("%s END", who);
	return 0;
}

/* Process "MRT6STAT" requests  */
static int mrt6_request(request_t *req, zmsg_t *msg)
{
	struct sioc_sg_req6 sg;
	uint32_t vrf_id, flags;
	char source[INET6_ADDRSTRLEN];
	char group[INET6_ADDRSTRLEN];

	if (zmsg_pop_sg_req6(msg, &sg)) {
		reply_error(req, "FAIL: mrt6_request stats");
		return -1;
	}

	/*
	 * For backwards compatibility, cope with MRSTAT
	 * request from data plane not containing a VRF ID.
	 */
	if (zmsg_popu32(msg, &vrf_id) < 0)
		vrf_id = VRF_DEFAULT_ID;

	if (zmsg_popu32(msg, &flags) < 0) {
		flags = 0;
	}

	/*
	 * If data plane is indicating last mroute in VRF about to be
	 * deleted, close per-VRF socket and exit. i.e. do not attempt
	 * to update kernel with this final stats block; update will fail
	 * since mroute must have already been deleted by kernel.
	 */
	if (flags) {
		inet_ntop(AF_INET6, &sg.src.sin6_addr, source, sizeof(source));
		inet_ntop(AF_INET6, &sg.grp.sin6_addr , group, sizeof(group));
		notice("Last stats update for IPv6 VRF %u; mroute is (%s, %s)",
		       vrf_id, source, group);
		if (mcast_close_stats_socket(vrf_id, AF_INET6) < 0) {
			err("Error closing IPv6 mcast stats socket for VRF %u", vrf_id);
		}

		return 0;
	}

	if (set_sg6_count(&sg, vrf_id)) {
		inet_ntop(AF_INET6, &sg.src.sin6_addr, source, sizeof(source));
		inet_ntop(AF_INET6, &sg.grp.sin6_addr , group, sizeof(group));
		err("Failure updating kernel with mcast stats for (%s, %s); VRF ID = %u",
		    source, group, vrf_id);
	}

	return 0;
}

/* Dataplane event to be published on event socket */
static int dp_event(request_t *req, zmsg_t *msg)
{
	if (zmsg_send(&msg, req->event_pub) < 0) {
		request_error(req, "DP event publish failed");
		return -1;
	}

	/* Positive return value indicates message is consumed. */
	return 1;
}

typedef int (request_msg_handler) (request_t *, zmsg_t *);

typedef struct request_handler_ {
	const char *name;
	request_msg_handler *hdlr;
	bool noconnectcheck;
} request_handler_t;

static const request_handler_t request_handlers[] = {
	{.name = "CONNECT", .hdlr = connect_request, .noconnectcheck = true},
	{.name = "CONFQUERY", .hdlr = conf_request},
	{.name = "INIPORT", .hdlr = iniport_request},
	{.name = "ADDPORT", .hdlr = addport_request},
	{.name = "NEWPORT", .hdlr = newport_request},
	{.name = "DELPORT", .hdlr = delport_request},
	{.name = "WHATSUP?", .hdlr = snapshot_request},
	{.name = "LINKUP", .hdlr = linkup_request},
	{.name = "LINKDOWN", .hdlr = linkdown_request},
	{.name = "STATS", .hdlr = stats_update},
	{.name = "MRTSTAT", .hdlr = mrt_request},
	{.name = "MRT6STAT", .hdlr = mrt6_request},
	{.name = "DPEVENT", .hdlr = dp_event},

	/*
	 * Note that this is not a message from the dataplane, its
	 * issued by the snapshot client in order to retrieve and
	 * display the database.
	 */
	{.name = "SNAPSHOT-DUMP", .hdlr = snapshot_dump,
	 .noconnectcheck = true},
	{.name = "CSTORE-DUMP", .hdlr = cstore_dump,
	 .noconnectcheck = true},
	{.name = NULL}
};

/* returns > 0 if the message has been consumed */
static int process_msg(request_t *req, zmsg_t *msg)
{
	const request_handler_t *hdlr;
	char *action = zmsg_popstr(msg);
	int hdlr_result = -1;

	if (action == NULL) {
		err("failed to collect action from message");
		return -1;
	}

	req->portno = -1;
	req->action = action;
	for (hdlr = &request_handlers[0]; hdlr->name != NULL; hdlr++)
		if (streq(action, hdlr->name))
			break;

	if (hdlr->name == NULL) {
		info("%s: unknown request message", action);
		return -1;
	}

	if (hdlr->noconnectcheck || vplane_is_connected(req->vp)) {
		if ((hdlr_result = (hdlr->hdlr)(req, msg)) >= 0)
			vplane_keepalive(req->vp, req->action, req->portno);
	} else {
		char buf[64];
		char *sid = zframe_strhex(*req->envelope);

		snprintf(buf, sizeof(buf), "vplane(%d) not connected (%s)",
			 vplane_get_id(req->vp), sid);
		request_error(req, buf);
		free(sid);

		/*
		 * Normally we would ignore messages from un-connected
		 * (un-authenticated) vplanes. But as a temporary
		 * measure - until the two-way keepalive mechanism is
		 * working - tell the vplane to "get lost"
		 * (re-synchronize).
		 *
		 * Failure to do so results in dead-lock - the vplane
		 * keeps issuing LINKUP messages which are ignored by
		 * the controller.
		 */
		reply_error(req, "FAIL: process_msg");
	}

	return hdlr_result;
}

static int process_request(zsock_t *sock, zmsg_t *msg, void *arg)
{
	loopargs_t *largs = arg;
	request_t req;
	zframe_t *envelope;
	int process_result;

	if (debug > 1)
		zmsg_dump(msg);

	envelope = zmsg_unwrap(msg);
	if (envelope == NULL) {
		err("missing envelope in message");
		return -1;
	}

	req.envelope = &envelope;
	req.snap = largs->snap;
	req.pipe = largs->pipe;
	req.event_pub = largs->event_pub;
	req.sock = sock;
	req.action = NULL;
	req.vp = vplane_findbysession(envelope);
	process_result = process_msg(&req, msg);
	free(req.action);
	zframe_destroy(req.envelope);

	return process_result;
}

/*
 * Wrapper around main request message handling function, used only for
 * unit-testing
 */
void request_test_msg(void *sock, zmsg_t *msg, void *snap)
{
	loopargs_t largs;

	largs.snap = snap;
	process_request(sock, msg, &largs);
}

/* callback from zloop, handles requests from dataplane */
static int requestor(zloop_t *loop __unused, zsock_t *sock, void *arg)
{
	zmsg_t *msg = zmsg_recv(sock);
	if (msg) {
		if (process_request(sock, msg, arg) <= 0)
			zmsg_destroy(&msg);
	}

	return 0;
}

static void authentication_disable(zsock_t *socket)
{
	if (zsock_curve_server(socket)) {
		zsock_set_curve_server(socket, false);
		info("request authentication disabled");
	}
}

/* enable authentication on the specified socket */
void authentication_enable(zsock_t *socket)
{
	zcert_t *cert;
	char *time;
	char ip[INET6_ADDRSTRLEN];

	if ((parser_authentication_certificate() == NULL) ||
	    (parser_authentication_path() == NULL))
		die("Incomplete authentication configuration\n");

	cert = zcert_load(parser_authentication_certificate());
	if (cert == NULL) {
		const struct ip_addr *addr = parser_local_addr();

		cert = zcert_new();
		if (cert == NULL)
			die("Authentication certificate initialization failed\n");
		zcert_set_meta(cert, "auto-created-by", "Vyatta controller");
		time = zclock_timestr();
		if (time != NULL) {
			zcert_set_meta(cert, "creation-time", "%s", time);
			free(time);
		}
		zcert_set_meta(cert, "creator-ip", "%s",
			       inet_ntop(addr->af, &addr->ip,
					 ip, sizeof(ip)));
		if (zcert_save(cert, parser_authentication_certificate()))
			die("Failed to create authentication certificate %s\n",
			    parser_authentication_certificate());
	}

	zcert_apply(cert, socket);
	zsock_set_curve_server(socket, true);
	info("request authentication enabled");
}

static void request_start(loopargs_t *largs)
{
	if (zloop_reader(largs->loop, largs->request, requestor, largs) < 0)
		panic("zloop_reader(request): '%s'", strerror(errno));
	info("request started");
}

static void request_close(zloop_t *loop, zsock_t **request)
{
	if (*request != NULL) {
		authentication_disable(*request);
		zloop_reader_end(loop, *request);
		zsock_destroy(request);
		info("request closed: %s", parser_endpoint_request_bound());
		parser_set_endpoint_request_bound(NULL);
	}
}

static zsock_t *request_open(const char *endpoint)
{
	zsock_t *s;
	char *ep;

	s = zsock_new_router(NULL);
	if (s == NULL) {
		err("zsock_new_router(NULL): '%s'", strerror(errno));
		return NULL;
	}

	if (parser_authentication_enabled())
		authentication_enable(s);

	if (zsock_bind(s, "%s", endpoint) < 0) {
		zsock_destroy(&s);
		err("zsock_bind(%s): '%s'", endpoint, strerror(errno));
		return NULL;
	}

	ep = zsock_last_endpoint(s);
	if (ep == NULL) {
		zsock_destroy(&s);
		err("zsock_last_endpoint(): '%s'", strerror(errno));
		return NULL;
	}

	parser_set_endpoint_request_bound(ep);

	if (strncmp(ep, "ipc://", 6) == 0)
		set_perm(ep+6);

	info("request open: %s", ep);
	return s;
}

/*
 * Re-read & process our configuration file. Need to ensure
 * serialization between the vplane message handlers and any adjustment
 * to the configuration. Thus the re-processing is done within this
 * thread.
 */
static void process_reconfigure(zmsg_t *msg, loopargs_t *largs)
{
	char *fname;

	fname = zmsg_popstr(msg);
	if (fname == NULL)
		err("failed to get configuration filename");
	else {
		char *old_endpoint;
		const char *new_endpoint;
		bool old_auth;

		old_endpoint = strdup(parser_endpoint_request());
		old_auth = parser_authentication_enabled();
		if (parser_controller_cfg(fname) < 0)
			panic("failed to parse configuration file: %s",
			      fname);
		new_endpoint = parser_endpoint_request();
		if (!streq(old_endpoint, new_endpoint) ||
		    (old_auth != parser_authentication_enabled())) {
			request_close(largs->loop, &largs->request);
			largs->request = request_open(new_endpoint);
			if (largs->request == NULL) {
				free(old_endpoint);
				free(fname);
				panic("request_open(%s) failed", new_endpoint);
			}
			if (largs->requestor_running)
				request_start(largs);
		}
		free(old_endpoint);
		free(fname);
	}

	zstr_send(largs->pipe, "DONE");
}

zsock_t *request_test_reconfigure(zloop_t *loop, zmsg_t *msg, void *pipe,
				  zsock_t *request)
{
	loopargs_t args;

	args.loop = loop;
	args.pipe = pipe;
	args.snap = NULL;
	args.request = request;
	args.requestor_running = false;
	process_reconfigure(msg, &args);
	return args.request;
}

/* callback from zloop, collects netlink messages from other thread */
static int collector(zloop_t *loop __unused, zsock_t *pipe, void *arg)
{
	loopargs_t *largs = arg;
	snapshot_t *snap = largs->snap;
	zmsg_t *msg = zmsg_recv(pipe);

	if (msg == NULL)
		return 0;

	nlmsg_t *nmsg = NULL;

	char *topic = zmsg_popstr(msg);
	if (topic != NULL) {
		if (streq(topic, "RECONFIGURE"))
			process_reconfigure(msg, largs);
		else if (streq(topic, "SNAPMARK")) {
			/* Snapshot marker, time to send the snapshot now. */
			if (snapshot_req_recv(msg) < 0)
				err("Failed to process snap marker");
		} else if (streq(topic, "$TERM")) {
			free(topic);
			zmsg_destroy(&msg);
			return -1;
		} else
			nmsg = nlmsg_recv(topic, msg);

		free(topic);
	}
	if (nmsg) {
		/*
		 * When snapshot_update returns 1 start listening
		 * for messages from dataplanes.
		 */
		if (snapshot_update(snap, nmsg)) {
			request_start(largs);
			largs->requestor_running = true;
		}
	}

	zmsg_destroy(&msg);
	return 0;
}

/* callback from zloop, timeout any fabric's that have not responded. */
static int check_expired(zloop_t *loop, int timerid __unused,
			 void *arg __unused)
{
	zloop_set_verbose(loop, debug > 1);
	vplane_tick();
	return 0;
}

/* Handle configuration messages in the request thread */
typedef int (config_msg_handler) (const char *topic, zmsg_t *msg, char **json);

struct config_handler {
	const char *topic;
	config_msg_handler *handler;
};

static const struct config_handler config_handlers[] = {
	{.topic = "GETCONFIG", .handler = parser_get_json_config},
	{.topic = "GETVPCONFIG", .handler = vplane_get_json_config},
	{.topic = "GETERRORS", .handler = connect_get_json_errors},
	{.topic = NULL}
};

static int cfg_info_handler(zloop_t *loop __unused, zsock_t *sock,
			    void *arg __unused)
{
	zmsg_t *msg = zmsg_recv(sock);
	char *topic;
	char *json = NULL;
	const struct config_handler *handler;
	int rc;

	if (msg == NULL)
		return 0;

	topic = zmsg_popstr(msg);

	for (handler = &config_handlers[0]; handler->topic; handler++)
		if (strncmp(handler->topic, topic,
			    strlen(handler->topic)) == 0)
			break;

	if (handler->topic == NULL) {
		info("%s: unknown config message", topic);
		free(topic);
		zstr_send(sock, "FAIL: cfg_info_handler not found");
		return 0; /* Ignore and continue */
	}

	rc = handler->handler(topic, msg, &json);
	free(topic);

	/* Send response to client */
	if (rc < 0)
		zstr_send(sock, "FAIL: cfg_info_handler");
	else {
		if (json != NULL) {
			zstr_sendm(sock, "OK");
			zstr_send(sock, json);
			free(json);
		} else
			zstr_send(sock, "OK");
	}

	zmsg_destroy(&msg);
	return 0;
}

static void cfg_info_close(zloop_t *loop, zsock_t **cfg_sock)
{
	if (*cfg_sock != NULL) {
		zloop_reader_end(loop, *cfg_sock);
		zsock_destroy(cfg_sock);
		info("configuration closed");
	}
}

static const char *cfg_info_url = "ipc:///var/run/vyatta/vplaned-config.socket";

/* Create ZMQ socket for request thread configuration messages */
static zsock_t *cfg_info_open(zloop_t *loop)
{
	zsock_t *cfg_sock = zsock_new_rep(cfg_info_url);
	if (!cfg_sock)
		panic("zsock_new_rep(%s): '%s'", cfg_info_url, strerror(errno));

	if (strncmp(cfg_info_url, "ipc://", 6) == 0)
		set_perm(cfg_info_url+6);

	if (zloop_reader(loop, cfg_sock, cfg_info_handler, NULL) < 0)
		panic("zloop_reader(%s): '%s'", cfg_info_url, strerror(errno));

	return cfg_sock;
}

static const char *event_url = "ipc:///var/run/vyatta/vplaned-event.pub";

void request_thread(zsock_t *pipe, void *args __unused)
{
	loopargs_t largs;

	port_init();
	snapshot_t *snap = snapshot_new();

	if (!snap)
		panic("can't allocate snapshot");

	zloop_t *loop = zloop_new();
	if (loop == NULL)
		panic("zloop_new failed");

	/* only turn on debug if really interested */
	zloop_set_verbose(loop, debug > 1);

	/* increase size of receive buffer */
	zsock_set_rcvhwm(pipe, 32768);

	largs.loop = loop;
	largs.snap = snap;
	largs.pipe = pipe;
	largs.event_pub = zsock_new_pub(event_url);
	if (largs.event_pub == NULL)
		panic("Failed to open event pub socket");
	set_perm(event_url+6);
	largs.request = request_open(parser_endpoint_request());
	largs.requestor_running = false;

	/* Set up and listen on config socket */
	zsock_t *cfgsock = cfg_info_open(loop);

	/* Requests from publisher thread  */
	if (zloop_reader(loop, pipe, collector, &largs) < 0)
		panic("zloop_reader(collector): '%s'", strerror(errno));

	/* Timer for vplane instances */
	int timerid = zloop_timer(loop, 1000, 0, check_expired, NULL);

	if (timerid < 0)
		panic("zloop_timer: '%s'", strerror(errno));

	snapshot_req_timeout_init(loop);

	/* Tell publisher thread we are ready */
	zsock_signal(pipe, 0);

	zloop_start(loop);

	zloop_timer_end(loop, timerid);
	cfg_info_close(loop, &cfgsock);
	zsock_destroy(&largs.event_pub);
	request_close(loop, &largs.request);

	zloop_destroy(&loop);
	snapshot_destroy(&snap);
	vplane_disconnect_all();
	port_destroy();
	connect_error_clear();
}
