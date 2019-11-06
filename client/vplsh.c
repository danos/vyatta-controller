/*
 * Dataplane console
 *
 * Virtual dataplane console modelled after vtysh in Quagga.
 *
 * Copyright (c) 2017,2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include <termios.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>

#include <histedit.h>
#include <sys/fcntl.h>
#include <czmq.h>

#include "vplaned.h"

#define HIST_MAX 100
#define VPLANED_TIMEOUT (5 * 1000)

static const char *progname;
static unsigned timeout_ms = 10 * 1000;
static const char local_ipc[]  = "ipc:///var/run/vplane.socket";
static const char vplane_ipc[]  = "ipc:///var/run/vyatta/vplaned.socket";

static const char version[] = "vPlane console v1.0\n";
static const char copyright[]
	= "Copyright (c) 2012-2016 by Brocade Communications Systems, Inc.";
static int debug;

static const char *prompt(EditLine *e __attribute__((unused)))
{
	return "vplsh# ";
}

static void die(const char *reason)
{
	fprintf(stderr, "%s failed: %s\n", reason, strerror(errno));
	exit(1);
}


/* Remove any leading/trailing whitespace */
static void chomp(char *buf)
{
	/* remove newline */
	char *cp = strchr(buf, '\n');
	if (cp)
		*cp = '\0';

	/* remove text after comment character */
	cp = strchr(buf, '#');
	if (cp)
		*cp = '\0';
}

/*
 * Command request (un)protocol:
 *   Send:
 *     [0] Dataplane command string
 *   Response:
 *     [0] ACK (or ERROR)
 *     [1] Response information (optional)
 */
static int execute(zsock_t *sock, const char *cmd)
{
	/* ignore blank lines */
	if (*cmd == '\0')
		return 0;

	if (zstr_send(sock, cmd) < 0)
		die("send request");

	zsock_set_rcvtimeo(sock, timeout_ms);

	zmsg_t *resp = zmsg_recv(sock);
	if (resp == NULL) {
		fprintf(stderr, "no response from server\n");
		return -1;
	}

	if (debug)
		zmsg_dump(resp);

	char *status = zmsg_popstr(resp);
	if (!status) {
		fprintf(stderr, "missing status in response\n");
		return -1;
	}

	int ret = (strcmp(status, "OK") == 0) ? 0 : -1;
	free(status);

	zframe_t *fr = zmsg_first(resp);
	if (fr && zframe_size(fr) > 0) {
		/* per convention if there is an error, print message
		   on standard error, otherwise standard out */
		FILE *out = (ret == 0) ? stdout : stderr;

		if (fwrite(zframe_data(fr), zframe_size(fr), 1, out) > 0)
			fputc('\n', out);
	}
	zmsg_destroy(&resp);
	return ret;
}

/* Read commands form a file */
static void batch(zsock_t *sock)
{
	char buf[BUFSIZ];

	while (!zsys_interrupted) {
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			break;

		chomp(buf);

		if (execute(sock, buf) < 0)
			break;
	}
}

/* Read commands from terminal with line editing */
static void interactive(zsock_t *sock)
{
	EditLine *el = el_init(progname, stdin, stdout, stderr);

	if (!el)
		die("edit line init");

	el_set(el, EL_PROMPT, &prompt);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_SIGNAL, 1);

	History *hist = history_init();
	if (!hist)
		die("history init");

	HistEvent ev;
	history(hist, &ev, H_SETSIZE, HIST_MAX);
	el_set(el, EL_HIST, history, hist);

	printf("%s\n", version);

	int count;
	const char *line;
	while (!zsys_interrupted &&
	       (line = el_gets(el, &count)) != NULL) {

		char *buf = strdupa(line);
		chomp(buf);

		if (streq(buf, "exit"))
			break;

		execute(sock, buf);

		history(hist, &ev, H_ENTER, line);
	}

	history_end(hist);
	el_end(el);
}

static int shell_mode(zsock_t *sock)
{
	if (isatty(fileno(stdin)))
		interactive(sock);
	else
		batch(sock);

	return 0;
}

static int cmd_mode(zsock_t *sock, zlist_t *cmd_list)
{
	char *c;

	c = zlist_first(cmd_list);
	while (!zsys_interrupted && c) {
		if (execute(sock, c) < 0)
			return EXIT_FAILURE;
		c = zlist_next(cmd_list);
	}

	return 0;
}

static char *get_publish_url(void)
{
	zsock_t *sock = vplaned_connect();
	char *url = NULL;
	int rc;

	if (sock == NULL) {
		fprintf(stderr, "vplaned connect failed\n");
		return NULL;
	}

	rc = vplaned_request_config(sock);
	if (rc < 0)
		fprintf(stderr,	"vplaned request failed: '%s'\n",
			strerror(-rc));
	else
		url = vplaned_ctrl_get_publish_url(sock, VPLANED_TIMEOUT);

	vplaned_disconnect(&sock);
	return url;
}

static void monitor_mode()
{
	zsock_t *subscriber;
	char *endpoint;

	endpoint = get_publish_url();
	if (endpoint == NULL) {
		fprintf(stderr,
			"controller publish URL not found\n");
		exit(EXIT_FAILURE);
	}

	subscriber = zsock_new_sub(endpoint, "");
	if (!subscriber) {
		fprintf(stderr, "zsock_new_sub(%s, \"\") failed\n", endpoint);
		exit(EXIT_FAILURE);
	}

	printf("Listening to %s\n", endpoint);
	fflush(stdout);

	zmsg_t *zmsg;
	while ((zmsg = zmsg_recv(subscriber)) != NULL) {
		zmsg_dump(zmsg);
		zmsg_destroy(&zmsg);
		fflush(stdout);
	}
	zsock_destroy(&subscriber);
	free(endpoint);
	exit(0);
}

static void fabric_connect(const char *endpoint, zlist_t *cmds)
{
	int ret;

	/*
	 * Special case for internal endpoint.
	 * Normal ZMQ will keep retrying if file does not exist
	 * or incorrect permissions.
	 */
	if (strncmp(endpoint, "ipc://", 6) == 0) {
		const char *path = endpoint + 6;

		if (access(path, W_OK|R_OK) < 0) {
			fprintf(stderr, "%s: %s\n",
				path, strerror(errno));
			exit(1);
		}
	}

	zsys_set_ipv6(1);

	if (debug)
		printf("Connecting to %s\n", endpoint);

	zsock_t *client = zsock_new_req(endpoint);
	if (!client)
		die("zsock_new_req connect");

	if (zlist_size(cmds) > 0)
		ret = cmd_mode(client, cmds);
	else
		ret = shell_mode(client);

	zsock_destroy(&client);
	if (ret == EXIT_FAILURE)
		exit(EXIT_FAILURE);
}

static zsock_t *vplaned_request(void)
{
	zsock_t *sock = vplaned_connect();
	int rc;

	if (sock == NULL) {
		fprintf(stderr, "vplaned connect failed\n");
		return NULL;
	}

	rc = vplaned_request_dataplane(sock);
	if (rc < 0)
		fprintf(stderr,	"vplaned request failed: '%s'\n",
			strerror(-rc));

	return sock;
}

static char *get_vplane_url(int dpid)
{
	zsock_t *sock = vplaned_request();
	char *url = NULL;
	struct vplaned_dataplane *dp = NULL;

	if ((sock != NULL)  &&
	    (vplaned_dp_get(sock, VPLANED_TIMEOUT, dpid, &dp) == 0) &&
	    (dp != NULL))
		url = strdup(vplaned_dp_console(dp));

	vplaned_dp_destroy(&dp);
	vplaned_disconnect(&sock);
	return url;
}

static void get_vplane_list(zlist_t *list)
{
	zsock_t *sock = vplaned_request();

	if (sock != NULL)
		vplaned_dp_get_list(sock, VPLANED_TIMEOUT, true, list);

	vplaned_disconnect(&sock);
}

static struct option longopts[] = {
	{ "version",	no_argument,	   NULL, 'V' },
	{ "debug",	no_argument,	   NULL, 'd' },
	{ "help",	no_argument,       NULL, 'h' },
	{ "timeout",    required_argument, NULL, 't' },
	{ "command",    required_argument, NULL, 'c' },
	{ "local",	no_argument,	   NULL, 'l' },
	{ "fabric",	required_argument, NULL, 'f' },
	{ "socket",     required_argument, NULL, 's' },
	{ "monitor",	no_argument,	   NULL, 'm' },
	{ "identify",	no_argument,	   NULL, 'i' },
	{ NULL, 0, NULL, 0 }
};

static void usage(void)
{
	printf("Usage: %s [OPTION...]\n\n"
	       "Shell for vPlane control.\n\n"
	       "-c, --command     Execute argument as command\n"
	       "-d, --debug       Debug interaction with controller\n"
	       "-s, --socket      Socket to controller\n"
	       "                  (default %s)\n"
	       "-l, --local	  Communicate with local dataplane\n"
	       "                  (equivalent to '--identify --fabric all'\n"
	       "                   if there is no local dataplane)\n"
	       "-m, --monitor	  Observe communication from controller\n"
	       "-f, --fabric      Fabric to communicate with (or 'all')\n"
	       "-i, --identify    Display fabric ID with multiple fabrics\n"
	       "-h, --help        Display help and exit\n\n"
	       "Command maybe repeated multiple times\n",
	       progname, vplane_ipc);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *p;
	int fabric = -1;
	const char *endpoint = NULL;
	int local = 0, monitor = 0, all = 0, identify = 0;
	int flag;

	/* Preserve name of myself. */
	p = strrchr(argv[0], '/');
	progname = (p ? ++p : argv[0]);

	zlist_t *cmds = zlist_new();
	if (!cmds)
		die("zlist new");
	zlist_autofree(cmds);

	while ((flag = getopt_long(argc, argv, "Vdlmif:t:s:c:",
				   longopts, 0)) != EOF) {
		switch (flag) {
		case 'd':
			++debug;
			break;
		case 'l':
			++local;
			break;
		case 'm':
			++monitor;
			break;
		case 'i':
			++identify;
			break;
		case 'f':
			if (strcmp(optarg, "all") == 0)
				++all;
			else
				fabric = strtoul(optarg, NULL, 0);
			break;
		case 't':
			timeout_ms = strtoul(optarg, NULL, 0);
			break;
		case 's':
			endpoint = optarg;
			break;
		case 'c':
			zlist_append(cmds, optarg);
			break;
		case 'V':
			printf("%s\n%s\n", version, copyright);
			exit(0);
		default:
			usage();
		}
	}

	/* Can only accept one direction */
	if (all + (fabric != -1) + (endpoint != NULL) + local > 1) {
		fprintf(stderr,
			"--fabric , --local, --socket options conflict\n");
		usage();
	}

	if (monitor)
		monitor_mode();

	if (local && (access(local_ipc + 6, W_OK|R_OK) < 0)) {
		local = 0;
		all++;
		identify++;
	}

	if (all) {
		zlist_t *endpoints = zlist_new();
		struct vplaned_dataplane *vp;

		if (endpoints != NULL) {
			get_vplane_list(endpoints);
			if (identify && !zlist_size(endpoints))
				fprintf(stderr, "no dataplane connected\n");
			while ((vp = zlist_pop(endpoints))) {
				if (identify)
					printf("\nvplane %d:\n\n",
					       vplaned_dp_id(vp));
				fabric_connect(vplaned_dp_console(vp), cmds);
				vplaned_dp_destroy(&vp);
			}
			zlist_destroy(&endpoints);
		}
	} else if (local)
		endpoint = local_ipc;	/* local dataplane */
	else if (fabric != -1) {
		endpoint = get_vplane_url(fabric);
		if (endpoint == NULL) {
			fprintf(stderr, "dataplane fabric %d URL not found\n",
				fabric);
			exit(EXIT_FAILURE);
		}
	} else if (!endpoint)
		endpoint = vplane_ipc;	/* local controller */

	if (endpoint != NULL)
		fabric_connect(endpoint, cmds);

	zlist_destroy(&cmds);

	return 0;
}
