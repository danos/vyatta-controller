/*
 * Basic standalone test
 */
#include <stdio.h>
#include <getopt.h>
#include <netinet/ether.h>

#include <ini.h>
#include <czmq.h>

static const char *cfgfile = "/etc/vyatta/dataplane.conf";
static const char *local_addr = "127.0.0.1";
static const char *ether_addr = "00:11:22:33:44:55";
static uint32_t key = 0;
static char *endpoint;
static char *identity;

static void die(const char *str)
{
	perror(str);
	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "testclient [-i id] [-k key] [-f config] [-l local_ip]\n");
	exit(1);
}


static void check(zsock_t *socket)
{
	zmsg_t *msg = zmsg_recv(socket);

	if (!msg)
		die("zmsg_recv");

	zmsg_dump(msg);
	char *answer = zmsg_popstr(msg);
	printf("I: %s\n", answer);

	if (!streq(answer, "OK")) {
		fprintf(stderr, "E: %s\n", answer);
		exit(1);
	}

	zmsg_destroy(&msg);
}

static int parse_entry(void *user, const char *section,
		       const char *name, const char *value)
{
	if (strcasecmp("controller", section) == 0) {
		if (streq("broker", name))
			endpoint = strdup(value);
	} else if (strcasecmp("dataplane", section) == 0) {
		if (streq("uuid", name))
			identity = strdup(value);
	}

	return 1;
}

/* Load config file and do sanity checks */
static void parse_cfg_file(void)
{
	FILE *f = fopen(cfgfile, "r");
	if (f == NULL) {
		perror(cfgfile);
		exit(EXIT_FAILURE);
	}

	int rc = ini_parse_file(f, parse_entry, NULL);
	if (rc) {
		fprintf(stderr, "Config file format error %s line %d\n", cfgfile, rc);
		exit(EXIT_FAILURE);
	}

	fclose(f);
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "f:l:e:k:")) != -1)
		switch(opt) {
		case 'f': cfgfile = optarg; break;
		case 'k': key = atoi(optarg); break;
		case 'l': local_addr = optarg; break;
		case 'e': ether_addr = optarg; break;
		default:
			usage();
		}

	parse_cfg_file();

	if (!identity) {
		fprintf(stderr, "can't find uuid\n");
		exit(1);
	}

	in_addr_t laddr = inet_addr(local_addr);
	if (laddr == 0) {
		fprintf(stderr, "bad local address\n");
		exit(1);
	}

	struct ether_addr *eth = ether_aton(ether_addr);
	if (!eth) {
		fprintf(stderr, "bad ether address\n");
		exit(1);
	}

	zsock_t *client = zsock_new(ZMQ_REQ);
	if (!client)
		die("zsock_new");

	zsock_set_identity(client, identity);

	printf ("I: connecting to server at %s...\n", endpoint);
	if (zsock_connect(client, endpoint) < 0)
		die("zsock_connect");

	zmsg_t *msg = zmsg_new();

	zmsg_addmem(msg, &key, sizeof(key));
	zmsg_addstr(msg, "CREATE");
	zmsg_addstr(msg, "p4p1");
	zmsg_addmem(msg, &laddr, sizeof(laddr));
	zmsg_addmem(msg, eth, sizeof(struct ether_addr));

	printf("I: sending create\n");
	zmsg_dump(msg);
	zmsg_send(&msg, client);

	check(client);

	msg = zmsg_new();
	zmsg_addmem(msg, &key, sizeof(key));
	zmsg_addstr(msg, "UP");
	printf("I: sending up\n");
	zmsg_dump(msg);
	zmsg_send(&msg, client);
	check(client);

	msg = zmsg_new();
	zmsg_addmem(msg, &key, sizeof(key));
	zmsg_addstr(msg, "DOWN");
	printf("I: sending down\n");
	zmsg_dump(msg);
	zmsg_send(&msg, client);
	check(client);

	zsock_destroy(&client);

	return 0;
}
