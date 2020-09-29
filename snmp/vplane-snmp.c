/*
 * Dataplane SNMP Helper
 *
 * Collect SNMP run-time statistics from dataplane
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <argz.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#include <czmq.h>
#include <json.h>

#include "vplaned.h"

#define DUMPSTATS
#undef DUMPSTATS

#define COUNTER32_MASK (0xffffffffU)

static const char *progname;
static const char version[] = "Vyatta Vplane SNMP Utility v0.1";
static const char copyright[] = "Copyright (C) 2013 Vyatta, Inc.";
static const char cmd_snmp_4[] = "snmp -4";
static const char cmd_snmp_6[] = "snmp -6";

#define TABLE_IDX_MIN (3)    /* MIB idx for ipSystemStatsInReceives*/
#define TABLE_IDX_MAX (47)   /* MIB idx for ipSystemStatsRefreshRate */
#define TABLE_PROTO_MIN (1)  /* IPv4 */
#define TABLE_PROTO_MAX (2)  /* IPv6 */
static const char oid_base[] = ".1.3.6.1.2.1.4.31.1.1";


static int debug;
static unsigned timeout_ms = 10 * 1000;

/* The order here should match the SNMP OID order so that mapping
 * from the OID to the stat id is trivial.
 */
typedef enum {
	STATS_INRECEIVES,
	STATS_HCINRECEIVES,
	STATS_INOCTETS,
	STATS_HCINOCTETS,
	STATS_INHDRERRORS,
	STATS_INNOROUTES,
	STATS_INADDRERRORS,
	STATS_INUNKNOWNPROTOS,
	STATS_INTRUNCATEDPKTS,
	STATS_INFORWDATAGRAMS,
	STATS_HCINFORWDATAGRAMS,     /* 10 */
	STATS_REASMREQDS,
	STATS_REASMOKS,
	STATS_REASMFAILS,
	STATS_INDISCARDS,
	STATS_INDELIVERS,
	STATS_HCINDELIVERS,
	STATS_OUTREQUESTS,
	STATS_HCOUTREQUESTS,
	STATS_OUTNOROUTES,
	STATS_OUTFORWDATAGRAMS,     /* 20 */
	STATS_HCOUTFORWDATAGRAMS,
	STATS_OUTDISCARDS,
	STATS_OUTFRAGREQDS,
	STATS_OUTFRAGOKS,
	STATS_OUTFRAGFAILS,
	STATS_OUTFRAGCREATES,
	STATS_OUTTRANSMITS,
	STATS_HCOUTTRANSMITS,
	STATS_OUTOCTETS,
	STATS_HCOUTOCTETS,          /* 30 */
	STATS_INMCASTPKTS,
	STATS_HCINMCASTPKTS,
	STATS_INMCASTOCTETS,
	STATS_HCINMCASTOCTETS,
	STATS_OUTMCASTPKTS,
	STATS_HCOUTMCASTPKTS,
	STATS_OUTMCASTOCTETS,
	STATS_HCOUTMCASTOCTETS,
	STATS_INBCASTPKTS,
	STATS_HCINBCASTPKTS,        /* 40 */
	STATS_OUTBCASTPKTS,
	STATS_HCOUTBCASTPKTS,
	STATS_DISCONTINUITYTIME,
	STATS_REFRESHRATE,
	STATS_LAST_ID
} mib_stat_id;


enum {
/* Stat ids for /proc/net/snmp */
	SNMP_HCINRECEIVES = 0,
	SNMP_INHDRERRORS,
	SNMP_INADDRERRORS,
	SNMP_HCOUTFORWDATAGRAMS,
	SNMP_INUNKNOWNPROTOS,
	SNMP_INDISCARDS,
	SNMP_HCINDELIVERS,
	SNMP_HCOUTREQUESTS,
	SNMP_OUTDISCARDS,
	SNMP_OUTNOROUTES,
	SNMP_REASMREQDS,
	SNMP_REASMOKS,
	SNMP_REASMFAILS,
	SNMP_OUTFRAGOKS,
	SNMP_OUTFRAGFAILS,
	SNMP_OUTFRAGCREATES,
	SNMP_LAST_ID,

/* Stat ids for /proc/net/netstat */
	NETSTAT_INNOROUTES = 0,
	NETSTAT_INTRANCATEDPKTS,
	NETSTAT_HCINMCASTPKTS,
	NETSTAT_HCOUTMCASTPKTS,
	NETSTAT_HCINBCASTPKTS,
	NETSTAT_HCOUTBCASTPKTS,
	NETSTAT_HCINOCTETS,
	NETSTAT_HCOUTOCTETS,
	NETSTAT_HCINMCASTOCTEST,
	NETSTAT_HCOUTMCASTOCTEST,
	NETSTAT_LAST_ID,

/* Stat type */
	COUNTER32 = 0,
	COUNTER64,
	TIMETICKS,
	GUAGE32,
};

/* Though some stats are 32-bit, we'll keep 64-bit values */
struct counter
{
	int type; /* COUNTER32, COUNTER64 */
	uint64_t stat;
};

#define STAT_COUNTER32()  { .type = COUNTER32, }
#define STAT_COUNTER64()  { .type = COUNTER64, }
#define STAT_TIMETICKS()  { .type = TIMETICKS, }
#define STAT_GUAGE32()    { .type = GUAGE32, }
static struct counter stat_table[STATS_LAST_ID] = {
	[STATS_INRECEIVES] = STAT_COUNTER32(),
	[STATS_HCINRECEIVES] = STAT_COUNTER64(),
	[STATS_INOCTETS] = STAT_COUNTER32(),
	[STATS_HCINOCTETS] = STAT_COUNTER64(),
	[STATS_INHDRERRORS] = STAT_COUNTER32(),
	[STATS_INNOROUTES] = STAT_COUNTER32(),
	[STATS_INADDRERRORS] = STAT_COUNTER32(),
	[STATS_INUNKNOWNPROTOS] = STAT_COUNTER32(),
	[STATS_INTRUNCATEDPKTS] = STAT_COUNTER32(),
	[STATS_INFORWDATAGRAMS] = STAT_COUNTER32(),
	[STATS_HCINFORWDATAGRAMS] = STAT_COUNTER64(),
	[STATS_REASMREQDS] = STAT_COUNTER32(),
	[STATS_REASMOKS] = STAT_COUNTER32(),
	[STATS_REASMFAILS] = STAT_COUNTER32(),
	[STATS_INDISCARDS] = STAT_COUNTER32(),
	[STATS_INDELIVERS] = STAT_COUNTER32(),
	[STATS_HCINDELIVERS] = STAT_COUNTER64(),
	[STATS_OUTREQUESTS] = STAT_COUNTER32(),
	[STATS_HCOUTREQUESTS] = STAT_COUNTER64(),
	[STATS_OUTNOROUTES] = STAT_COUNTER32(),
	[STATS_OUTFORWDATAGRAMS] = STAT_COUNTER32(),
	[STATS_HCOUTFORWDATAGRAMS] = STAT_COUNTER64(),
	[STATS_OUTDISCARDS] = STAT_COUNTER32(),
	[STATS_OUTFRAGREQDS] = STAT_COUNTER32(),
	[STATS_OUTFRAGOKS] = STAT_COUNTER32(),
	[STATS_OUTFRAGFAILS] = STAT_COUNTER32(),
	[STATS_OUTFRAGCREATES] = STAT_COUNTER32(),
	[STATS_OUTTRANSMITS] = STAT_COUNTER32(),
	[STATS_HCOUTTRANSMITS] = STAT_COUNTER64(),
	[STATS_OUTOCTETS] = STAT_COUNTER32(),
	[STATS_HCOUTOCTETS] = STAT_COUNTER64(),
	[STATS_INMCASTPKTS] = STAT_COUNTER32(),
	[STATS_HCINMCASTPKTS] = STAT_COUNTER64(),
	[STATS_INMCASTOCTETS] = STAT_COUNTER32(),
	[STATS_HCINMCASTOCTETS] = STAT_COUNTER64(),
	[STATS_OUTMCASTPKTS] = STAT_COUNTER32(),
	[STATS_HCOUTMCASTPKTS] = STAT_COUNTER64(),
	[STATS_OUTMCASTOCTETS] = STAT_COUNTER32(),
	[STATS_HCOUTMCASTOCTETS] = STAT_COUNTER64(),
	[STATS_INBCASTPKTS] = STAT_COUNTER32(),
	[STATS_HCINBCASTPKTS] = STAT_COUNTER64(),
	[STATS_OUTBCASTPKTS] = STAT_COUNTER32(),
	[STATS_HCOUTBCASTPKTS] = STAT_COUNTER64(),
	[STATS_DISCONTINUITYTIME] = STAT_TIMETICKS(),
	[STATS_REFRESHRATE] = STAT_GUAGE32(),
};


static void msg_syslog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_NOTICE, fmt, ap);
	va_end(ap);
}


static void msg_stderr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define dbgmsg(x, ...) if (debug) msg_syslog(x, ##__VA_ARGS__)
#define dbgmsg1(x, ...) if (debug > 1) msg_syslog(x, ##__VA_ARGS__)
#define dbgmsg2(x, ...) if (debug > 2) msg_syslog(x, ##__VA_ARGS__)

static void die(const char *reason)
{
	int local_errno = errno;
	msg_syslog("%s failed: %s", reason, strerror(local_errno));
	msg_stderr("%s failed: %s", reason, strerror(local_errno));
	exit(1);
}

static uint64_t get_stat(int stat_id)
{
	return stat_table[stat_id].stat;
}


static void add_stat(int stat_id, uint64_t val)
{
	stat_table[stat_id].stat += val;
}

/* See man snmpd.conf for format of reporting oid values */
static void print_stat(const char *oid, int stat_id)
{
	static const char fmt32[] = "%" PRIu32 "\n";
	static const char fmt64[] = "%" PRIu64 "\n";

	if ((stat_id < 0) || (stat_id >= STATS_LAST_ID))
		return;

	switch (stat_table[stat_id].type) {
		case COUNTER32:
			printf("%s\nCounter32\n", oid);
			printf(fmt32, (uint32_t)(stat_table[stat_id].stat & COUNTER32_MASK));
			break;
		case COUNTER64:
			printf("%s\nCounter64\n", oid);
			printf(fmt64, stat_table[stat_id].stat);
			break;
		default:
			msg_stderr("%s: unknown stat type %d", __func__, stat_table[stat_id].type);
			break;
	}
}

/* Debugging aid */
#ifdef DUMPSTATS
static void dump_stats(void)
{
	int id;
	for (id = 0; id < STATS_LAST_ID; ++id)
		msg_syslog("%s: %d %llu", __func__, id, stat_table[id].stat);
}
#else
#define dump_stats()
#endif

/*
 * Some stats are calculated from others.
 */
#define SET_C32_FROM_C64(x) add_stat(STATS_##x, get_stat(STATS_HC##x))
static void calc_stats(void)
{
	add_stat(STATS_HCINFORWDATAGRAMS, get_stat(STATS_INNOROUTES) +
		 get_stat(STATS_HCOUTFORWDATAGRAMS));
	add_stat(STATS_HCOUTTRANSMITS, get_stat(STATS_OUTFRAGOKS) +
		 get_stat(STATS_OUTFRAGFAILS));
	add_stat(STATS_OUTFRAGREQDS, get_stat(STATS_HCOUTREQUESTS) +
		 get_stat(STATS_HCOUTFORWDATAGRAMS) + get_stat(STATS_OUTFRAGCREATES));
	SET_C32_FROM_C64(INRECEIVES);
	SET_C32_FROM_C64(INOCTETS);
	SET_C32_FROM_C64(INFORWDATAGRAMS);
	SET_C32_FROM_C64(INDELIVERS);
	SET_C32_FROM_C64(OUTREQUESTS);
	SET_C32_FROM_C64(OUTFORWDATAGRAMS);
	SET_C32_FROM_C64(OUTTRANSMITS);
	SET_C32_FROM_C64(OUTOCTETS);
	SET_C32_FROM_C64(INMCASTPKTS);
	SET_C32_FROM_C64(INMCASTOCTETS);
	SET_C32_FROM_C64(OUTMCASTPKTS);
	SET_C32_FROM_C64(OUTMCASTOCTETS);
	SET_C32_FROM_C64(INBCASTPKTS);
	SET_C32_FROM_C64(OUTBCASTPKTS);
}


/* Determine the value index from the OID
 *
 * Return:
 *  value index on success; -1 otherwise
 */
static int get_stat_idx(const char *oid)
{
	char *dot;
	char *oid_copy = strdupa(oid);
	int id;

	if (!oid_copy) {
		errno = ENOMEM;
		return -1;
	}

	dot = strrchr(oid_copy, '.');
	if (!dot) {
		errno = EINVAL;
		return -1;
	}

	*dot = '\0';
	dot = strrchr(oid_copy, '.');
	if (!dot) {
		errno = EINVAL;
		return -1;
	}

	id = atoi(++dot);
	dbgmsg2("%s: oid %s has idx %d", __func__, oid, id);
	return id;
}


/* Determine if OID is in ipSystemStatsTable */
static int in_sysstatstable(const char *oid)
{
	const char *dot;
	int dots = 0;
	int idx;

	dbgmsg2("%s: Checking oid %s", __func__, oid);
	if (strncmp(oid, oid_base, sizeof(oid_base) - 1) != 0)
		return 0;

	/* This is the table oid exactly, used in GETNEXT */
	if (oid[sizeof(oid_base)] == '\0')
		return 1;

	dot = oid + sizeof(oid_base) - 1;
	dbgmsg2("%s: Checking oid remainder %s", __func__, dot);
	while ((dot = strchr(dot, '.')) != NULL) {
		++dot;
		++dots;
	}

	dbgmsg2("%s: ...oid has %d dots", __func__, dots);
	if (dots != 2)
		return 0;

	idx = get_stat_idx(oid);
	return ((idx >= TABLE_IDX_MIN) && (idx <= TABLE_IDX_MAX));
}


static int get_in_stat_id(const char *name)
{
	switch (name[0]) {
		case 'A':
			return STATS_INADDRERRORS;
		case 'B':
			if (name[sizeof("Bcast") - 1] == 'P')
				return STATS_HCINBCASTPKTS;
			break;
		case 'D':
			switch (name[1]) {
				case 'e':
					return STATS_HCINDELIVERS;
				case 'i':
					return STATS_INDISCARDS;
				default:
					break;
			}
			break;
		case 'F':
			return STATS_HCINFORWDATAGRAMS;
		case 'H':
			return STATS_INHDRERRORS;
		case 'M':
			switch (name[sizeof("Mcast") - 1]) {
				case 'O':
					return STATS_HCINMCASTOCTETS;
				case 'P':
					return STATS_HCINMCASTPKTS;
				default:
					break;
			}
			break;
		case 'N':
			return STATS_INNOROUTES;
		case 'O':
			return STATS_HCINOCTETS;
		case 'R':
			return STATS_HCINRECEIVES;
		case 'T':
			if (name[1] == 'r')
				return STATS_INTRUNCATEDPKTS;
			break;
		case 'U':
			return STATS_INUNKNOWNPROTOS;
		default:
			break;
	}
	return -1;
}

static int get_out_stat_id(const char *name)
{
	switch (name[0]) {
		case 'B':
			if (name[sizeof("Bcast") - 1] == 'P')
				return STATS_HCOUTBCASTPKTS;
			break;
		case 'D':
			return STATS_OUTDISCARDS;
		case 'F':
			switch (name[1]) {
				case 'o':
					return STATS_HCOUTFORWDATAGRAMS;
				case 'r':
				default:
					break;
			}
			break;
		case 'M':
			switch (name[sizeof("Mcast") - 1]) {
				case 'O':
					return STATS_HCOUTMCASTOCTETS;
				case 'P':
					return STATS_HCOUTMCASTPKTS;
				default:
					break;
			}
			break;
		case 'N':
			return STATS_OUTNOROUTES;
		case 'O':
			return STATS_HCOUTOCTETS;
		case 'R':
			return STATS_HCOUTREQUESTS;
		case 'T':
			return STATS_HCOUTTRANSMITS;

		default:
			break;
	}
	return -1;
}

/* Convert stat name to stat id
 *
 * This is a bit of a pachinko machine that only looks at specific
 * characters in the name instead of comparing the entire name.
 *
 * Note: any static prefix must be removed (e.g, "Ip6").
 */
static int get_stat_id_by_name(const char *stat)
{
	if (!stat) {
		errno = EFAULT;
		return -1;
	}
	dbgmsg2("%s: processing stat %s", __func__, stat);

	switch (stat[0]) {
		case 'F': /* Frag */
			switch (stat[sizeof("Frag") - 1]) {
				case 'F':
					return STATS_OUTFRAGFAILS;
				case 'O':
					return STATS_OUTFRAGOKS;
				case 'R':
					return STATS_OUTFRAGREQDS;
				default:
					break;
			}
			break;
		case 'I': /* In */
			return get_in_stat_id(stat + sizeof("In") - 1);
		case 'O': /* Out */
			return get_out_stat_id(stat + sizeof("Out") - 1);
		case 'R': /* Reasm */
			switch (stat[sizeof("Reasm") - 1]) {
				case 'R':
					return STATS_REASMREQDS;
				case 'O':
					return STATS_REASMOKS;
				case 'F':
					return STATS_REASMFAILS;
				default:
					break;
			}
			break;
		default:
			break;
	}
	return -1; /* Unrecognized name */
}

/* Determine the value id from the OID
 *
 * Return:
 *  value id on success; -1 otherwise
 */
static int get_stat_id_by_oid(const char *oid)
{
	int id = get_stat_idx(oid);
	if (id != -1)
		id -= TABLE_IDX_MIN;
	dbgmsg2("%s: oid %s has id %d", __func__, oid, id);
	return id;
}

/* Determine the protocol from the OID
 *
 * Return:
 *  1 = ipv4
 *  2 = ipv6
 * -1 = Unknown
 */
static int get_protocol(const char *oid)
{
	char *dot;

	dot = strrchr(oid, '.');
	if (dot && isdigit(*(++dot))) {
		switch (*dot) {
			case '1':
			case '2':
				return (*dot - '0');
			default:
				return -1;
		}
	}
	return -1;
}


/* Assumes the first 2 lines of /proc/net/snmp are the IP info.
 * This assumption is valid since the this file is part of the kernel
 * user API.
 */
static int get_snmp_stats(void)
{
	FILE *fp;
	char line[1024]; /* must be big enough; 1k should be plenty */
	static const char snmp_file[] = "/proc/net/snmp";
	int len;
	unsigned long long int tmpvals[SNMP_LAST_ID];

	fp = fopen(snmp_file, "r");
	if (!fp)
		return -1;

	/* Skip the header line and read the data values */
	for (len = 0; len < 2; ++len) {
		if (!fgets(line, sizeof(line), fp)) {
			msg_stderr("Unable to read values from %s", snmp_file);
			fclose(fp);
			return -1;
		}
	}
	fclose(fp);

	/* All kernel reported values are 64-bit
	 * Scan directly into the 64-bit counters and into temp
	 * locations for the 32-bit counters.
	 */
        len = sscanf(line, /* skip "IP:" prefix and first 2 values */
		     "%*s %*s %*s %llu %llu %llu %llu"
		     " %llu %llu %llu %llu %llu"
		     " %llu %*s %llu %llu %llu %llu"
		     " %llu %llu",
		     &tmpvals[SNMP_HCINRECEIVES],
		     &tmpvals[SNMP_INHDRERRORS],
		     &tmpvals[SNMP_INADDRERRORS],
		     &tmpvals[SNMP_HCOUTFORWDATAGRAMS],
		     &tmpvals[SNMP_INUNKNOWNPROTOS],
		     &tmpvals[SNMP_INDISCARDS],
		     &tmpvals[SNMP_HCINDELIVERS],
		     &tmpvals[SNMP_HCOUTREQUESTS],
		     &tmpvals[SNMP_OUTDISCARDS],
		     &tmpvals[SNMP_OUTNOROUTES],
		     &tmpvals[SNMP_REASMREQDS],
		     &tmpvals[SNMP_REASMOKS],
		     &tmpvals[SNMP_REASMFAILS],
		     &tmpvals[SNMP_OUTFRAGOKS],
		     &tmpvals[SNMP_OUTFRAGFAILS],
		     &tmpvals[SNMP_OUTFRAGCREATES]);
	/* ok, so I'm paranoid */
        if (len != SNMP_LAST_ID) {
		msg_stderr("Unexpected number of values (expected %d, got %d)\n",
			   SNMP_LAST_ID, len);
		return -1;
        }

	add_stat(STATS_HCINRECEIVES, tmpvals[SNMP_HCINRECEIVES]);
	add_stat(STATS_INHDRERRORS, tmpvals[SNMP_INHDRERRORS]);
	add_stat(STATS_INADDRERRORS, tmpvals[SNMP_INADDRERRORS]);
	add_stat(STATS_HCOUTFORWDATAGRAMS, tmpvals[SNMP_HCOUTFORWDATAGRAMS]);
	add_stat(STATS_INUNKNOWNPROTOS, tmpvals[SNMP_INUNKNOWNPROTOS]);
	add_stat(STATS_INDISCARDS, tmpvals[SNMP_INDISCARDS]);
	add_stat(STATS_HCINDELIVERS, tmpvals[SNMP_HCINDELIVERS]);
	add_stat(STATS_HCOUTREQUESTS, tmpvals[SNMP_HCOUTREQUESTS]);
	add_stat(STATS_OUTDISCARDS, tmpvals[SNMP_OUTDISCARDS]);
	add_stat(STATS_OUTNOROUTES, tmpvals[SNMP_OUTNOROUTES]);
	add_stat(STATS_REASMREQDS, tmpvals[SNMP_REASMREQDS]);
	add_stat(STATS_REASMOKS, tmpvals[SNMP_REASMOKS]);
	add_stat(STATS_REASMFAILS, tmpvals[SNMP_REASMFAILS]);
	add_stat(STATS_OUTFRAGOKS, tmpvals[SNMP_OUTFRAGOKS]);
	add_stat(STATS_OUTFRAGFAILS, tmpvals[SNMP_OUTFRAGFAILS]);
	add_stat(STATS_OUTFRAGCREATES, tmpvals[SNMP_OUTFRAGCREATES]);
	return 0;
}


/* Assumes the first 2 lines of /proc/net/snmp are the IP info.
 * This assumption is valid since the this file is part of the kernel
 * user API.
 */
static int get_netstat_stats(void)
{
	FILE *fp;
	char line[1024]; /* must be big enough; 1k should be plenty */
	static const char netstat_file[] = "/proc/net/netstat";
	static const char ip_ext_pfx[] = "IpExt:";
	int len;
	unsigned long long int tmpvals[NETSTAT_LAST_ID];

	fp = fopen(netstat_file, "r");
	if (!fp)
		return -1;

	/* Find second line starting with ip_ext_pfx */
	len = 0;
	while (len < 2) {
		if (!fgets(line, sizeof(line), fp)) {
			msg_stderr("Unable to read values from %s", netstat_file);
			fclose(fp);
			return -1;
		}

		if (strncmp(line, ip_ext_pfx, sizeof(ip_ext_pfx) - 1) == 0)
			++len;
	}
	fclose(fp);

	/* All kernel reported values are 64-bit
	 * Scan directly into the 64-bit counters and into temp
	 * locations for the 32-bit counters.
	 */
        len = sscanf(line, /* skip prefix */
		     "%*s %llu %llu %llu %llu %llu"
		     " %llu %llu %llu %llu %llu",
		     &tmpvals[NETSTAT_INNOROUTES],
		     &tmpvals[NETSTAT_INTRANCATEDPKTS],
		     &tmpvals[NETSTAT_HCINMCASTPKTS],
		     &tmpvals[NETSTAT_HCOUTMCASTPKTS],
		     &tmpvals[NETSTAT_HCINBCASTPKTS],
		     &tmpvals[NETSTAT_HCOUTBCASTPKTS],
		     &tmpvals[NETSTAT_HCINOCTETS],
		     &tmpvals[NETSTAT_HCOUTOCTETS],
		     &tmpvals[NETSTAT_HCINMCASTOCTEST],
		     &tmpvals[NETSTAT_HCOUTMCASTOCTEST]);
	/* ok, so I'm paranoid */
        if (len != NETSTAT_LAST_ID) {
		msg_stderr("Unexpected number of values (expected %d, got %d)\n",
			   SNMP_LAST_ID, len);
		return -1;
        }

	add_stat(STATS_INNOROUTES, tmpvals[NETSTAT_INNOROUTES]);
	add_stat(STATS_INTRUNCATEDPKTS, tmpvals[NETSTAT_INTRANCATEDPKTS]);
	add_stat(STATS_HCINMCASTPKTS, tmpvals[NETSTAT_HCINMCASTPKTS]);
	add_stat(STATS_HCOUTMCASTPKTS, tmpvals[NETSTAT_HCOUTMCASTPKTS]);
	add_stat(STATS_HCINBCASTPKTS, tmpvals[NETSTAT_HCINBCASTPKTS]);
	add_stat(STATS_HCOUTBCASTPKTS, tmpvals[NETSTAT_HCOUTBCASTPKTS]);
	add_stat(STATS_HCINOCTETS, tmpvals[NETSTAT_HCINOCTETS]);
	add_stat(STATS_HCOUTOCTETS, tmpvals[NETSTAT_HCOUTOCTETS]);
	add_stat(STATS_HCINMCASTOCTETS, tmpvals[NETSTAT_HCINMCASTOCTEST]);
	add_stat(STATS_HCOUTMCASTOCTETS, tmpvals[NETSTAT_HCOUTMCASTOCTEST]);
	return 0;
}


/* Assumes the first 2 lines of /proc/net/snmp are the IP info.
 * This assumption is valid since the this file is part of the kernel
 * user API.
 */
static int get_stats4(void)
{
	if (get_snmp_stats() == -1)
		return -1;

	if (get_netstat_stats() == -1)
		return -1;

	return 0;
}


static int get_stats6(void)
{
	FILE *fp;
	char line[1024]; /* must be big enough; 1k should be plenty */
	static const char snmp_file[] = "/proc/net/snmp6";
	static const char ip6_pfx[] = "Ip6";
	size_t len;
	int stat_id;
	char name[128]; /* 128 should be big enough for stat name */
	unsigned long long int tmpval;

	fp = fopen(snmp_file, "r");
	if (!fp)
		return -1;

	while (1) {
		if (!fgets(line, sizeof(line), fp)) {
			if (!feof(fp)) {
				msg_stderr("Unable to read values from %s", snmp_file);
				fclose(fp);
				return -1;
			}
			break; /* EOF */
		}

		if (strncmp(line, ip6_pfx, sizeof(ip6_pfx) - 1) != 0)
			continue;

		len = strcspn(line, " ");
		if (len > sizeof(name) - 1)
			len = sizeof(name) - 1;
		strncpy(name, line, len);
		name[len] ='\0';

		len = sscanf(line + len, "%llu", &tmpval);
		if (len != 1) {
			msg_stderr("%s: unable to scan line: %s", __func__, line);
			continue;
		}

		stat_id = get_stat_id_by_name(name + sizeof(ip6_pfx) - 1);
		if ((stat_id < 0) || (stat_id >= STATS_LAST_ID)) {
			dbgmsg2("%s: Unknown or ignored stat %s", __func__, name);
			continue;
		}

		add_stat(stat_id, tmpval);
	}
	fclose(fp);
	return 0;
}


/* Parse specified JSON blob
 *
 * Reads the values out of the JSON blob and update the stats
 * structure.
 */
static int process_json_stats(const char *json, const char *cmd)
{
	static const char ipstats[] = "ip";
	static const char ip6stats[] = "ip6";
	const char *stat_obj_name;
	json_object *jobj_root, *jobj_stat;
	struct json_object_iterator iter, iter_end;

	if (!json || !cmd) {
		dbgmsg1("%s: invalid parameters");
		errno = EFAULT;
		return -1;
	}

	dbgmsg1("%s\n%s", __func__, json);
	jobj_root = json_tokener_parse(json);
	if (!jobj_root) {
		msg_stderr("Error loading JSON object");
		errno = EINVAL;
		return -1;
	}

	if (cmd == cmd_snmp_6)
		stat_obj_name = ip6stats;
	else
		stat_obj_name = ipstats;

	if (!json_object_object_get_ex(jobj_root, stat_obj_name, &jobj_stat)) {
		dbgmsg("%s: unable to find object %s", __func__, stat_obj_name);
		json_object_put(jobj_root);
		errno = EINVAL;
		return -1;
	}

	iter = json_object_iter_begin(jobj_stat);
	iter_end = json_object_iter_end(jobj_stat);
	while (!json_object_iter_equal(&iter, &iter_end)) {
		json_object *vobj;
		const char *name = json_object_iter_peek_name(&iter);

		int stat_id = get_stat_id_by_name(name);
		dbgmsg2("%s: stat %s has id %d", __func__, name, stat_id);
		if ((stat_id < 0) || (stat_id >= STATS_LAST_ID)) {
			dbgmsg1("%s: Unknown or ignored stat %s", __func__, name);
			json_object_iter_next(&iter);
			continue;
		}

		vobj = json_object_iter_peek_value(&iter);
		if (!json_object_is_type(vobj, json_type_int)) {
			dbgmsg("%s: Unknown type '%d' for stat %s", __func__,
			       json_object_get_type(vobj), name);
			json_object_iter_next(&iter);
			continue;
		}

		switch (stat_table[stat_id].type) {
			case COUNTER32:
				add_stat(stat_id,
					 (uint32_t)json_object_get_int(vobj));
				break;
			case COUNTER64:
				add_stat(stat_id, json_object_get_int64(vobj));
				break;
			default:
				dbgmsg("%s: Unknown stat type %d for stat %s", __func__,
				       stat_table[stat_id].type, name);
				break;
		}

		json_object_iter_next(&iter);
	}
	json_object_put(jobj_root);
	return 0;
}



/*
 * Command request (un)protocol:
 *   Send frames:
 *     [0] Dataplane command string
 *   Response frames:
 *     [0] ACK (or ERROR)
 *     [1] JSON response
 */
static int execute(zsock_t *sock, const char *cmd, const char *ep)
{
	int ret = 0;
	char *data = NULL;

	/* ignore blank lines */
	if (*cmd == '\0')
		return 0;

	dbgmsg1("%s: cmd = '%s'", __func__, cmd);
	if (zstr_send(sock, cmd) < 0)
		die("send request");

	zsock_set_rcvtimeo(sock, timeout_ms);

	zmsg_t *resp = zmsg_recv(sock);
	if (resp == NULL) {
		msg_stderr("no response from server (%s)", ep);
		return -1;
	}

	if (debug > 1)
		zmsg_dump(resp);

	char *status = zmsg_popstr(resp);
	if (!status) {
		msg_stderr("missing status in response");
		goto end;
	}

	if (strcmp(status, "OK") != 0) {
		msg_stderr("command failed");
		goto end;
	}

	data = zmsg_popstr(resp);
	if (!data) {
		msg_stderr("missing response data");
		ret = -1;
		goto end;
	}

	process_json_stats(data, cmd);
	ret = 0;

end:
	free(status);
	free(data);
	zmsg_destroy(&resp);
	return ret;
}

static void get_dataplane_list(zlist_t *list)
{
	zsock_t *sock = vplaned_connect();
	int rc;

	if (sock == NULL) {
		msg_stderr("vplaned connect failed");
		return;
	}

	rc = vplaned_request_dataplane(sock);
	if (rc < 0)
		msg_stderr("vplaned request failed: '%s'", strerror(-rc));
	else
		vplaned_dp_get_list(sock, (5*1000), true, list);

	vplaned_disconnect(&sock);
}

/* Get list of all dataplane endpoints */
static zlist_t *get_dataplanes(void)
{
	zlist_t *endpoints = zlist_new();

	if (endpoints != NULL) {
		get_dataplane_list(endpoints);
		if (zlist_size(endpoints) == 0)
			msg_stderr("No dataplanes found");
	}

	return endpoints;
}


static char *inc_oid(char *next, const char *oid, size_t len)
{
	int idx;
	int proto;

	if (!next || !oid) {
		errno = EFAULT;
		return NULL;
	}

	dbgmsg("%s: start %s", __func__, oid);
	idx = get_stat_idx(oid);
	proto = get_protocol(oid);
	if ((idx == -1) || (proto == -1)) {
		errno = EINVAL;
		return NULL;
	}

	if (++proto > TABLE_PROTO_MAX) {
		proto = TABLE_PROTO_MIN;
		++idx;
	}

	if (idx > TABLE_IDX_MAX)
		return NULL;

	snprintf(next, len, "%s.%u.%u", oid_base, (unsigned int)idx,
		 (unsigned int)proto);
	dbgmsg("%s: end %s", __func__, next);
	return next;
}



static struct option longopts[] = {
	{ "version",	no_argument,	   NULL, 'V' },
	{ "debug",	no_argument,	   NULL, 'd' },
	{ "help",	no_argument,       NULL, 'h' },
	{ "get",        required_argument, NULL, 'g' },
	{ "getnext",    required_argument, NULL, 'n' },
	{ "populate",	required_argument, NULL, 'p' },
	{ "set",	required_argument, NULL, 's' },
	{ "timeout",    required_argument, NULL, 't' },
	{ NULL, 0, NULL, 0 }
};

static void usage(void)
{
	msg_stderr("Usage: %s [OPTION...]\n\n%s\n\n"
		"-d, --debug       Enable debug messages\n"
		"-g, --get         Perform get on specified OID\n"
		"-h, --help        Display help and exit\n"
		"-n, --getnext     Perform get-next on specified OID\n"
		"-p, --populate    Populate the table\n"
		"-s, --set         Perform set on specified OID\n"
		"-t, --timeout     Socket timeout in ms\n"
		"-v, --version     Display version and exit\n",
		progname, version);
	exit(1);
}

static void get_stats_from_dataplanes(const char *cmd)
{
	zlist_t *dataplanes;

	dataplanes = get_dataplanes();
	if (dataplanes) {
		struct vplaned_dataplane *ep;
		while ((ep = zlist_pop(dataplanes))) {
			const char *console = vplaned_dp_console(ep);
			zsock_t *client = zsock_new_req(console);
			if (!client)
				die("zsock_new_req");

			if (execute(client, cmd, console) < 0)
				msg_stderr("command error: %s", cmd);

			vplaned_dp_destroy(&ep);
			zsock_destroy(&client);
			dump_stats();
		}
		zlist_destroy(&dataplanes);
	}
}

static void populate_table(const char *pfile)
{
	int id;
	FILE *fp;
	char buf[1024];

	fp = fopen(pfile, "w");
	if (!fp)
		return;
	get_stats4();
	get_stats_from_dataplanes(cmd_snmp_4);
	calc_stats();
	for (id = 0; id < STATS_LAST_ID; ++id) {
		snprintf(buf, sizeof(buf), "%s.%d.1 %d %lu\n", oid_base, id+3,
			stat_table[id].type, stat_table[id].stat);
		fputs(buf, fp);
	}
	get_stats6();
	get_stats_from_dataplanes(cmd_snmp_6);
	calc_stats();
	for (id = 0; id < STATS_LAST_ID; ++id) {
		snprintf(buf, sizeof(buf), "%s.%d.2 %d %lu\n", oid_base, id+3,
			stat_table[id].type, stat_table[id].stat);
		fputs(buf, fp);
	}
	fclose(fp);
}

int main(int argc, char **argv)
{
	char next_oid[sizeof(oid_base) + 5]; /* + worst case ".nn.n" */;
	const char *p;
	int flag;
	const char *cmd = NULL;
	const char *pfile = NULL;
	char *oid = NULL;

	/* Preserve app name */
	progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

	openlog(progname, LOG_PID, LOG_DAEMON);

	while ((flag = getopt_long(argc, argv, "dg:hn:p:s:t:v",
				   longopts, 0)) != EOF) {
		switch (flag) {
		case 'd':
			++debug;
			break;
		case 'p':
			pfile = optarg;
			dbgmsg("option: Populate %s", pfile);
			break;
		case 'g':
			if (oid)
				break;
			if (!in_sysstatstable(optarg))
				break;
			oid = optarg;
			dbgmsg("option: GET %s", oid);
			break;
		case 'n':
			if (oid)
				break;

			dbgmsg("option: GETNEXT %s", optarg);
			if (strcmp(optarg, oid_base) == 0) {
				const char suffix[] = ".3.1";
				oid = alloca(strlen(optarg) + sizeof(suffix));
				strcpy(oid, optarg);
				strcat(oid, suffix);
			} else if (in_sysstatstable(optarg)) {
				oid = inc_oid(next_oid, optarg, sizeof(next_oid));
			} else
				exit(0);
			dbgmsg("using: GETNEXT %s", oid);
			break;
		case 's':
			printf("not-writable\n");
			exit(0);
			break;
		case 't':
			timeout_ms = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			msg_stderr("%s\n%s\n", version, copyright);
			exit(0);
		case 'h':
		default:
			usage();
		}
	}

	if (pfile) {
		populate_table(pfile);
		exit(0);
	}

	if (!oid) {
		dbgmsg("OID not in system table: %s\n", oid);
		exit(1);
	}

	switch (get_protocol(oid)) {
		case 1:
			get_stats4();
			cmd = cmd_snmp_4;
			break;
		case 2:
			get_stats6();
			cmd = cmd_snmp_6;
			break;
		default:
			die("Unknown protocol");
	}
	dump_stats();

	get_stats_from_dataplanes(cmd);

	calc_stats();
	dump_stats();

	int id = get_stat_id_by_oid(oid);
	if (id < 0) {
		dbgmsg("Invalid stat id %d", id);
		return 0;
	}
	print_stat(oid, id);

	closelog();
	return 0;
}
