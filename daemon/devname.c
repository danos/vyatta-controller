/*
 * Assign dataplane interface name
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if.h>

#include <czmq.h>
#include <json.h>

#include "controller.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

struct port_info {
	int		port;	     /* DPDK port id */
	const char	*driver;     /* DPDK driver name */
	const char	*name;	     /* DPDK device name */
	const char	*hypervisor; /* Hypervisor type (ie "VMware") */
	const char	*mac;	     /* Ethernet address "00:11:22:33:44:55" */

	int		slot;	     /* PCI slot (from ACPI) */
	const char	*pci_addr;   /* PCI 0000:00:00.0 */
	int		firmware;    /* Onboard device index */
	int		dev_port;    /* Multi port device */
	bool		multifunction; /* device has multiple functions */
	bool		uplink;
	bool		backplane;   /* Backplane port connecting to switch */
	unsigned int	if_flags;    /* Additional IFFLAGS for tun create */
	unsigned int	mtu;         /* Default MTU for tun create */
};

struct pci_address {
	uint16_t domain;     /* Device domain */
	uint8_t bus;	     /* Device bus */
	uint8_t devid;	     /* Device ID */
	uint8_t function;    /* Device function. */
};

/** Formatting string for PCI device identifier: Ex: 0000:00:01.0 */
#define PCI_SCAN_FMT "%hx:%hhx:%hhx.%hhx"

/* Like snprintf but concatinates to existing string */
static size_t snprintfcat(char *buf, size_t size, const char *fmt, ...)
{
	size_t n, len = strnlen(buf, size);
	va_list args;

	va_start(args, fmt);
	n = vsnprintf(buf + len, size - len, fmt, args);
	va_end(args);

	return len + n;
}

/*
 * Derive device name for external network interfaces (mostly PCI based)
 * based on rules compatible with systemd.
 */
static int get_devname(const struct port_info *pinfo,
		       char *ifname, size_t sz)
{
	struct pci_address loc;

	if (strcasestr(pinfo->driver, "net_netvsc") != NULL) {
		snprintf(ifname, sz, "s%d", pinfo->slot);
		return 0;
	}

	if (pinfo->pci_addr == NULL) {
		/*assume a vdev device if no pci_addr is supplied.*/
		strncpy(ifname, pinfo->name, sz);
		return 0;
	}

	memset(&loc, 0, sizeof(loc));
	if (sscanf(pinfo->pci_addr, PCI_SCAN_FMT,
		   &loc.domain, &loc.bus, &loc.devid, &loc.function) != 4) {
		err("invalid pci address %s, %s",
		    pinfo->pci_addr, strerror(errno));
		return -1;
	}

	/*
	 * Special case only for VMware because PCI information on
	 *  VMware is non-standard and carrier customer demanded
	 *  compatiablity with early beta.
	 */
	if (pinfo->hypervisor && strncmp(pinfo->hypervisor, "VMware", 6) == 0) {
		if (pinfo->slot < 0) {
			err("ACPI slot information not found");
			return -1;
		}
		snprintf(ifname, sz, "p%dp%u", pinfo->slot, loc.function + 1);
		return 0;
	}

	/* Workaround Xen driver not really being PCI. */
	if (strcmp(pinfo->driver, "rte_xen_pmd") == 0) {
		snprintf(ifname, sz, "s%d", loc.bus);
		return 0;
	}

	/* Is it an onboard port? */
	if (pinfo->firmware > 0)
		snprintf(ifname, sz, "o%d", pinfo->firmware);

	else {
		if (loc.domain > 0)
			snprintf(ifname, sz, "P%u", loc.domain);
		else
			ifname[0] = '\0';

		/* Is the ACPI slot reported by BIOS? */
		if (pinfo->slot >= 0) {
			if (loc.bus > 0)
				snprintfcat(ifname, sz, "p%u", loc.bus);

			snprintfcat(ifname, sz, "s%d", pinfo->slot);
		} else {
			snprintfcat(ifname, sz, "p%us%u", loc.bus, loc.devid);
		}

		/* add suffix fN for multi-function PCI device */
		if (loc.function > 0 || pinfo->multifunction)
			snprintfcat(ifname, sz, "f%u", loc.function);
	}

	/* add suffix dN for devices with multiple ports at same address */
	if (pinfo->dev_port > 0)
		snprintfcat(ifname, sz, "d%u", pinfo->dev_port);

	return 0;
}

/* Special case for bonding device */
static int get_bond_devname(const char *driver_name, char *ifname, size_t sz)
{
	unsigned int num;

	if (sscanf(driver_name, "dp%*ubond%u", &num) != 1) {
		err("invalid bond device name %s, %s",
		    driver_name, strerror(errno));
		return -1;
	}

	snprintfcat(ifname, sz, "bond%u", num);
	return 0;
}

static int hwbinding_policy(const struct port_info *pinfo,
			    char *ifname, size_t sz)
{
	const char *name;

	name = get_name_by_pciaddr(pinfo->pci_addr);
	if (name)
		goto match;
	name = get_name_by_mac(pinfo->mac);
	if (name)
		goto match;
	name = get_name_by_pcislot(pinfo->slot, pinfo->multifunction);
	if (name)
		goto match;
	name = get_name_by_fwidx(pinfo->firmware);
	if (name)
		goto match;
	name = get_name_by_port(pinfo->port);
	if (name)
		goto match;

	return -1;

match:
	strncpy(ifname, name, sz);
	return 0;
}

/* Default based policy to create name */
static int default_policy(const struct port_info *pinfo,
			  char *ifname, size_t sz)
{
	/* Special cases for internal or virtual devices */
	if (strstr(pinfo->driver, "bond") != NULL)
		return get_bond_devname(pinfo->name, ifname, sz);
	else if (strncmp(pinfo->name, "vhost", 5) == 0) {
		/* For vhost, pinfo->name=vhost1 */
		/* convert path name to only retain host name */
		strncpy(ifname, pinfo->name, sz);
		ifname[sz-1] = 0;
	} else if (strcasestr(pinfo->driver, "af_packet")) {
		char *name = (char *) pinfo->name;

		/* skip the "en" prefix if present */
		if (strncmp(name, "en", 2) == 0)
			name += 2;
		/* skip the "ww" prefix if present */
		if (strncmp(name, "ww", 2) == 0)
			name += 2;
		strncpy(ifname, name, sz);
		ifname[sz - 1] = 0;
	} else {
		/* Optional hardware based policy to create name */
		int rc = hwbinding_policy(pinfo, ifname, IFNAMSIZ);

		if (rc < 0)
			return get_devname(pinfo, ifname, sz);
	}

	return 0;

}

#define PINFO_OFFSET(field)	offsetof(struct port_info, field)
#define PINFO_PTR(pinfo, offs)  ((void  *)((char *)(pinfo) + (offs)))

static const struct port_info_key {
	const char *key;
	json_type   type;
	ptrdiff_t   offset;
} port_keys[] = {
	{ "port",	   json_type_int,     PINFO_OFFSET(port) },
	{ "driver",	   json_type_string,  PINFO_OFFSET(driver) },
	{ "name",	   json_type_string,  PINFO_OFFSET(name) },
	{ "hypervisor",	   json_type_string,  PINFO_OFFSET(hypervisor) },
	{ "mac",	   json_type_string,  PINFO_OFFSET(mac) },
	{ "slot",	   json_type_int,     PINFO_OFFSET(slot) },
	{ "pci-address",   json_type_string,  PINFO_OFFSET(pci_addr) },
	{ "firmware",	   json_type_int,     PINFO_OFFSET(firmware) },
	{ "dev-port",	   json_type_int,     PINFO_OFFSET(dev_port) },
	{ "multifunction", json_type_boolean, PINFO_OFFSET(multifunction) },
	{ "uplink",        json_type_boolean, PINFO_OFFSET(uplink) },
	{ "backplane",     json_type_boolean, PINFO_OFFSET(backplane) },
	{ "if_flags",	   json_type_int,     PINFO_OFFSET(if_flags) },
	{ "mtu",	   json_type_int,     PINFO_OFFSET(mtu) },
};

static const struct port_info_key *match_port_key(const char *key)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(port_keys); i++) {
		const struct port_info_key *p = port_keys + i;

		if (strcmp(p->key, key) == 0)
			return p;
	}

	return NULL;	/* not found */
}

/* Extract key fields from the JSON port information */
int assign_port(const char *json, unsigned int dp_id,
		char *ifname, struct ether_addr *eth,
		char **driver, char **bus, unsigned int *if_flags,
		unsigned int *mtu)
{
	struct port_info pinfo = {
		.port = -1, .slot = -1,
	};
	json_object *jobj;
	int rc = -1;

	dbg("devinfo (%d) '%s'", dp_id, json);

	/* Parse JSON encoded description of hardware */
	jobj = json_tokener_parse(json);
	if (!jobj) {
		err("invalid json device info");
		return -1;
	}

	json_object_object_foreach(jobj, key, value) {
		const struct port_info_key *p = match_port_key(key);

		if (!p)
			continue;

		json_type type = json_object_get_type(value);

		if (type != p->type) {
			notice("wrong json type for key %s", key);
			continue;
		}

		switch (type) {
		case json_type_string: {
			const char **sptr = PINFO_PTR(&pinfo, p->offset);

			*sptr = json_object_get_string(value);
			break;
		}
		case json_type_int: {
			int *iptr = PINFO_PTR(&pinfo, p->offset);
			*iptr = json_object_get_int64(value);
			break;
		}
		case json_type_boolean: {
			bool *bptr = PINFO_PTR(&pinfo, p->offset);
			*bptr = json_object_get_boolean(value);
			break;
		}
		default:
			err("unexpect json type %u", type);
		}
	}

	if (pinfo.port == -1)
		notice("missing port in port request");
	else if (!pinfo.driver)
		notice("missing device driver");
	else if (!pinfo.name)
		err("missing driver device name");
	else {
		int n;

		if (pinfo.uplink)
			n = snprintf(ifname, IFNAMSIZ, "up%u", dp_id);
		else if (pinfo.backplane)
			n = snprintf(ifname, IFNAMSIZ, "bp%u", dp_id);
		else
			n = snprintf(ifname, IFNAMSIZ, "dp%u", dp_id);

		rc = default_policy(&pinfo, ifname + n, IFNAMSIZ - n);
	}

	if (if_flags && pinfo.if_flags)
		*if_flags = pinfo.if_flags;

	if (mtu && pinfo.mtu)
		*mtu = pinfo.mtu;

	if (rc == 0) {
		/* store results of name lookup */
		ether_aton_r(pinfo.mac, eth);
		*driver = strdup(pinfo.driver);
		if (pinfo.pci_addr)
			*bus = strdup(pinfo.pci_addr);

		rc = pinfo.port;
	}

	/* release ref count, frees strings as well */
	json_object_put(jobj);
	return rc;
}
