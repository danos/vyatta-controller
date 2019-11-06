/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <czmq.h>

#include <linux/if.h>

#include "controller.h"

static zlist_t *hwb_list;
static char *interface_cfg;
static time_t interface_cfg_mtime;

enum binding_type {
	HWBINDING_FWIDX = 1,	/* firmware index */
	HWBINDING_MACADDR,	/* mac address */
	HWBINDING_PCIADDR,	/* pci address */
	HWBINDING_PCISLOT,	/* pci slot */
	HWBINDING_PORT,		/* dpdk port */
};

#define PCI_SCAN_FMT  "%hx:%hhx:%hhx.%hhx"
#define PCI_SCAN_FMT_SHORT "%hhx:%hhx.%hhx"

struct hwbinding {
	enum binding_type type;
	union {
		int fwidx;
		int port;
		struct pcislot {
			int slot;
			int function;
		} pcislot;
		struct pciaddr {
			unsigned short domain;
			unsigned char bus;
			unsigned char devid;
			unsigned char function;
		} pciaddr;
		struct ether_addr eaddr;
	} u;
	char *name;
};

static void free_hwbinding(void *data)
{
	struct hwbinding *hwb = data;

	free(hwb->name);
	free(hwb);
}

static enum binding_type name_to_binding_type(char *name)
{
	if (!strcmp(name, "pci-address"))
		return HWBINDING_PCIADDR;
	if (!strcmp(name, "pci-slot"))
		return HWBINDING_PCISLOT;
	if (!strcmp(name, "firmware-index"))
		return HWBINDING_FWIDX;
	if (!strcmp(name, "mac"))
		return HWBINDING_MACADDR;
	if (!strcmp(name, "port"))
		return HWBINDING_PORT;

	return 0;
}

static void parse_interface_cfg(const char *config)
{
	FILE *fp;
	char line[BUFSIZ];
	char name[BUFSIZ], type[BUFSIZ], value[BUFSIZ];
	struct hwbinding *hwb;
	int lineno = 0;
	char *p;

	if (!hwb_list) {
		hwb_list = zlist_new();
		if (!hwb_list) {
			err("%s: zlist_new() failed!", __func__);
			return;
		}
	}
	zlist_purge(hwb_list);

	fp = fopen(config, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		++lineno;

		p = strchr(line, '#');
		if (p)
			*p = '\0';

		if (sscanf(line, "%s %s %s", name, type, value) != 3)
			continue;

		if (!isalpha(name[0]))
			goto fail;

		hwb = malloc(sizeof(*hwb));
		if (!hwb)
			continue;
		memset(hwb, 0, sizeof(*hwb));
		hwb->type = name_to_binding_type(type);
		if (!hwb->type)
			goto fail_free;
		if (strlen(name) >= IFNAMSIZ)
			goto fail_free;
		hwb->name = strdup(name);
		if (!hwb->name)
			goto fail_free;

		if (hwb->type == HWBINDING_FWIDX) {
			hwb->u.fwidx = atoi(value);
		} else if (hwb->type == HWBINDING_PORT) {
			hwb->u.port = atoi(value);
		} else if (hwb->type == HWBINDING_MACADDR) {
			struct ether_addr *eaddr;

			eaddr = ether_aton_r(value, &hwb->u.eaddr);
			if (!eaddr)
				goto fail_free;
		} else if (hwb->type == HWBINDING_PCISLOT) {
			int slot, function;

			if (sscanf(value, "%d.%d", &slot, &function) == 2) {
				hwb->u.pcislot.slot = slot;
				hwb->u.pcislot.function = function;
			} else {
				hwb->u.pcislot.slot = atoi(value);
				hwb->u.pcislot.function = 0;
			}
		} else if (hwb->type == HWBINDING_PCIADDR) {
			if (sscanf(value, PCI_SCAN_FMT,
				   &hwb->u.pciaddr.domain,
				   &hwb->u.pciaddr.bus,
				   &hwb->u.pciaddr.devid,
				   &hwb->u.pciaddr.function) != 4) {

				hwb->u.pciaddr.domain = 0;
				if (sscanf(value, PCI_SCAN_FMT_SHORT,
					   &hwb->u.pciaddr.bus,
					   &hwb->u.pciaddr.devid,
					   &hwb->u.pciaddr.function) != 3)
					goto fail_free;
			}
		}

		if (zlist_append(hwb_list, hwb) < 0) {
			err("failed to add %s from %s", name, interface_cfg);
			free_hwbinding(hwb);
			continue;
		}
		zlist_freefn(hwb_list, hwb, free_hwbinding, false);
		continue;

fail_free:
		free_hwbinding(hwb);
fail:
		err("can't parse line %d in %s", lineno, interface_cfg);
	}
	fclose(fp);
}

void interface_cfg_destroy(void)
{
	if (interface_cfg) {
		free(interface_cfg);
		interface_cfg_mtime = 0;
		interface_cfg = NULL;
	}

	if (hwb_list) {
		zlist_purge(hwb_list);
		zlist_destroy(&hwb_list);
		hwb_list = NULL;
	}
}

static void reread_interface_cfg(void)
{
	struct stat stat_buf;

	if (!interface_cfg)
		return;

	if (stat(interface_cfg, &stat_buf) == -1) {
		if (hwb_list)
			zlist_purge(hwb_list);
		interface_cfg_mtime = 0;
		return;
	}

	if (interface_cfg_mtime != stat_buf.st_mtime) {
		interface_cfg_mtime = stat_buf.st_mtime;

		parse_interface_cfg(interface_cfg);
	}
}

void read_interface_cfg(const char *name)
{
	interface_cfg_destroy();
	interface_cfg = strdup(name);

	reread_interface_cfg();
}

static const char *get_name_by_hwb(struct hwbinding *target)
{
	struct hwbinding *hwb;

	reread_interface_cfg();

	if (!hwb_list)
		return NULL;

	for (hwb = zlist_first(hwb_list); hwb; hwb = zlist_next(hwb_list)) {
		if (memcmp(hwb, target,
		    sizeof(hwb->type) + sizeof(hwb->u)) == 0)
			return hwb->name;
	}

	return NULL;
}

const char *get_name_by_pcislot(int slot, int function)
{
	struct hwbinding hw;

	memset(&hw, 0, sizeof(hw));
	hw.type = HWBINDING_PCISLOT;
	hw.u.pcislot.slot = slot;
	hw.u.pcislot.function = function;

	return get_name_by_hwb(&hw);
}

const char *get_name_by_pciaddr(const char *pci_addr)
{
	struct hwbinding hw;

	if (!pci_addr)
		return NULL;

	memset(&hw, 0, sizeof(hw));
	hw.type = HWBINDING_PCIADDR;

	if (sscanf(pci_addr, PCI_SCAN_FMT,
		   &hw.u.pciaddr.domain,
		   &hw.u.pciaddr.bus,
		   &hw.u.pciaddr.devid,
		   &hw.u.pciaddr.function) != 4)
		return NULL;

	return get_name_by_hwb(&hw);
}

const char *get_name_by_mac(const char *mac)
{
	struct hwbinding hw;

	if (!mac)
		return NULL;

	memset(&hw, 0, sizeof(hw));
	hw.type = HWBINDING_MACADDR;
	if (!ether_aton_r(mac, &hw.u.eaddr))
		return NULL;

	return get_name_by_hwb(&hw);
}

const char *get_name_by_fwidx(int fwidx)
{
	struct hwbinding hw;

	memset(&hw, 0, sizeof(hw));
	hw.type = HWBINDING_FWIDX;
	hw.u.fwidx = fwidx;

	return get_name_by_hwb(&hw);
}

const char *get_name_by_port(int port)
{
	struct hwbinding hw;

	memset(&hw, 0, sizeof(hw));
	hw.type = HWBINDING_PORT;
	hw.u.port = port;

	return get_name_by_hwb(&hw);
}
