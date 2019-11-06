/*
 * Filesystem change watcher
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <sys/inotify.h>
#include <czmq.h>
#include "controller.h"

struct fs_watcher;

typedef void (*fs_watcher_handler)(const struct fs_watcher *this,
				   const struct inotify_event *event);

struct fs_watcher {
	fs_watcher_handler handler;
	const char *path;
	int wd; /* watch descriptor */
};

struct fs_register {
	const char *path;
	uint32_t watch_mask;
	fs_watcher_handler handler;
};

/* struct fs_watchers indexed by watch descriptor */
static zhashx_t *fs_watchers_wd;

static int fsnotify_fd = -1;

static void watcher_destructor(void **item)
{
	struct fs_watcher *watcher = *item;

	inotify_rm_watch(fsnotify_fd, watcher->wd);
	free(watcher);
	*item = NULL;
}

static size_t watcher_wd_hasher(const void *key)
{
	return (uintptr_t)key;
}

static int watcher_wd_comparator(const void *item1, const void *item2)
{
	return (uintptr_t)item1 - (uintptr_t)item2;
}

static void watcher_wd_destructor(void **item __unused)
{
}

static void *watcher_wd_duplicator(const void *item)
{
	return (void *)item;
}

static int overflow_handler(void *data, void *arg)
{
	struct fs_watcher *fs_watcher = data;

	fs_watcher->handler(fs_watcher, arg);
	return 0;
}

/* handle filesystem notification events for an fd previously returned
 * by fsnotify_init */
void fsnotify_handle_events(void)
{
	/* The buffer will be aliased with struct inotify_event so this
	 * should have the same alignment as it
	 */
	char buf[4096]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	ssize_t len;
	char *ptr;

	/* Loop while events can be read from inotify file descriptor. */

	while ((len = read(fsnotify_fd, buf, sizeof(buf))) > 0) {
		for (ptr = buf; ptr < buf + len;
		     ptr += sizeof(struct inotify_event) + event->len) {
			struct fs_watcher *fs_watcher;

			event = (const struct inotify_event *) ptr;

			/* on overflow events will have been dropped
			 * so call each handler. Although this may
			 * generate redundant notifications, it's better
			 * than not generating required ones.
			 */
			if (event->mask & IN_Q_OVERFLOW) {
				void *item;
				for (item = zhashx_first(fs_watchers_wd); item != NULL;
						item = zhashx_next(fs_watchers_wd))
					overflow_handler(item, (void *)event);
				continue;
			}

			fs_watcher = zhashx_lookup(fs_watchers_wd,
						 (void *)(uintptr_t)event->wd);
			if (!fs_watcher) {
				notice(
					"failed to find event for wd %d whilst handling fsnotify events",
					event->wd);
				continue;
			}
			fs_watcher->handler(fs_watcher, event);
		}
	}

	if (len == -1 && errno != EAGAIN && errno != EINTR)
		err("read for fsnotify events failed: %s",
		    strerror(errno));
}

static int add_watcher(const char *path, uint32_t mask,
		       fs_watcher_handler handler)
{
	struct fs_watcher *watcher = malloc(sizeof(*watcher));

	if (!watcher)
		return -1;

	watcher->path = path;
	watcher->handler = handler;
	watcher->wd = inotify_add_watch(fsnotify_fd, path, mask);
	if (watcher->wd == -1) {
		free(watcher);
		return -1;
	}
	zhashx_insert(fs_watchers_wd, (void *)(uintptr_t)watcher->wd,
		      watcher);

	dbg("added fs watcher for %s", path);

	/* trigger handler immediately to retrieve initial value in
	 * order to avoid hardcoding defaults in dataplane
	 */
	watcher->handler(watcher, NULL);

	return 0;
}

static void generate_json_cmd(const char *level0, const char *level1,
			      const char *cmd, const char *commit_action)
{
	const char template[] =
		"{\"%s\": "
		  "{\"%s\": "
		    "{\"__%s__\": \"%s\", \"__INTERFACE__\": \"ALL\"}"
		  "}"
		"}";
	char buf[sizeof(template) + strlen(level0) + strlen(level1) +
		 strlen(commit_action) + strlen(cmd)];
	int rc;

	snprintf(buf, sizeof(buf), template, level0, level1, commit_action,
		 cmd);
	rc = process_gen_config(buf);
	if (rc != 0)
		notice("failed to generate json cmd: %s", buf);
}

static int sysctl_read_value(const char *path, char *buf, size_t len)
{
	FILE *file;
	int read;

	file = fopen(path, "r");
	if (!file) {
		notice("unable to open %s", path);
		return -1;
	}

	read = fread(buf, 1, len, file);
	fclose(file);

	return read ? 0 : -1;
}

/*
 * ICMP redirect related watcher
 */
static void sysctl_ip_disable_redirects(
	const struct fs_watcher *this,
	const struct inotify_event *event __unused)
{
	char val[256] = { 0 };

	if (!sysctl_read_value(this->path, val, sizeof(val))) {
		dbg("%s=%s", this->path, val);

		if (!strcmp(val, "0\n")) {
			generate_json_cmd("ip4", "redirects",
					  "ip4 redirects disable",
					  "SET");
		} else {
			generate_json_cmd("ip4", "redirects",
					  "ip4 redirects enable",
					  "SET");
		}
	}
}

static const struct fs_register redirects_watchers[] = {
	{
		.path = "/proc/sys/net/ipv4/conf/all/send_redirects",
		.watch_mask = IN_CLOSE_WRITE,
		.handler = sysctl_ip_disable_redirects,
	},
};

void fsnotify_add_redirects_watchers(void)
{
	unsigned int i;
	static bool redirects_initiated = false;

	/* if already registered redirects then nothing to do */
	if (redirects_initiated)
		return;

	redirects_initiated = true;

	for (i = 0;
	     i < sizeof(redirects_watchers)/sizeof(redirects_watchers[0]);
	     i++) {
		if (add_watcher(redirects_watchers[i].path,
				redirects_watchers[i].watch_mask,
				redirects_watchers[i].handler))
			notice("unable to add watcher for %s",
			       redirects_watchers[i].path);
	}
}

static void sysctl_mpls_platform_labels(
	const struct fs_watcher *this,
	const struct inotify_event *event __unused)
{
	char action[512];
	char val[256] = { 0 };

	if (!sysctl_read_value(this->path, val, sizeof(val))) {
		dbg("%s=%s", this->path, val);

		snprintf(action, sizeof(action),
			 "mpls labeltablesize %s", val);
		action[255] = '\0';
		generate_json_cmd("mpls", "labeltablesize", action, "SET");
	}
}

static void sysctl_mpls_default_ttl(const struct fs_watcher *this,
				    const struct inotify_event *event __unused)
{
	char action[512];
	char val[256] = { 0 };

	if (!sysctl_read_value(this->path, val, sizeof(val))) {
		dbg("%s=%s", this->path, val);

		snprintf(action, sizeof(action),
			 "mpls defaultttl %s", val);
		action[255] = '\0';
		generate_json_cmd("mpls", "defaultttl", action, "SET");
	}
}

static void sysctl_mpls_ip_ttl_propagate(
	const struct fs_watcher *this,
	const struct inotify_event *event __unused)
{
	char val[256] = { 0 };

	if (!sysctl_read_value(this->path, val, sizeof(val))) {
		dbg("%s=%s", this->path, val);

		if (!strcmp(val, "0\n")) {
			generate_json_cmd("mpls", "ipttlpropagate",
					  "mpls ipttlpropagate disable",
					  "SET");
		} else {
			generate_json_cmd("mpls", "ipttlpropagate",
					  "mpls ipttlpropagate enable",
					  "SET");
		}
	}
}

/* Note that in general it isn't advisable to use inotify to track
 * changes to files in /proc/sys because the kernel doesn't issue
 * notifications when dynamic values change. However, for static
 * values (i.e. configuration parameters) that are only changed by
 * userspace, inotify will give us notifications.
 */
static const struct fs_register mpls_watchers[] = {
	{
		.path = "/proc/sys/net/mpls/platform_labels",
		.watch_mask = IN_CLOSE_WRITE,
		.handler = sysctl_mpls_platform_labels,
	},
	{
		.path = "/proc/sys/net/mpls/default_ttl",
		.watch_mask = IN_CLOSE_WRITE,
		.handler = sysctl_mpls_default_ttl,
	},
	{
		.path = "/proc/sys/net/mpls/ip_ttl_propagate",
		.watch_mask = IN_CLOSE_WRITE,
		.handler = sysctl_mpls_ip_ttl_propagate,
	},
};

void fsnotify_add_mpls_watchers(void)
{
	static bool mpls_inited = false;
	unsigned int i;

	/* if already initialised then nothing to do */
	if (mpls_inited)
		return;

	mpls_inited = true;

	for (i = 0; i < sizeof(mpls_watchers)/sizeof(mpls_watchers[0]); i++) {
		if (add_watcher(mpls_watchers[i].path,
				mpls_watchers[i].watch_mask,
				mpls_watchers[i].handler))
			notice("unable to add watcher for %s",
			       mpls_watchers[i].path);
	}
}

/* initialise filesystem notifications, returning a file descriptor */
int fsnotify_init(void)
{
	fsnotify_fd = inotify_init1(IN_NONBLOCK);
	if (fsnotify_fd == -1)
		panic("inotify_init1");

	fs_watchers_wd = zhashx_new();
	if (!fs_watchers_wd)
		panic("zhashx_new");

	zhashx_set_destructor(fs_watchers_wd, watcher_destructor);
	zhashx_set_key_comparator(fs_watchers_wd, watcher_wd_comparator);
	zhashx_set_key_hasher(fs_watchers_wd, watcher_wd_hasher);
	zhashx_set_key_duplicator(fs_watchers_wd, watcher_wd_duplicator);
	zhashx_set_key_destructor(fs_watchers_wd, watcher_wd_destructor);

	return fsnotify_fd;
}

void fsnotify_destroy(void)
{
	zhashx_destroy(&fs_watchers_wd);
	close(fsnotify_fd);
	fsnotify_fd = -1;
}
