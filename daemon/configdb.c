/**
 *  Storage of unique hashed commands. Provides mapping between
 *  our configuration tree and commands to the dataplane. Sits
 *  behind the configstore interface.
 *
 * Copyright (c) 2018-2019, 2021 AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2012-2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 **/
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <json.h>
#include <linkhash.h>
#include <czmq.h>
#include "controller.h"
#include "configdb.h"

#define HASH_SIZE 256

/*
  Externally available resync commands. Note that _root_config_coll
  is cleared after a new configuration command has been received.
  _root_config_coll is regenerated on resync request and _root_config_coll
  is null.
 */
/* Global config container (tree storage) */
static lh_table *_root_config_coll;

/* Interface hint keyword */
#define INTERFACE_NODE "__INTERFACE__"

/* Actions sent via configuration tree, parent of command */
#define DELETE_ACTION "__DELETE__"
#define SET_ACTION    "__SET__"
#define ACTIVE_ACTION "__ACTIVE__"

#define PROTOBUF_TOKEN "__PROTOBUF__"

/*
  Callback function handling release of configuration node structure.
  Note, this code indirectly calls child hash release functions.
 */
static void
config_coll_free(struct lh_entry *e)
{
	config_node_t *cv = (config_node_t *)e->v;

	/* Initiates recursive call to children */
	lh_table *db = cv->_hash;
	if (db != NULL)
		lh_table_free(db);

	free(cv->_value);
	free(cv->_topic);
	free(cv->_interface);

	/* key is strdup'ed manually because json-c does not make a copy */
	free((void *)e->k);

	free(cv);
}

/*
 * API change (breakage). The json-c hash table name argument got
 * dropped around version 0.13.x (see json-c:1ae4b50b)
 */
static inline lh_table *
my_lh_kchar_table_new(int size, lh_entry_free_fn free_fn)
{
#if JSON_C_MINOR_VERSION > 13
	return lh_kchar_table_new(size, free_fn);
#else
	return lh_kchar_table_new(size, "config_hash", free_fn);
#endif
}

/*
  Create single config_node_t structure
*/

static config_node_t *
create_config_node(char *key __unused)
{
	config_node_t *cv = malloc(sizeof(config_node_t));
	if (cv == NULL) {
		err("failure to allocate memory");
		return cv;
	}
	cv->_hash = my_lh_kchar_table_new(HASH_SIZE, config_coll_free);
	cv->_seq = -1;
	cv->_topic = NULL;
	cv->_value = NULL;
	cv->_interface = NULL;
	cv->_bin = false;
	return cv;
}

/*
  Helper function to extract topic from command (likely to go away)
 */
static char*
extract_topic(const char *line)
{
	char topic[BUFSIZ], *tmp = NULL;
	topic[0] = '\0';
	/* For now... grab first two entries as topic */
	/* NEED to fix this up so that topic is pulled from config cmd */
	char *token = strtok_r((char *)line, " ", &tmp);
	int ct = 0;
	while (token != NULL && ct < 2) {
		strcat(topic, token);
		strcat(topic, " ");
		token = strtok_r(NULL, " ", &tmp);
		++ct;
	}
	if (ct == 2)
		return strdup(topic);

	return NULL;
}

/*
  Recursive call to merge json_object into hashed configuration tree. Handles
  Sets/Deletes as identifed by the JSON values.
 */
static void
merge_json_to_db(lh_table *db, json_object *jobj, config_node_t *p_cv)
{
	if (db == NULL || jobj == NULL)
		return;

	enum json_type type = json_object_get_type(jobj);
	if (type == json_type_object) {
		json_object_iter iter;
		enum json_type itertype;

		json_object_object_foreachC(jobj, iter) {
			itertype = json_object_get_type(iter.val);
			if (itertype == json_type_string) {
				if (strcmp(iter.key, DELETE_ACTION) == 0) { /* DELETE */
					const char *cmd = json_object_get_string(iter.val);
					add_cmd(p_cv, cmd);

					/* handle binary data key */
					json_object *bin_jobj;
					;
					if (json_object_object_get_ex(jobj,
								      PROTOBUF_TOKEN,
								      &bin_jobj) &&
					    bin_jobj &&
					    json_object_is_type(bin_jobj, json_type_boolean))
						p_cv->_bin = json_object_get_boolean(bin_jobj);

					lh_table_free(p_cv->_hash); /* free nodes below this point */
					p_cv->_hash = NULL;
					free(p_cv->_topic);
					p_cv->_topic = extract_topic(cmd);
				} else if (strcmp(iter.key, SET_ACTION) == 0 ||
					   strcmp(iter.key, ACTIVE_ACTION) == 0) { /* SET or ACTIVE */
					/* two possible actions, update or create */
					config_node_t *cv = NULL;
					struct lh_entry *e = lh_table_lookup_entry(db, (void *)SET_ACTION);
					if (e == NULL) {  /* create new entry */
						cv = create_config_node(SET_ACTION);
						if (cv == NULL)
							return;

						const char *cmd = json_object_get_string(iter.val);
						cv->_value = strdup(cmd);
						cv->_topic = extract_topic(cmd);

						add_cmd(cv, NULL);

						/* handle binary data key */
						json_object *bin_jobj;
						if (json_object_object_get_ex(jobj,
									      PROTOBUF_TOKEN,
									      &bin_jobj) &&
						    bin_jobj &&
						    json_object_is_type(bin_jobj, json_type_boolean))
							cv->_bin = json_object_get_boolean(bin_jobj);

						/* Handle interface hint */
						json_object *iface_jobj = NULL;
						json_object_object_get_ex(jobj, INTERFACE_NODE, &iface_jobj);
						if (iface_jobj != NULL && json_object_is_type(iface_jobj, json_type_string)) {
							const char *iface = json_object_get_string(iface_jobj);
							cv->_interface = strdup(iface); /* copy interface hint */
						}

						lh_table_insert(db, (void *)strdup(SET_ACTION), (void *)cv);
					} else {		 /* update existing entry */
						cv = (config_node_t *)e->v;
						free(cv->_value);

						const char *cmd = json_object_get_string(iter.val);
						cv->_value = strdup(cmd);
						/* Need to look up iv entry so this can be republished again */
						add_cmd(cv, NULL);

					}
				}
				continue; /* string object is end of recursion */
			}

			/*
			 * Skip anything other than an object,
			 * i.e. ignore the PROTOBUF "tag".
			 */
			if (itertype != json_type_object)
				continue;

			/* RECURSION, i.e. Object node */
			struct lh_entry *e = lh_table_lookup_entry(db, (void *)iter.key);
			if (e == NULL) { /* create */
				p_cv = create_config_node(iter.key);
				if (p_cv == NULL)
					return;

				lh_table_insert(db, (void *)strdup(iter.key),
						(void *)p_cv);
			} else {	/* update */
				p_cv = ((config_node_t *)e->v);
				if (p_cv->_hash == NULL)
					p_cv->_hash =
						my_lh_kchar_table_new(HASH_SIZE,
								   config_coll_free);

			}
			merge_json_to_db(p_cv->_hash, iter.val, p_cv);
		}
	}
}


/*
  Entry function to update internal configuration db.
 */
void
update_db(json_object *jobj)
{
	if (!_root_config_coll)
		_root_config_coll
			= my_lh_kchar_table_new(HASH_SIZE, config_coll_free);

	flush_resync(); /* empty resync cache */
	merge_json_to_db(_root_config_coll, jobj, NULL);
}


lh_table*
get_config_coll(void)
{
	return _root_config_coll;
}

void
config_coll_destroy(void)
{
	if (_root_config_coll) {
		lh_table_free(_root_config_coll);
		_root_config_coll = NULL;
	}
}
