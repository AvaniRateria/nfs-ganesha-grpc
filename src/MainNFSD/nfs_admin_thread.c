// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file  nfs_admin_thread.c
 * @brief The admin_thread and support code.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <urcu-bp.h>
#ifdef LINUX
#include <mcheck.h> /* For mtrace/muntrace */
#endif
#ifndef __APPLE__
#include <malloc.h>
#endif

#include "nfs_core.h"
#include "log.h"
#include "sal_functions.h"
#include "sal_data.h"
#include "idmapper.h"
#include "delayed_exec.h"
#include "export_mgr.h"
#include "pnfs_utils.h"
#include "fsal.h"
#include "netgroup_cache.h"
#include "nfs_dupreq.h"
#ifdef USE_DBUS
#include "gsh_dbus.h"
#include "mdcache.h"
#include "nfs_lib.h"
#endif
#include "conf_url.h"
#include "nfs_rpc_callback.h"

/**
 * @brief Mutex protecting shutdown flag.
 */

static pthread_mutex_t admin_control_mtx;

/**
 * @brief Condition variable to signal change in shutdown flag.
 */

static pthread_cond_t admin_control_cv;

/**
 * @brief Flag to indicate shutdown Ganesha.
 *
 * Protected by admin_control_mtx and signaled by admin_control_cv.
 */
bool admin_shutdown;

#ifdef USE_DBUS

/**
 * @brief Dbus method get grace period status
 *
 * @param[in]  args  dbus args
 * @param[out] reply dbus reply message with grace period status
 */
static bool admin_dbus_get_grace(DBusMessageIter *args, DBusMessage *reply,
				 DBusError *error)
{
	char *errormsg = "get grace success";
	bool success = true;
	DBusMessageIter iter;
	dbus_bool_t ingrace;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Get grace takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}

	ingrace = nfs_in_grace();
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &ingrace);

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_get_grace = {
	.name = "get_grace",
	.method = admin_dbus_get_grace,
	.args = { {
			  .name = "isgrace",
			  .type = "b",
			  .direction = "out",
		  },
		  STATUS_REPLY,
		  END_ARG_LIST }
};

/**
 * @brief Dbus method start grace period
 *
 * @param[in]  args  Unused
 * @param[out] reply Unused
 */

static bool admin_dbus_grace(DBusMessageIter *args, DBusMessage *reply,
			     DBusError *error)
{
	char *errormsg = "Started grace period";
	bool success = true;
	DBusMessageIter iter;
	nfs_grace_start_t gsp;
	char *input = NULL;
	char *ip;
	int ret;

	dbus_message_iter_init_append(reply, &iter);
	if (args == NULL) {
		errormsg = "Grace period take 1 arguments: event:IP-address.";
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		success = false;
		goto out;
	}
	if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_STRING) {
		errormsg = "Grace period arg 1 not a string.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}
	dbus_message_iter_get_basic(args, &input);

	gsp.nodeid = -1;
	gsp.event = EVENT_TAKE_IP;

	ip = index(input, ':');
	if (ip == NULL)
		gsp.ipaddr = input; /* no event specified */
	else {
		int size = strlen(input) + 1;
		char *buf = alloca(size);

		gsp.ipaddr = ip + 1; /* point at the ip passed the : */
		memcpy(buf, input, size);
		ip = strstr(buf, ":");
		if (ip != NULL) {
			*ip = '\0'; /* replace ":" with null */
			gsp.event = atoi(buf);
		}
		if (gsp.event == EVENT_TAKE_NODEID)
			gsp.nodeid = atoi(gsp.ipaddr);
	}

	do {
		ret = nfs_start_grace(&gsp);
		/*
		 * grace could fail if there are refs taken.
		 * wait for no refs and retry.
		 */
		if (ret == -EAGAIN) {
			LogEvent(COMPONENT_DBUS, "Retry grace");
			nfs_wait_for_grace_norefs();
		} else if (ret) {
			LogCrit(COMPONENT_DBUS, "Start grace failed %d", ret);
			success = false;
			errormsg = "Unable to start grace";
			break;
		}
	} while (ret);
out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_grace_period = {
	.name = "grace",
	.method = admin_dbus_grace,
	.args = { IPADDR_ARG, STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for shutting down Ganesha
 *
 * @param[in]  args  Unused
 * @param[out] reply Unused
 */

static bool admin_dbus_shutdown(DBusMessageIter *args, DBusMessage *reply,
				DBusError *error)
{
	char *errormsg = "Server shut down";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Shutdown takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}

	admin_halt();

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_shutdown = { .name = "shutdown",
						  .method = admin_dbus_shutdown,
						  .args = { STATUS_REPLY,
							    END_ARG_LIST } };

static void drc_to_dbus(drc_t *drc, void *state)
{
	DBusMessageIter struct_iter;
	DBusMessageIter *array_iter = (DBusMessageIter *)state;
	char client_ip[SOCK_NAME_MAX] = { 0 };
	char *ipaddr = client_ip;
	int port;
	const char *str = NULL;

	if (!drc) {
		LogEvent(COMPONENT_DBUS, "Skipping NULL drc");
		return;
	}

	if (!sprint_sockip(&drc->d_u.tcp.addr, ipaddr, SOCK_NAME_MAX))
		(void)strlcpy(ipaddr, "<unknown>", SOCK_NAME_MAX);

	port = get_sockport(&drc->d_u.tcp.addr);

	dbus_message_iter_open_container(array_iter, DBUS_TYPE_STRUCT, NULL,
					 &struct_iter);
	str = "Client addr:";
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &str);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &ipaddr);
	str = "Client port:";
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &str);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32, &port);
	str = "Number of DRC entries:";
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &str);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32,
				       &drc->size);
	dbus_message_iter_close_container(array_iter, &struct_iter);
}

/**
 * @brief Dbus method get the drc info
 *
 * @param[in]  args
 */
static bool admin_dbus_get_drc_info(DBusMessageIter *args, DBusMessage *reply,
				    DBusError *error)
{
	char *errormsg = "get drc into success";
	const char *str = NULL;
	bool success = true;
	uint32_t counter;
	DBusMessageIter iter, array_iter, struct_iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Get drc info takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sssusu)",
					 &array_iter);

	counter = for_each_tcp_drc(drc_to_dbus, (void *)&array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	str = "Number of DRCs:";
	dbus_message_iter_open_container(&iter, DBUS_TYPE_STRUCT, NULL,
					 &struct_iter);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &str);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32,
				       &counter);
	dbus_message_iter_close_container(&iter, &struct_iter);

	counter = get_tcp_drc_recycle_qlen();
	str = "Number of inactive DRCs:";
	dbus_message_iter_open_container(&iter, DBUS_TYPE_STRUCT, NULL,
					 &struct_iter);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &str);
	dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32,
				       &counter);
	dbus_message_iter_close_container(&iter, &struct_iter);

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_get_drc_info = {
	.name = "get_drc_info",
	.method = admin_dbus_get_drc_info,
	.args = { {
			  .name = "drc_info",
			  .type = "a(sssusu)",
			  .direction = "out",
		  },
		  {
			  .name = "num_of_drcs",
			  .type = "(su)",
			  .direction = "out",
		  },
		  {
			  .name = "num_of_inactive_drcs",
			  .type = "(su)",
			  .direction = "out",
		  },
		  STATUS_REPLY,
		  END_ARG_LIST }
};

/**
 * @brief Dbus method for flushing manage gids cache
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_purge_gids(DBusMessageIter *args, DBusMessage *reply,
				  DBusError *error)
{
	char *errormsg = "Purge gids cache";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Purge gids takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}

	uid2grp_clear_cache();

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_purge_gids = {
	.name = "purge_gids",
	.method = admin_dbus_purge_gids,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for flushing netgroup cache
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_purge_netgroups(DBusMessageIter *args,
				       DBusMessage *reply, DBusError *error)
{
	char *errormsg = "Purge netgroup cache";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Purge netgroup takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}

	ng_clear_cache();

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_purge_netgroups = {
	.name = "purge_netgroups",
	.method = admin_dbus_purge_netgroups,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for flushing idmapper cache
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_purge_idmapper_cache(DBusMessageIter *args,
					    DBusMessage *reply,
					    DBusError *error)
{
	char *errormsg = "Purge idmapper cache";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Purge idmapper takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}
	idmapper_clear_cache();
out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_purge_idmapper_cache = {
	.name = "purge_idmapper_cache",
	.method = admin_dbus_purge_idmapper_cache,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for updating open fd limit
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_init_fds_limit(DBusMessageIter *args, DBusMessage *reply,
				      DBusError *error)
{
	char *errormsg = "Init fds limit";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "Init fds limit takes no arguments.";
		success = false;
		LogWarn(COMPONENT_DBUS, "%s", errormsg);
		goto out;
	}

	init_fds_limit();

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_init_fds_limit = {
	.name = "init_fds_limit",
	.method = admin_dbus_init_fds_limit,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for enabling malloc trace
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_malloc_trace(DBusMessageIter *args, DBusMessage *reply,
				    DBusError *error)
{
	char *errormsg = "malloc trace";
	bool success = true;
	DBusMessageIter iter;
	char *filename;

	dbus_message_iter_init_append(reply, &iter);
	if (args == NULL) {
		errormsg = "malloc trace needs trace filename.";
		success = false;
		goto out;
	}

	if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_STRING) {
		errormsg = "malloc trace needs trace filename.";
		success = false;
		goto out;
	}

	dbus_message_iter_get_basic(args, &filename);

#ifdef LINUX
	LogEvent(COMPONENT_DBUS, "enabling malloc trace to %s.", filename);
	setenv("MALLOC_TRACE", filename, 1);
	mtrace();
#else
	errormsg = "malloc trace is not supported";
	success = false;
#endif

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

/**
 * @brief Dbus method for disabling malloc trace
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_malloc_untrace(DBusMessageIter *args, DBusMessage *reply,
				      DBusError *error)
{
	char *errormsg = "malloc untrace";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	if (args != NULL) {
		errormsg = "malloc untrace takes no arguments.";
		success = false;
		goto out;
	}

#ifdef LINUX
	LogEvent(COMPONENT_DBUS, "disabling malloc trace.");
	muntrace();
#else
	errormsg = "malloc untrace is not supported";
	success = false;
#endif

out:
	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_malloc_trace = {
	.name = "malloc_trace",
	.method = admin_dbus_malloc_trace,
	.args = { { .name = "tracefile", .type = "s", .direction = "in" },
		  STATUS_REPLY,
		  END_ARG_LIST }
};

static struct gsh_dbus_method method_malloc_untrace = {
	.name = "malloc_untrace",
	.method = admin_dbus_malloc_untrace,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for enabling malloc trim
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_trim_enable(DBusMessageIter *args, DBusMessage *reply,
				   DBusError *error)
{
	char *errormsg = "Malloc trim enabled";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	LogEvent(COMPONENT_MEMLEAKS, "enabling malloc_trim");
	nfs_param.core_param.malloc_trim = true;
	gsh_dbus_status_reply(&iter, success, errormsg);

	return success;
}

static struct gsh_dbus_method method_trim_enable = {
	.name = "trim_enable",
	.method = admin_dbus_trim_enable,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for disabling malloc trim
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_trim_disable(DBusMessageIter *args, DBusMessage *reply,
				    DBusError *error)
{
	char *errormsg = "Malloc trim disabled";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	LogEvent(COMPONENT_MEMLEAKS, "disabling malloc_trim");
	nfs_param.core_param.malloc_trim = false;
	gsh_dbus_status_reply(&iter, success, errormsg);

	return success;
}

static struct gsh_dbus_method method_trim_disable = {
	.name = "trim_disable",
	.method = admin_dbus_trim_disable,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for calling malloc_trim()
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_trim_call(DBusMessageIter *args, DBusMessage *reply,
				 DBusError *error)
{
	char *errormsg = "malloc_trim() called";
	bool success = true;
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);
	LogEvent(COMPONENT_MEMLEAKS, "Calling malloc_trim");
	malloc_trim(0);
	gsh_dbus_status_reply(&iter, success, errormsg);

	return success;
}

static struct gsh_dbus_method method_trim_call = {
	.name = "trim_call",
	.method = admin_dbus_trim_call,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for getting trim status
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_dbus_trim_status(DBusMessageIter *args, DBusMessage *reply,
				   DBusError *error)
{
	char *errormsg = "Malloc trim status: enabled";
	bool success = true;
	DBusMessageIter iter;
	char hostname[64 + 1] = { 0 };
	char name[100];
	FILE *fp;

	/* log malloc_info() as a side effect! */
	(void)gethostname(hostname, sizeof(hostname));
	snprintf(name, sizeof(name), "/tmp/mallinfo-%s.%d.txt", hostname,
		 getpid());
	fp = fopen(name, "w");
	if (fp != NULL) {
		malloc_info(0, fp);
		fclose(fp);
	}

	dbus_message_iter_init_append(reply, &iter);
	if (!nfs_param.core_param.malloc_trim)
		errormsg = "Malloc trim status: disabled";
	gsh_dbus_status_reply(&iter, success, errormsg);

	return success;
}

static struct gsh_dbus_method method_trim_status = {
	.name = "trim_status",
	.method = admin_dbus_trim_status,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

/**
 * @brief Dbus method for getting trim status
 *
 * @param[in]  args
 * @param[out] reply
 */
static bool admin_reread_config(DBusMessageIter *args, DBusMessage *reply,
				DBusError *error)
{
	char *errormsg = "OK";
	DBusMessageIter iter;

	dbus_message_iter_init_append(reply, &iter);

	bool success = reread_config();

	if (!success)
		errormsg = "Failed to reread config";

	gsh_dbus_status_reply(&iter, success, errormsg);
	return success;
}

static struct gsh_dbus_method method_reread_config = {
	.name = "reread_config",
	.method = admin_reread_config,
	.args = { STATUS_REPLY, END_ARG_LIST }
};

static struct gsh_dbus_method *admin_methods[] = { &method_shutdown,
						   &method_grace_period,
						   &method_get_grace,
						   &method_purge_gids,
						   &method_purge_netgroups,
						   &method_init_fds_limit,
						   &method_purge_idmapper_cache,
						   &method_malloc_trace,
						   &method_malloc_untrace,
						   &method_trim_enable,
						   &method_trim_disable,
						   &method_trim_call,
						   &method_trim_status,
						   &method_reread_config,
						   &method_get_drc_info,
						   NULL };

/* clang-format off */

#define HANDLE_VERSION_PROP(prop_name, prop_string)                           \
	static bool dbus_prop_get_VERSION_##prop_name(DBusMessageIter *reply) \
	{                                                                     \
		const char *version_string = prop_string;                     \
		if (!dbus_message_iter_append_basic(reply, DBUS_TYPE_STRING,  \
						    &version_string))         \
			return false;                                         \
		return true;                                                  \
	}                                                                     \
									      \
	static struct gsh_dbus_prop VERSION_##prop_name##_prop = {            \
		.name = "VERSION_" #prop_name,                                \
		.access = DBUS_PROP_READ,                                     \
		.type = "s",                                                  \
		.get = dbus_prop_get_VERSION_##prop_name,                     \
		.set = NULL                                                   \
	}

/* clang-format on */

#define VERSION_PROPERTY_ITEM(name) (&VERSION_##name##_prop)

HANDLE_VERSION_PROP(RELEASE, GANESHA_VERSION);

#if !GANESHA_BUILD_RELEASE
HANDLE_VERSION_PROP(COMPILE_DATE, __DATE__);
HANDLE_VERSION_PROP(COMPILE_TIME, __TIME__);
HANDLE_VERSION_PROP(COMMENT, VERSION_COMMENT);
HANDLE_VERSION_PROP(GIT_HEAD, _GIT_HEAD_COMMIT);
HANDLE_VERSION_PROP(GIT_DESCRIBE, _GIT_DESCRIBE);
#endif

static struct gsh_dbus_prop *admin_props[] = {
	VERSION_PROPERTY_ITEM(RELEASE),
#if !GANESHA_BUILD_RELEASE
	VERSION_PROPERTY_ITEM(COMPILE_DATE),
	VERSION_PROPERTY_ITEM(COMPILE_TIME),
	VERSION_PROPERTY_ITEM(COMMENT),
	VERSION_PROPERTY_ITEM(GIT_HEAD),
	VERSION_PROPERTY_ITEM(GIT_DESCRIBE),
#endif
	NULL
};

static struct gsh_dbus_signal heartbeat_signal = { .name = HEARTBEAT_NAME,
						   .signal = NULL,
						   .args = { HEARTBEAT_ARG,
							     END_ARG_LIST } };

static struct gsh_dbus_signal *admin_signals[] = { &heartbeat_signal, NULL };

static struct gsh_dbus_interface admin_interface = { .name = DBUS_ADMIN_IFACE,
						     .props = admin_props,
						     .methods = admin_methods,
						     .signals = admin_signals };

static struct gsh_dbus_interface *admin_interfaces[] = { &admin_interface,
							 &log_interface, NULL };

#endif /* USE_DBUS */

/**
 * @brief Initialize admin thread control state and DBUS methods.
 */

void nfs_Init_admin_thread(void)
{
	PTHREAD_MUTEX_init(&admin_control_mtx, NULL);
	PTHREAD_COND_init(&admin_control_cv, NULL);
#ifdef USE_DBUS
	gsh_dbus_register_path("admin", admin_interfaces);
#endif /* USE_DBUS */
	LogEvent(COMPONENT_NFS_CB, "Admin thread initialized");
}

/**
 * @brief Signal the admin thread to shut down the system
 */

void admin_halt(void)
{
	PTHREAD_MUTEX_lock(&admin_control_mtx);

	if (!admin_shutdown) {
		admin_shutdown = true;
		pthread_cond_broadcast(&admin_control_cv);
	}

	PTHREAD_MUTEX_unlock(&admin_control_mtx);
	LogEvent(COMPONENT_MAIN, "NFS EXIT: %s done", __func__);
}

static void do_shutdown(void)
{
	int rc = 0;
	bool disorderly = false;

	LogEvent(COMPONENT_MAIN, "NFS EXIT: stopping NFS service");

	gsh_rados_url_shutdown_watch();

	config_url_shutdown();

#ifdef USE_DBUS
	/* DBUS shutdown */
	gsh_dbus_pkgshutdown();
#endif

	LogEvent(COMPONENT_MAIN, "Stopping delayed executor.");
	delayed_shutdown();
	LogEvent(COMPONENT_MAIN, "Delayed executor stopped.");

	LogEvent(COMPONENT_MAIN, "Stopping state asynchronous request thread");
	rc = state_async_shutdown();
	if (rc != 0) {
		LogMajor(
			COMPONENT_THREAD,
			"Error shutting down state asynchronous request system: %d",
			rc);
		disorderly = true;
	} else {
		LogEvent(COMPONENT_THREAD,
			 "State asynchronous request system shut down.");
	}

	LogEvent(COMPONENT_MAIN, "Unregistering ports used by NFS service");
	/* finalize RPC package */
	Clean_RPC();

	LogEvent(COMPONENT_MAIN, "Shutting down RPC services");
	(void)svc_shutdown(SVC_SHUTDOWN_FLAG_NONE);

	LogEvent(COMPONENT_MAIN, "Stopping reaper threads");
	rc = reaper_shutdown();
	if (rc != 0) {
		LogMajor(COMPONENT_THREAD,
			 "Error shutting down reaper thread: %d", rc);
		disorderly = true;
	} else {
		LogEvent(COMPONENT_THREAD, "Reaper thread shut down.");
	}

	LogEvent(COMPONENT_MAIN, "Stopping worker threads");
#ifdef _USE_9P
	if (nfs_param.core_param.core_options & CORE_OPTION_9P) {
		rc = _9p_worker_shutdown();

		if (rc != 0) {
			LogMajor(COMPONENT_THREAD,
				 "Unable to shut down worker threads: %d", rc);
			disorderly = true;
		} else {
			LogEvent(COMPONENT_THREAD,
				 "Worker threads successfully shut down.");
		}
	}
#endif

	rc = general_fridge_shutdown();
	if (rc != 0) {
		LogMajor(COMPONENT_THREAD,
			 "Error shutting down general fridge: %d", rc);
		disorderly = true;
	} else {
		LogEvent(COMPONENT_THREAD, "General fridge shut down.");
	}

	/* We have to remove DS before exports, DS refer to exports but
	 * exports do not refer to DS. This SHOULD remove every single DS.
	 */
	LogEvent(COMPONENT_MAIN, "Removing all DSs.");
	remove_all_dss();

	LogEvent(COMPONENT_MAIN, "Removing all exports.");
	remove_all_exports();

	nfs4_recovery_shutdown();
	nfs_rpc_cb_pkgshutdown();

	if (disorderly) {
		LogMajor(COMPONENT_MAIN,
			 "Error in shutdown, taking emergency cleanup.");
		/* We don't attempt to free state, clean the cache,
		   or unload the FSALs more cleanly, since doing
		   anything more than this risks hanging up on
		   potentially invalid locks. */
		emergency_cleanup_fsals();
	} else {
		LogEvent(COMPONENT_MAIN, "Destroying the FSAL system.");
		destroy_fsals();
		LogEvent(COMPONENT_MAIN, "FSAL system destroyed.");
	}

	unlink(nfs_pidfile_path);
	PTHREAD_MUTEX_destroy(&admin_control_mtx);
	PTHREAD_COND_destroy(&admin_control_cv);
	LogEvent(COMPONENT_MAIN, "NFS EXIT: %s done", __func__);
}

void *admin_thread(void *UnusedArg)
{
	SetNameFunction("Admin");
	rcu_register_thread();

	PTHREAD_MUTEX_lock(&admin_control_mtx);

	while (!admin_shutdown) {
		/* Wait for shutdown indication. */
		pthread_cond_wait(&admin_control_cv, &admin_control_mtx);
	}

	PTHREAD_MUTEX_unlock(&admin_control_mtx);

	do_shutdown();

	rcu_unregister_thread();
	return NULL;
}
