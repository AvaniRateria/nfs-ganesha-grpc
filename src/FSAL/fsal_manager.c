// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * -------------
 */

/**
 * @addtogroup FSAL
 * @{
 */

/**
 * @file fsal_manager.c
 * @author Jim Lieb <jlieb@panasas.com>
 * @brief FSAL module manager
 */

#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include "log.h"
#include "fsal.h"
#include "nfs_core.h"
#include "config_parsing.h"
#include "pnfs_utils.h"
#include "fsal_private.h"
#include "FSAL/fsal_localfs.h"

/**
 * @brief List of loaded fsal modules
 *
 * Static to be private to the functions in this module
 * fsal_lock is taken whenever the list is walked.
 */

pthread_mutex_t fsal_lock;
GLIST_HEAD(fsal_list);

void initialize_fsal_lock(void)
{
	PTHREAD_MUTEX_init(&fsal_lock, NULL);
#if GSH_CAN_HOST_LOCAL_FS
	PTHREAD_RWLOCK_init(&fs_lock, NULL);
#endif
}

void destroy_fsal_lock(void)
{
	PTHREAD_MUTEX_destroy(&fsal_lock);
#if GSH_CAN_HOST_LOCAL_FS
	PTHREAD_RWLOCK_destroy(&fs_lock);
#endif
}

/**
 * @{
 *
 * Variables for passing status/errors between shared object
 * and this module. They must be accessed under lock.
 */

static char *dl_error;
static int so_error;
static struct fsal_module *new_fsal;

/**
 * @}
 */

/**
 * @brief FSAL load state
 */

static enum load_state {
	init, /*< In server start state. .init sections can run */
	idle, /*< Switch from init->idle early in main() */
	loading, /*< In dlopen(). set by load_fsal() just prior */
	registered, /*< signal by registration that all is well */
	error /*< signal by registration that all is not well */
} load_state = init;

/**
 * @brief Start a static FSAL
 *
 * Start a FSAL that's statically linked in.
 *
 * @param[in]  name	    FSAL name
 * @param[in]  init	    Initialization function for FSAL
 * @param[out] fsal_hdl	FSAL handle
 */

void load_fsal_static(const char *name, void (*init)(void),
		      struct fsal_module **fsal_hdl)
{
	char *dl_path = gsh_concat("Builtin-", name);
	struct fsal_module *fsal;

	PTHREAD_MUTEX_lock(&fsal_lock);

	if (load_state != idle)
		LogFatal(COMPONENT_INIT, "Couldn't Register FSAL_%s", name);

	if (dl_error) {
		gsh_free(dl_error);
		dl_error = NULL;
	}

	load_state = loading;

	PTHREAD_MUTEX_unlock(&fsal_lock);

	/* now it is the module's turn to register itself */
	init();

	PTHREAD_MUTEX_lock(&fsal_lock);

	if (load_state != registered)
		LogFatal(COMPONENT_INIT, "Couldn't Register FSAL_%s", name);

	/* we now finish things up, doing things the module can't see */

	fsal = new_fsal; /* recover handle from .ctor and poison again */
	new_fsal = NULL;
	fsal->path = dl_path;
	fsal->dl_handle = NULL;
	so_error = 0;
	load_state = idle;

	if (fsal_hdl != NULL)
		*fsal_hdl = fsal;
	PTHREAD_MUTEX_unlock(&fsal_lock);
}

struct dummy_fsal {
	void *dummy;
};

struct dummy_fsal dummy, dummy2;

static void *fsal_dummy_init(void *link_mem, void *self_struct)
{
	if (link_mem == NULL) {
		return self_struct;
	} else if (self_struct == NULL) {
		return &dummy2;
	} else { /* free resources case */
		return NULL;
	}
}

static struct config_item fsal_dummy_params[] = { CONFIG_EOL };

struct config_block fsal_dummy_block = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal",
	.blk_desc.name = "FSAL_ITEM",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.flags = CONFIG_RELAX,
	.blk_desc.u.blk.init = fsal_dummy_init,
	.blk_desc.u.blk.params = fsal_dummy_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};

static int fsal_name_adder(const char *token, enum term_type type_hint,
			   struct config_item *item, void *param_addr,
			   void *cnode, struct config_error_type *err_type)
{
	int rc;
	config_file_t myconfig = get_parse_root(cnode);

	LogMidDebug(COMPONENT_EXPORT, "Adding FSAL %s", token);

	fsal_dummy_block.blk_desc.name = (char *)token;

	rc = load_config_from_parse(myconfig, &fsal_dummy_block, &dummy, false,
				    err_type);

	return rc < 0 ? rc : 0;
}

static struct config_item fsal_params[] = {
	CONF_ITEM_PROC_MULT("Name", noop_conf_init, fsal_name_adder, dummy_fsal,
			    dummy),
	CONFIG_EOL
};

struct config_block fsal_block = {
	.dbus_interface_name = "org.ganesha.nfsd.config.fsal",
	.blk_desc.name = "FSAL_LIST",
	.blk_desc.type = CONFIG_BLOCK,
	.blk_desc.flags = CONFIG_UNIQUE, /* too risky to have more */
	.blk_desc.u.blk.init = noop_conf_init,
	.blk_desc.u.blk.params = fsal_params,
	.blk_desc.u.blk.commit = noop_conf_commit
};

/*
 * This can be overridden by any FSAL that is compiled statically with
 * Ganesha and wants to be started when the static fsals are started.
 */
__attribute__((weak)) void start_custom_static_fsals(
	config_file_t __attribute__((unused)) in_config,
	struct config_error_type __attribute__((unused)) * err_type)
{
	LogInfo(COMPONENT_FSAL, "start_custom_static_fsals is not implemented");
}

/**
 * @brief Start_fsals
 *
 * Called early server initialization.  Set load_state to idle
 * at this point as a check on dynamic loading not starting too early.
 */

int start_fsals(config_file_t in_config, struct config_error_type *err_type)
{
	int rc;

	initialize_fsal_lock();
	init_ctx_refstr();

	rc = load_config_from_parse(in_config, &fsal_block, &dummy, false,
				    err_type);

	if (rc < 0) {
		LogCrit(COMPONENT_CONFIG, "FSAL block error");
		return -1;
	}

	/* .init was a long time ago... */
	load_state = idle;

	/* Load FSAL_MDCACHE */
	load_fsal_static("MDCACHE", mdcache_fsal_init, NULL);

	/* Load FSAL_PSEUDO */
	load_fsal_static("PSEUDO", pseudo_fsal_init, NULL);

	/* Load additional static FSALs */
	start_custom_static_fsals(in_config, err_type);

	return 0;
}

/**
 * Enforced filename for FSAL library objects.
 */

static const char *pathfmt = "%s/libfsal%s.so";

/**
 * @brief Load the fsal's shared object.
 *
 * The dlopen() will trigger a .init constructor which will do the
 * actual registration.  after a successful load, the returned handle
 * needs to be "put" back after any other initialization is done.
 *
 * @param[in]  name       Name of the FSAL to load
 * @param[out] fsal_hdl_p Newly allocated FSAL handle
 *
 * @retval 0 Success, when finished, put_fsal_handle() to free
 * @retval EBUSY the loader is busy (should not happen)
 * @retval EEXIST the module is already loaded
 * @retval ENOLCK register_fsal without load_fsal holding the lock.
 * @retval EINVAL wrong loading state for registration
 * @retval ENOMEM out of memory
 * @retval ENOENT could not find "module_init" function
 * @retval EFAULT module_init has a bad address
 * @retval other general dlopen errors are possible, all of them bad
 */

int load_fsal(const char *name, struct fsal_module **fsal_hdl_p)
{
	void *dl = NULL;
	int retval = EBUSY; /* already loaded */
	char *dl_path;
	struct fsal_module *fsal;
	char *bp;
	struct stat statbuf;
	size_t size = strlen(nfs_param.core_param.ganesha_modules_loc) +
		      strlen(name) + strlen(pathfmt) + 1;
	char *path = alloca(size);

	(void)snprintf(path, size, pathfmt,
		       nfs_param.core_param.ganesha_modules_loc, name);
	bp = rindex(path, '/');
	bp++; /* now it is the basename, lcase it */
	while (*bp != '\0') {
		if (isupper(*bp))
			*bp = tolower(*bp);
		bp++;
	}
	dl_path = gsh_strdup(path);

	PTHREAD_MUTEX_lock(&fsal_lock);
	/* check filepath */
	if (stat(path, &statbuf) < 0) {
		retval = errno;
		LogCrit(COMPONENT_INIT,
			"stat returned %s (%d) while loading FSAL path %s",
			strerror(retval), retval, path);
		goto errout;
	}

	if (load_state != idle)
		goto errout;
	if (dl_error) {
		gsh_free(dl_error);
		dl_error = NULL;
	}

	load_state = loading;
	PTHREAD_MUTEX_unlock(&fsal_lock);

	LogDebug(COMPONENT_INIT, "Loading FSAL %s with %s", name, path);
#if defined(LINUX) && !defined(SANITIZE_ADDRESS)
	dl = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
#elif defined(BSDBASED) || defined(SANITIZE_ADDRESS)
	dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif

	PTHREAD_MUTEX_lock(&fsal_lock);
	if (dl == NULL) {
		dl_error = dlerror();
		LogFatal(
			COMPONENT_INIT,
			"Could not dlopen module: %s Error: %s. You might want to install the nfs-ganesha-%s package",
			path, dl_error, name);
	}
	dlerror(); /* clear it */

	/* now it is the module's turn to register itself */

	if (load_state == loading) {
		/* constructor didn't fire */
		void (*module_init)(void);
		char *sym_error;

		module_init = dlsym(dl, "fsal_init");
		sym_error = (char *)dlerror();
		if (sym_error != NULL) {
			dl_error = gsh_strdup(sym_error);
			so_error = ENOENT;
			LogCrit(COMPONENT_INIT,
				"Could not execute symbol fsal_init from module:%s Error:%s",
				path, dl_error);
			goto dlerr;
		}
		if ((void *)module_init == NULL) {
			so_error = EFAULT;
			LogCrit(COMPONENT_INIT,
				"Could not execute symbol fsal_init from module:%s Error:%s",
				path, dl_error);
			goto dlerr;
		}
		PTHREAD_MUTEX_unlock(&fsal_lock);

		(*module_init)(); /* try registering by hand this time */

		PTHREAD_MUTEX_lock(&fsal_lock);
	}
	if (load_state == error) { /* we are in registration hell */
		retval = so_error; /* this is the registration error */
		LogCrit(COMPONENT_INIT,
			"Could not execute symbol fsal_init from module:%s Error:%s",
			path, dl_error);
		goto dlerr;
	}
	if (load_state != registered) {
		retval = EPERM;
		LogCrit(COMPONENT_INIT,
			"Could not execute symbol fsal_init from module:%s Error:%s",
			path, dl_error);
		goto dlerr;
	}

	/* we now finish things up, doing things the module can't see */

	fsal = new_fsal; /* recover handle from .ctor and poison again */
	new_fsal = NULL;

	/* take initial ref so we can pass it back... */
	fsal_get(fsal);

	LogFullDebug(COMPONENT_FSAL, "FSAL %s fsal_refcount %" PRIu32, name,
		     atomic_fetch_int32_t(&fsal->refcount));

	fsal->path = dl_path;
	fsal->dl_handle = dl;
	so_error = 0;
	*fsal_hdl_p = fsal;
	load_state = idle;
	PTHREAD_MUTEX_unlock(&fsal_lock);
	return 0;

dlerr:
	dlclose(dl);
errout:
	load_state = idle;
	PTHREAD_MUTEX_unlock(&fsal_lock);
	LogMajor(COMPONENT_INIT, "Failed to load module (%s) because: %s", path,
		 strerror(retval));
	gsh_free(dl_path);
	return retval;
}

/**
 * @brief Look up an FSAL
 *
 * Acquire a handle to the named FSAL and take a reference to it. This
 * must be done before using any methods.  Once done, release it with
 * @c put_fsal.
 *
 * @param[in] name The name to look up
 *
 * @return Module pointer or NULL if not found.
 */

struct fsal_module *lookup_fsal(const char *name)
{
	struct fsal_module *fsal;
	struct glist_head *entry;

	PTHREAD_MUTEX_lock(&fsal_lock);
	glist_for_each(entry, &fsal_list) {
		fsal = glist_entry(entry, struct fsal_module, fsals);
		if (strcasecmp(name, fsal->name) == 0) {
			fsal_get(fsal);
			PTHREAD_MUTEX_unlock(&fsal_lock);
			op_ctx->fsal_module = fsal;
			LogFullDebug(COMPONENT_FSAL,
				     "FSAL %s fsal_refcount %" PRIu32, name,
				     atomic_fetch_int32_t(&fsal->refcount));
			return fsal;
		}
	}
	PTHREAD_MUTEX_unlock(&fsal_lock);
	return NULL;
}

/* functions only called by modules at ctor/dtor time
 */

/**
 * @brief Register the fsal in the system
 *
 * This can be called from three places:
 *
 *  + the server program's .init section if the fsal was statically linked
 *  + the shared object's .init section when load_fsal() dynamically loads it.
 *  + from the shared object's 'fsal_init' function if dlopen does not support
 *    .init/.fini sections.
 *
 * Any other case is an error.
 * Change load_state only for dynamically loaded modules.
 *
 * @param[in] fsal_hdl      FSAL module handle
 * @param[in] name          FSAL name
 * @param[in] major_version Major version
 * @param[in] minor_version Minor version
 *
 * @return 0 on success, otherwise POSIX errors.
 */

/** @todo implement api versioning and pass the major,minor here
 */

int register_fsal(struct fsal_module *fsal_hdl, const char *name,
		  uint32_t major_version, uint32_t minor_version,
		  uint8_t fsal_id)
{
	PTHREAD_MUTEX_lock(&fsal_lock);
	if ((major_version != FSAL_MAJOR_VERSION) ||
	    (minor_version > FSAL_MINOR_VERSION)) {
		so_error = EINVAL;
		LogCrit(COMPONENT_INIT,
			"FSAL \"%s\" failed to register because of version mismatch core = %d.%d, fsal = %d.%d",
			name, FSAL_MAJOR_VERSION, FSAL_MINOR_VERSION,
			major_version, minor_version);
		load_state = error;
		goto errout;
	}

	so_error = 0;

	if (!(load_state == loading || load_state == init)) {
		so_error = EACCES;
		goto errout;
	}

	new_fsal = fsal_hdl;

	if (name != NULL)
		new_fsal->name = gsh_strdup(name);

	/* init ops vector to system wide defaults
	 * from FSAL/default_methods.c
	 */
	memcpy(&fsal_hdl->m_ops, &def_fsal_ops, sizeof(struct fsal_ops));

	PTHREAD_RWLOCK_init(&fsal_hdl->fsm_lock, NULL);
	glist_init(&fsal_hdl->servers);
	glist_init(&fsal_hdl->handles);
	glist_init(&fsal_hdl->exports);
	fsal_hdl->is_configured = false;
	glist_add_tail(&fsal_list, &fsal_hdl->fsals);
	if (load_state == loading)
		load_state = registered;
	if (fsal_id != FSAL_ID_NO_PNFS && fsal_id < FSAL_ID_COUNT)
		pnfs_fsal[fsal_id] = fsal_hdl;
	PTHREAD_MUTEX_unlock(&fsal_lock);
	return 0;

errout:

	gsh_free(fsal_hdl->path);
	gsh_free(fsal_hdl->name);
	load_state = error;
	PTHREAD_MUTEX_unlock(&fsal_lock);
	LogCrit(COMPONENT_INIT, "FSAL \"%s\" failed to register because: %s",
		name, strerror(so_error));
	return so_error;
}

/**
 * @brief Unregisters an FSAL
 *
 * Verify that the fsal is not busy and release all its resources
 * owned at this level.  RW Lock is already freed.  Called from the
 * module's MODULE_FINI
 *
 * @param[in] fsal_hdl FSAL handle
 *
 * @retval 0 on success.
 * @retval EBUSY if FSAL is in use.
 */

int unregister_fsal(struct fsal_module *fsal_hdl)
{
	int32_t refcount = atomic_fetch_int32_t(&fsal_hdl->refcount);

	if (refcount != 0) {
		/* this would be very bad */
		LogCrit(COMPONENT_FSAL,
			"Unregister FSAL %s with non-zero fsal_refcount=%d",
			fsal_hdl->name, refcount);
		return EBUSY;
	}
	gsh_free(fsal_hdl->path);
	gsh_free(fsal_hdl->name);
	return 0;
}

/**
 * @brief Init and commit for FSAL sub-block
 */

/**
 * @brief Initialize space for an FSAL sub-block.
 *
 * We allocate space to hold the name parameter so that
 * is available in the commit phase.
 */

void *fsal_init(void *link_mem, void *self_struct)
{
	struct fsal_args *fp;

	assert(link_mem != NULL || self_struct != NULL);

	if (link_mem == NULL) {
		return self_struct; /* NOP */
	} else if (self_struct == NULL) {
		void *args = gsh_calloc(1, sizeof(struct fsal_args));

		LogFullDebug(COMPONENT_CONFIG, "Allocating args %p/%p",
			     link_mem, args);
		return args;
	} else {
		fp = self_struct;
		gsh_free(fp->name);
		gsh_free(fp);
		return NULL;
	}
}

/**
 * @brief Load and initialize FSAL module
 *
 * Use the name parameter to lookup the fsal. If the fsal is not
 * loaded (yet), load it and call its init. This will trigger the
 * processing of a top level block of the same name as the fsal, i.e.
 * the VFS fsal will look for a VFS block and process it (if found).
 *
 * @param[in]  node       parse node of FSAL block
 * @param[in]  name       name of the FSAL to load and initialize (if
 *                        not already loaded)
 * @param[out] fsal_hdl   Pointer to FSAL module or NULL if not found
 * @param[out] err_type   pointer to error type
 *
 * @retval 0 on success, error count on errors
 */

int fsal_load_init(void *node, const char *name, struct fsal_module **fsal_hdl,
		   struct config_error_type *err_type)
{
	fsal_status_t status;

	if (name == NULL || strlen(name) == 0) {
		config_proc_error(node, err_type, "Name of FSAL is missing");
		err_type->missing = true;
		return 1;
	}

	*fsal_hdl = lookup_fsal(name);
	if (*fsal_hdl == NULL) {
		int retval;
		config_file_t myconfig;

		retval = load_fsal(name, fsal_hdl);
		if (retval != 0) {
			config_proc_error(node, err_type,
					  "Failed to load FSAL (%s) because: %s",
					  name, strerror(retval));
			err_type->fsal = true;
			return 1;
		}
		op_ctx->fsal_module = *fsal_hdl;
		myconfig = get_parse_root(node);
		status = (*fsal_hdl)->m_ops.init_config(*fsal_hdl, myconfig,
							err_type);
		(*fsal_hdl)->is_configured = true;
		if (FSAL_IS_ERROR(status)) {
			config_proc_error(node, err_type,
					  "Failed to initialize FSAL (%s)",
					  name);
			fsal_put(*fsal_hdl);
			err_type->fsal = true;
			LogFullDebug(COMPONENT_FSAL,
				     "FSAL %s fsal_refcount %" PRIu32, name,
				     atomic_fetch_int32_t(
					     &(*fsal_hdl)->refcount));
			return 1;
		}
	} else {
		config_file_t myconfig;

		myconfig = get_parse_root(node);
		if ((*fsal_hdl)->is_configured) {
			status = (*fsal_hdl)->m_ops.update_config(*fsal_hdl,
								  myconfig,
								  err_type);
		} else {
			/* Static fsals might not be configured */
			(*fsal_hdl)->is_configured = true;
			status = (*fsal_hdl)->m_ops.init_config(*fsal_hdl,
								myconfig,
								err_type);
		}

		if (FSAL_IS_ERROR(status)) {
			config_proc_error(node, err_type,
					  "Failed to update FSAL (%s)", name);
			return 0;
		}
	}

	return 0;
}

/**
 * @brief Load and initialize sub-FSAL module
 *
 * @retval 0 on success, error count on errors
 */

int subfsal_commit(void *node, void *link_mem, void *self_struct,
		   struct config_error_type *err_type)
{
	struct fsal_module *fsal_next;
	struct subfsal_args *subfsal = (struct subfsal_args *)self_struct;
	int errcnt = fsal_load_init(node, subfsal->name, &fsal_next, err_type);

	if (errcnt == 0)
		subfsal->fsal_node = node;

	return errcnt;
}

/** @} */
